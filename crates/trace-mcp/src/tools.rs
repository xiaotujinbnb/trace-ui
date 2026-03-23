use std::sync::Arc;

use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};

use trace_core::{TraceEngine, BuildOptions, SearchOptions, SliceOptions, StringQueryOptions, DepTreeOptions, ExportConfig, parse_hex_addr};
use crate::types::*;

// ── 截断常量 ──
// NOTE: 修改这些值时，需同步更新对应 #[tool] 描述中的硬编码数字。

// Referenced in: get_trace_lines description ("up to 100 lines per call")
const MAX_LINES: u32 = 100;
// Referenced in: search_instructions description ("up to 200 results")
const MAX_SEARCH: u32 = 200;
// Referenced in: get_memory_history description ("up to 200 records")
const MAX_HISTORY: usize = 200;
// Referenced in: get_dependency_tree, build_dep_tree_from_slice descriptions ("up to 200 nodes")
const MAX_DEP_NODES: u32 = 200;
const DEFAULT_SEARCH: u32 = 30;

fn json(val: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(val).unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
}

/// Run a blocking closure on the tokio blocking thread pool to avoid starving
/// the async runtime. Used for heavy TraceEngine operations.
async fn blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("Task panicked: {}", e))?
}

#[derive(Clone)]
pub struct TraceToolHandler {
    engine: Arc<TraceEngine>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TraceToolHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceToolHandler").finish()
    }
}

#[tool_router]
impl TraceToolHandler {
    pub fn new(engine: Arc<TraceEngine>) -> Self {
        Self {
            engine,
            tool_router: Self::tool_router(),
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "open_trace",
        description = "Open a trace file and build its index. This is the first step before any analysis. \
            Returns session info including session_id needed for all subsequent operations. \
            Building the index may take a few seconds for large files."
    )]
    async fn open_trace(&self, Parameters(req): Parameters<OpenTraceRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let session = engine.create_session(&req.file_path)
                .map_err(|e| format!("Failed to open trace: {}", e))?;

            let session_id = session.session_id.clone();
            let options = BuildOptions {
                force_rebuild: req.force_rebuild,
                skip_strings: req.skip_strings,
            };

            match engine.build_index(&session_id, options, None) {
                Ok(build) => Ok(json(&serde_json::json!({
                    "session_id": session_id,
                    "file_path": session.file_path,
                    "file_size": session.file_size,
                    "total_lines": build.total_lines,
                    "has_string_index": build.has_string_index,
                    "from_cache": build.from_cache,
                }))),
                Err(e) => {
                    let _ = engine.close_session(&session_id);
                    Err(format!("Failed to build index: {}", e))
                }
            }
        }).await
    }

    #[tool(
        name = "close_trace",
        description = "Close a trace session and free its resources. \
            Call this when you're done analyzing a trace file."
    )]
    fn close_trace(&self, Parameters(req): Parameters<CloseTraceRequest>) -> Result<String, String> {
        self.engine.close_session(&req.session_id)
            .map(|()| "Session closed.".to_string())
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "list_sessions",
        description = "List all currently open trace sessions with their status."
    )]
    fn list_sessions(&self) -> String {
        json(&self.engine.list_sessions())
    }

    #[tool(
        name = "get_session_info",
        description = "Get detailed status of a trace session, including whether the index is ready, \
            total line count, and whether taint analysis results exist."
    )]
    fn get_session_info(&self, Parameters(req): Parameters<GetSessionInfoRequest>) -> Result<String, String> {
        self.engine.get_session_info(&req.session_id)
            .map(|info| json(&info))
            .map_err(|e| e.to_string())
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_trace_lines",
        description = "Retrieve instruction lines from the trace. Each line contains: \
            address, disassembly, register changes, and memory access info. \
            Lines are identified by 0-based sequence numbers. \
            Returns up to 100 lines per call."
    )]
    fn get_trace_lines(&self, Parameters(req): Parameters<GetTraceLinesRequest>) -> Result<String, String> {
        let count = req.count.min(MAX_LINES);
        let end = req.start_seq.saturating_add(count);
        let seqs: Vec<u32> = (req.start_seq..end).collect();
        let lines = self.engine.get_lines(&req.session_id, &seqs)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "lines": lines,
            "count": lines.len(),
            "start_seq": req.start_seq,
            "requested": count,
        })))
    }

    #[tool(
        name = "get_registers",
        description = "Get the complete register snapshot at a specific instruction line. \
            Shows all ARM64 registers (X0-X30, SP, PC, NZCV) with their values, \
            which registers were modified by this instruction, and which were read."
    )]
    fn get_registers(&self, Parameters(req): Parameters<GetRegistersRequest>) -> Result<String, String> {
        self.engine.get_registers_at(&req.session_id, req.seq)
            .map(|regs| json(&regs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_memory",
        description = "Read memory contents at a specific address and instruction line. \
            Shows the byte values as they were at that point in execution. \
            Unknown bytes (never written) are marked in the 'known' array."
    )]
    fn get_memory(&self, Parameters(req): Parameters<GetMemoryRequest>) -> Result<String, String> {
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.min(256);
        self.engine.get_memory_at(&req.session_id, addr, req.seq, length)
            .map(|snap| json(&snap))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_memory_history",
        description = "Get the read/write access history for a memory address. \
            Returns records showing every time this address was read or written, \
            with the instruction that did it and the data value. \
            Supports pagination with offset/limit."
    )]
    fn get_memory_history(&self, Parameters(req): Parameters<GetMemoryHistoryRequest>) -> Result<String, String> {
        let addr = parse_hex_addr(&req.address)?;
        let limit = req.limit.min(MAX_HISTORY);

        let meta = self.engine.get_mem_history_meta(&req.session_id, addr, req.center_seq)
            .map_err(|e| e.to_string())?;

        let records = self.engine.get_mem_history_range(&req.session_id, addr, req.offset, limit)
            .map_err(|e| e.to_string())?;

        Ok(json(&serde_json::json!({
            "total": meta.total,
            "center_index": meta.center_index,
            "offset": req.offset,
            "records": records,
            "has_more": req.offset + records.len() < meta.total,
        })))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 搜索与分析 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "search_instructions",
        description = "Search for instructions matching a text or regex pattern in the trace. \
            Returns matching line numbers and a preview of each match. \
            Use regex for complex patterns like 'bl.*0x[0-9a-f]+' to find specific branch targets. \
            Wrap pattern in /slashes/ for auto-regex detection."
    )]
    async fn search_instructions(&self, Parameters(req): Parameters<SearchInstructionsRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let max = req.max_results.unwrap_or(DEFAULT_SEARCH).min(MAX_SEARCH);
            let options = SearchOptions {
                case_sensitive: req.case_sensitive,
                use_regex: req.use_regex,
                fuzzy: false,
                max_results: Some(max),
            };
            let result = engine.search(&req.session_id, &req.query, options)
                .map_err(|e| e.to_string())?;

            let preview_seqs: Vec<u32> = result.match_seqs.iter().copied().take(max as usize).collect();
            let lines = engine.get_lines(&req.session_id, &preview_seqs)
                .map_err(|e| e.to_string())?;

            let matches: Vec<serde_json::Value> = lines.iter().map(|l| {
                serde_json::json!({
                    "seq": l.seq,
                    "address": l.address,
                    "disasm": l.disasm,
                    "changes": l.changes,
                })
            }).collect();

            Ok(json(&serde_json::json!({
                "matches": matches,
                "total_matches": result.total_matches,
                "total_scanned": result.total_scanned,
                "truncated": result.truncated,
            })))
        }).await
    }

    #[tool(
        name = "run_taint_analysis",
        description = "Perform backward taint analysis (data dependency tracking) \
            from a register or memory address at a specific instruction. \
            Returns which instructions contributed to the tainted value. \
            Use this to trace where a value came from. \
            Register names are case-insensitive. \
            Example from_specs: ['reg:X0@1234'] traces X0 at line 1234, \
            ['mem:0xbffff000@last'] traces the last write to that address."
    )]
    async fn run_taint_analysis(&self, Parameters(req): Parameters<RunTaintAnalysisRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let options = SliceOptions {
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                data_only: req.data_only,
            };
            let result = engine.run_slice(&req.session_id, &req.from_specs, options)
                .map_err(|e| e.to_string())?;
            Ok(json(&serde_json::json!({
                "marked_count": result.marked_count,
                "total_lines": result.total_lines,
                "percentage": format!("{:.2}%", result.percentage),
                "hint": "Use get_tainted_lines to retrieve the actual tainted instructions.",
            })))
        }).await
    }

    #[tool(
        name = "get_tainted_lines",
        description = "Retrieve the instructions marked as tainted by the last run_taint_analysis. \
            Returns full line content with disassembly for each tainted instruction. \
            Supports pagination with offset/limit."
    )]
    fn get_tainted_lines(&self, Parameters(req): Parameters<GetTaintedLinesRequest>) -> Result<String, String> {
        let limit = req.limit.min(200);

        let all_seqs = self.engine.get_tainted_seqs(&req.session_id)
            .map_err(|e| e.to_string())?;

        let total = all_seqs.len() as u32;
        let page_seqs: Vec<u32> = all_seqs.into_iter()
            .skip(req.offset as usize)
            .take(limit as usize)
            .collect();

        let lines = self.engine.get_lines(&req.session_id, &page_seqs)
            .map_err(|e| e.to_string())?;

        Ok(json(&serde_json::json!({
            "lines": lines,
            "total_tainted": total,
            "offset": req.offset,
            "count": lines.len(),
            "has_more": (req.offset as usize + lines.len()) < total as usize,
        })))
    }

    #[tool(
        name = "clear_taint",
        description = "Clear the current taint analysis results. \
            Call this before running a new taint analysis if you want fresh results."
    )]
    fn clear_taint(&self, Parameters(req): Parameters<ClearTaintRequest>) -> Result<String, String> {
        self.engine.clear_slice(&req.session_id)
            .map(|()| "Taint results cleared.".to_string())
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_dependency_tree",
        description = "Build a dependency graph showing how a value at a specific instruction \
            was computed. Returns a DAG of instructions connected by data/control dependencies. \
            Useful for understanding the full computation chain of a value. \
            Target format: 'reg:X0' for a register (case-insensitive), 'mem:0xaddr' for a memory address."
    )]
    async fn get_dependency_tree(&self, Parameters(req): Parameters<GetDependencyTreeRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let max_nodes = req.max_nodes.unwrap_or(MAX_DEP_NODES).min(MAX_DEP_NODES);
            let options = DepTreeOptions {
                data_only: req.data_only,
                max_nodes: Some(max_nodes),
            };
            engine.build_dep_tree(&req.session_id, req.seq, &req.target, options)
                .map(|graph| json(&graph))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "get_def_use_chain",
        description = "Get the definition-use chain for a register at a specific instruction. \
            If the register is USED at this line, returns the upstream DEF (where it was last written). \
            If the register is DEFined at this line, returns all downstream USEs until it's redefined. \
            Register names are case-insensitive. \
            Useful for tracking register value propagation."
    )]
    fn get_def_use_chain(&self, Parameters(req): Parameters<GetDefUseChainRequest>) -> Result<String, String> {
        self.engine.get_def_use_chain(&req.session_id, req.seq, &req.register.to_lowercase())
            .map(|chain| json(&chain))
            .map_err(|e| e.to_string())
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 结构信息 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_call_tree",
        description = "Get the function call tree rooted at a specific node. \
            Returns the node itself plus its direct children (lazy loading). \
            Use node_id=0 to start from the root. Each node contains: \
            function address, name, entry/exit line numbers, and child node IDs."
    )]
    fn get_call_tree(&self, Parameters(req): Parameters<GetCallTreeRequest>) -> Result<String, String> {
        self.engine.get_call_tree_children(&req.session_id, req.node_id, true)
            .map(|nodes| json(&nodes))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_function_info",
        description = "Get detailed information about a specific function call in the call tree. \
            Returns the function's address, name, entry/exit lines, line count, and child calls."
    )]
    fn get_function_info(&self, Parameters(req): Parameters<GetFunctionInfoRequest>) -> Result<String, String> {
        let nodes = self.engine.get_call_tree_children(&req.session_id, req.node_id, true)
            .map_err(|e| e.to_string())?;
        match nodes.first() {
            Some(node) => Ok(json(node)),
            None => Err(format!("Node {} not found", req.node_id)),
        }
    }

    #[tool(
        name = "get_function_list",
        description = "Get an aggregated list of all function calls found in the trace. \
            Groups calls by function name, showing each occurrence with its line number. \
            Useful for finding where specific functions are called."
    )]
    fn get_function_list(&self, Parameters(req): Parameters<GetFunctionListRequest>) -> Result<String, String> {
        self.engine.get_function_calls(&req.session_id)
            .map(|result| json(&result))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_strings",
        description = "List runtime strings found in the trace. \
            These are strings observed in memory during execution. \
            Supports filtering by minimum length and search query. \
            Each string includes its memory address, content, encoding, and access type."
    )]
    fn get_strings(&self, Parameters(req): Parameters<GetStringsRequest>) -> Result<String, String> {
        let limit = req.limit.min(200);
        let options = StringQueryOptions {
            min_len: req.min_len,
            offset: req.offset,
            limit,
            search: req.search,
        };
        let result = self.engine.get_strings(&req.session_id, options)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "strings": result.strings,
            "total": result.total,
            "offset": req.offset,
            "has_more": (req.offset + result.strings.len() as u32) < result.total,
        })))
    }

    #[tool(
        name = "get_string_xrefs",
        description = "Get cross-references for a specific string: all instructions that \
            read or write the string's memory address. Each xref includes the instruction \
            address, disassembly, and read/write type."
    )]
    fn get_string_xrefs(&self, Parameters(req): Parameters<GetStringXRefsRequest>) -> Result<String, String> {
        let addr = parse_hex_addr(&req.address)?;
        self.engine.get_string_xrefs(&req.session_id, addr, req.byte_len)
            .map(|xrefs| json(&xrefs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "scan_crypto_patterns",
        description = "Scan the trace for known cryptographic algorithm signatures \
            (AES, SHA256, MD5, etc.) by detecting magic number constants in register values. \
            Returns matched algorithms and the instructions where they appear."
    )]
    async fn scan_crypto_patterns(&self, Parameters(req): Parameters<ScanCryptoPatternsRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            if let Ok(Some(cached)) = engine.load_crypto_cache(&req.session_id) {
                return Ok(json(&cached));
            }
            engine.scan_crypto(&req.session_id)
                .map(|result| json(&result))
                .map_err(|e| e.to_string())
        }).await
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 扩展工具 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "export_taint_results",
        description = "Export the current taint analysis results to a file. \
            Requires a prior run_taint_analysis call. \
            Supports 'json' (structured with metadata) and 'txt' (raw tainted lines) formats."
    )]
    async fn export_taint_results(&self, Parameters(req): Parameters<ExportTaintResultsRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            // ExportConfig requires from_specs — retrieve from session's stored slice_origin
            // For MCP export, we pass empty config since the slice is already computed
            let config = ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            };
            engine.export_taint_results(&req.session_id, &req.output_path, &req.format, config)
                .map(|()| json(&serde_json::json!({
                    "exported": true,
                    "path": req.output_path,
                    "format": req.format,
                })))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "build_dep_tree_from_slice",
        description = "Build a dependency graph from the current taint analysis results. \
            Requires a prior run_taint_analysis call. \
            This is more convenient than get_dependency_tree when you already have taint results, \
            as it automatically uses the tainted instructions as the starting points."
    )]
    async fn build_dep_tree_from_slice(&self, Parameters(req): Parameters<BuildDepTreeFromSliceRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let max_nodes = req.max_nodes.unwrap_or(MAX_DEP_NODES).min(MAX_DEP_NODES);
            let options = DepTreeOptions {
                data_only: req.data_only,
                max_nodes: Some(max_nodes),
            };
            engine.build_dep_tree_from_slice(&req.session_id, options)
                .map(|graph| json(&graph))
                .map_err(|e| e.to_string())
        }).await
    }

    #[tool(
        name = "get_line_def_registers",
        description = "Get the list of registers defined (written) by a specific instruction. \
            Useful before calling get_def_use_chain to know which registers are available. \
            Returns register names like ['X0', 'X1']."
    )]
    fn get_line_def_registers(&self, Parameters(req): Parameters<GetLineDefRegistersRequest>) -> Result<String, String> {
        self.engine.get_line_def_registers(&req.session_id, req.seq)
            .map(|regs| json(&regs))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_call_tree_node_count",
        description = "Get the total number of nodes in the function call tree. \
            Useful for understanding the scale of the call tree before exploring it."
    )]
    fn get_call_tree_node_count(&self, Parameters(req): Parameters<GetCallTreeNodeCountRequest>) -> Result<String, String> {
        self.engine.get_call_tree_node_count(&req.session_id)
            .map(|count| json(&serde_json::json!({ "node_count": count })))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "scan_strings",
        description = "Scan the trace for runtime strings. Only needed if open_trace was called \
            with skip_strings=true. After this completes, get_strings and get_string_xrefs \
            will have data. This may take a while for large traces."
    )]
    async fn scan_strings(&self, Parameters(req): Parameters<ScanStringsRequest>) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            engine.scan_strings(&req.session_id)
                .map(|()| json(&serde_json::json!({
                    "status": "String scanning completed.",
                })))
                .map_err(|e| e.to_string())
        }).await
    }
}

#[tool_handler]
impl ServerHandler for TraceToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_instructions(
            "Trace UI MCP Server — analyze ARM64 execution traces. \
             Start by calling open_trace with a file path, then use the returned \
             session_id for all analysis operations. Available analyses: \
             instruction browsing, register/memory inspection, taint analysis, \
             dependency trees, function call trees, string extraction, and \
             cryptographic pattern detection.".to_string(),
        )
    }
}
