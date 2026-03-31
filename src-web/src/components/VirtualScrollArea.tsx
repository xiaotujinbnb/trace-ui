import type { ReactNode } from "react";
import type { ScrollbarProps } from "../hooks/useVirtualScroll";
import CustomScrollbar from "./CustomScrollbar";

interface VirtualScrollAreaProps {
  /** useVirtualScroll 返回的 containerRef */
  containerRef: React.RefObject<HTMLDivElement | null>;
  /** useVirtualScroll 返回的 containerStyle */
  containerStyle: React.CSSProperties;
  /** useVirtualScroll 返回的 containerHeight */
  containerHeight: number;
  /** useVirtualScroll 返回的 scrollbarProps */
  scrollbarProps: ScrollbarProps;
  /** 列表容器的额外样式（如 fontSize、outline 等） */
  style?: React.CSSProperties;
  /** 列表容器的额外属性（如 tabIndex、onKeyDown 等） */
  tabIndex?: number;
  onKeyDown?: React.KeyboardEventHandler<HTMLDivElement>;
  /** 右侧额外内容（如 Minimap），渲染在 CustomScrollbar 之前 */
  gutterContent?: ReactNode;
  /** 右侧槽位宽度（默认 12，有 Minimap 时需要更宽） */
  gutterWidth?: number;
  /** 启用水平滚动 */
  horizontalScroll?: boolean;
  children: ReactNode;
}

export default function VirtualScrollArea({
  containerRef,
  containerStyle,
  containerHeight,
  scrollbarProps,
  style,
  tabIndex,
  onKeyDown,
  gutterContent,
  gutterWidth = 12,
  horizontalScroll,
  children,
}: VirtualScrollAreaProps) {
  const outerOverflow: React.CSSProperties = horizontalScroll
    ? { overflowX: "visible", overflowY: "hidden" }
    : { overflow: "hidden" };
  return (
    <div style={{ flex: 1, display: "flex", ...outerOverflow }}>
      <div
        ref={containerRef}
        tabIndex={tabIndex}
        onKeyDown={onKeyDown}
        style={{
          flex: 1,
          ...containerStyle,
          ...style,
          ...(horizontalScroll ? { overflowX: "auto", overflowY: "hidden" } : {}),
        }}
      >
        {children}
      </div>
      {containerHeight > 0 && (
        <div style={{ width: gutterWidth, flexShrink: 0, position: "relative" }}>
          {gutterContent}
          <CustomScrollbar {...scrollbarProps} />
        </div>
      )}
    </div>
  );
}
