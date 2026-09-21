import { useEffect, useState, type RefObject } from "react";

// useIsTruncated reports whether an element's text is actually being clipped by its box, so a caller can offer the full value only
// when the shown one is incomplete.
//
// The alternative, always offering it, puts a tooltip on every cell including the ones already showing everything they have, which
// trains an operator to ignore the tooltip on the cells that needed it. Whether a value is clipped depends on the column's width,
// not on the value's length, so it cannot be decided when the value is rendered: the same identifier is complete on a wide window
// and clipped on a narrow one. A ResizeObserver is what keeps the answer current as the column changes.
export function useIsTruncated(ref: RefObject<HTMLElement | null>): boolean {
  const [truncated, setTruncated] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const measure = () => {
      // scrollWidth is the content's full width; clientWidth is what the box shows. Wider content than box means ellipsized.
      setTruncated(el.scrollWidth > el.clientWidth);
    };
    measure();
    // ResizeObserver is absent in some test environments and older browsers; without it the first measurement still stands, which
    // is the right answer until the column changes size.
    if (typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => {
      observer.disconnect();
    };
  }, [ref]);

  return truncated;
}
