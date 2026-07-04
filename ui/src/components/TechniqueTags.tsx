import { Link } from "react-router-dom";
import { Badge } from "./ui/Badge";
import "./TechniqueTags.scss";

interface Props {
  // MITRE ATT&CK technique ids (e.g. ["T1059.004"]). An empty or absent list renders nothing.
  readonly techniques?: string[];
  // When set, each technique badge links to the rule's documentation page (/rules/:ruleId); when absent the badges are display-only
  // (the hover tooltip case, where a link inside a transient card is unreachable).
  readonly ruleId?: string;
  readonly className?: string;
}

// TechniqueTags renders an alert's MITRE technique ids inline (issue #585): the shared badge surface for the graph tooltip, the detail
// panel, and the timeline row, so the three sites stay consistent and a future tactic-color change lands in one place.
export function TechniqueTags({ techniques, ruleId, className }: Props) {
  if (!techniques || techniques.length === 0) return null;
  return (
    <span className={className ? `technique-tags ${className}` : "technique-tags"}>
      {techniques.map((t) =>
        ruleId !== undefined ? (
          <Link key={t} className="technique-tags__link" to={`/rules/${encodeURIComponent(ruleId)}`} title={`Open the ${ruleId} rule documentation`}>
            <Badge variant="neutral">{t}</Badge>
          </Link>
        ) : (
          <Badge key={t} variant="neutral">{t}</Badge>
        ),
      )}
    </span>
  );
}
