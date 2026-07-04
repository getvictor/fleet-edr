import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { TechniqueTags } from "./TechniqueTags";

function renderTags(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("TechniqueTags", () => {
  it("renders nothing for an empty or absent technique list", () => {
    const { container } = renderTags(<TechniqueTags techniques={[]} ruleId="r1" />);
    expect(container).toBeEmptyDOMElement();
    const { container: c2 } = renderTags(<TechniqueTags ruleId="r1" />);
    expect(c2).toBeEmptyDOMElement();
  });

  it("links each technique to the rule doc page when a ruleId is given", () => {
    renderTags(<TechniqueTags techniques={["T1059.004", "T1543.004"]} ruleId="shell_from_office" />);
    const one = screen.getByRole("link", { name: "T1059.004" });
    expect(one).toHaveAttribute("href", "/rules/shell_from_office");
    expect(screen.getByRole("link", { name: "T1543.004" })).toHaveAttribute("href", "/rules/shell_from_office");
  });

  it("renders display-only badges (no links) when no ruleId is given", () => {
    renderTags(<TechniqueTags techniques={["T1059.004"]} />);
    expect(screen.getByText("T1059.004")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
