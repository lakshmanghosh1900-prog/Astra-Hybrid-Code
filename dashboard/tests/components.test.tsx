import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApprovalInbox } from "../components/ApprovalInbox";
import { CostDashboard } from "../components/CostDashboard";
import { TaskList } from "../components/TaskList";

const task = { id: "1", prompt: "Fix auth", repo_path: "/repo", state: "awaiting_approval" as const, risk: "T2" as const, steps: 1, tokens: 120, repairs: 0 };

describe("dashboard components", () => {
  it("renders the empty state", () => { render(<TaskList tasks={[]} onSelect={() => undefined} />); expect(screen.getByText("No tasks yet.")).toBeInTheDocument(); });
  it("renders approval and cost information", () => { render(<><ApprovalInbox tasks={[task]} onApprove={() => undefined} /><CostDashboard tasks={[task]} /></>); expect(screen.getByText("Approval inbox")).toBeInTheDocument(); expect(screen.getByText("120")).toBeInTheDocument(); });
});
