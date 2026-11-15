import { useState } from "react";
import type { Task } from "../lib/api";
import { StatusBadge } from "./StatusBadge";

export type PendingAction = { taskId: string; operation: "approve" | "deny" | "cancel" };

type ApprovalInboxProps = {
  tasks: Task[];
  onApprove: (task: Task) => void;
  onDeny?: (task: Task, reason: string) => void;
  pendingAction?: PendingAction;
};

export function ApprovalInbox({ tasks, onApprove, onDeny, pendingAction }: ApprovalInboxProps) {
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const pending = tasks.filter((task) => task.state === "awaiting_approval");
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><h2 className="font-semibold">Approval inbox</h2>
    {pending.length === 0 ? <p className="mt-3 text-sm text-slate-400">No approval requests.</p> : <ul className="mt-3 space-y-3">{pending.map((task) => {
      const busy = pendingAction?.taskId === task.id;
      const reason = reasons[task.id] ?? "";
      return <li key={task.id} className="rounded-lg border border-slate-800 p-3"><div><p className="text-sm">{task.prompt}</p><StatusBadge state={task.state} /></div><div className="mt-3 flex flex-wrap items-center gap-2"><button disabled={busy} onClick={() => onApprove(task)} className="rounded-md bg-emerald-600 px-3 py-2 text-sm hover:bg-emerald-500 disabled:cursor-wait disabled:opacity-60">{busy && pendingAction?.operation === "approve" ? "Approving…" : "Approve"}</button>{onDeny && <><input aria-label={`Deny reason for ${task.id}`} value={reason} placeholder="Reason for denial" className="min-w-48 flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm" onChange={(event) => setReasons((current) => ({ ...current, [task.id]: event.target.value }))} /><button disabled={busy || !reason.trim()} onClick={() => onDeny(task, reason)} className="rounded-md border border-rose-700 px-3 py-2 text-sm text-rose-200 hover:bg-rose-950/50 disabled:cursor-wait disabled:opacity-60">{busy && pendingAction?.operation === "deny" ? "Denying…" : "Deny"}</button></>}</div></li>;
    })}</ul>}
  </section>;
}
