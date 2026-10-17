import type { Task } from "../lib/api";
import { StatusBadge } from "./StatusBadge";

export function ApprovalInbox({ tasks, onApprove }: { tasks: Task[]; onApprove: (task: Task) => void }) {
  const pending = tasks.filter((task) => task.state === "awaiting_approval");
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><h2 className="font-semibold">Approval inbox</h2>
    {pending.length === 0 ? <p className="mt-3 text-sm text-slate-400">No approval requests.</p> : <ul className="mt-3 space-y-3">{pending.map((task) => <li key={task.id} className="flex items-center justify-between gap-3"><div><p className="text-sm">{task.prompt}</p><StatusBadge state={task.state} /></div><button onClick={() => onApprove(task)} className="rounded-md bg-emerald-600 px-3 py-2 text-sm hover:bg-emerald-500">Approve</button></li>)}</ul>}
  </section>;
}
