import { taskLifecycleState, type TaskState } from "../lib/api";

export function StatusBadge({ state }: { state: TaskState }) {
  const lifecycle = taskLifecycleState(state);
  const color = lifecycle === "succeeded" ? "bg-emerald-500/20 text-emerald-300"
    : lifecycle === "failed" ? "bg-rose-500/20 text-rose-300"
    : lifecycle === "cancelled" ? "bg-slate-500/20 text-slate-300"
    : lifecycle === "pending" ? "bg-amber-500/20 text-amber-300"
    : "bg-sky-500/20 text-sky-300";
  return <span title={state} className={`rounded-full px-2 py-1 text-xs font-medium ${color}`}>{lifecycle}</span>;
}
