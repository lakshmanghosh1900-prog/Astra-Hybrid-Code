import type { Task } from "../lib/api";
import { StatusBadge } from "./StatusBadge";

export function TaskList({ tasks, selected, onSelect }: {
  tasks: Task[];
  selected?: string;
  onSelect: (task: Task) => void;
}) {
  if (tasks.length === 0) return <p className="rounded-lg border border-slate-800 p-6 text-slate-400">No tasks yet.</p>;
  return <div className="space-y-2">{tasks.map((task) => (
    <button key={task.id} onClick={() => onSelect(task)} className={`w-full rounded-lg border p-4 text-left ${selected === task.id ? "border-sky-400 bg-slate-800" : "border-slate-800 bg-slate-900 hover:border-slate-600"}`}>
      <div className="flex items-center justify-between gap-3"><span className="truncate font-medium">{task.prompt}</span><StatusBadge state={task.state} /></div>
      <div className="mt-2 text-xs text-slate-500">{task.id} · {task.risk} · {task.tokens.toLocaleString()} tokens</div>
    </button>
  ))}</div>;
}
