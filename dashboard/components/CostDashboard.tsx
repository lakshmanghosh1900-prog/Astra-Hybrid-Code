export function CostDashboard({ tasks }: { tasks: { tokens: number; repairs: number }[] }) {
  const tokens = tasks.reduce((total, task) => total + task.tokens, 0);
  const repairs = tasks.reduce((total, task) => total + task.repairs, 0);
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><h2 className="font-semibold">Cost & reliability</h2><div className="mt-3 grid grid-cols-2 gap-3"><div className="rounded bg-slate-950 p-3"><p className="text-xs text-slate-500">Tokens</p><p className="text-xl">{tokens.toLocaleString()}</p></div><div className="rounded bg-slate-950 p-3"><p className="text-xs text-slate-500">Repairs</p><p className="text-xl">{repairs}</p></div></div></section>;
}
