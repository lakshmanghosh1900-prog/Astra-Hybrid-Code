export function DiffViewer({ diff }: { diff: string }) {
  return <section className="rounded-xl border border-slate-800 bg-slate-900 p-5"><h2 className="font-semibold">Diff / workspace status</h2><pre className="mt-3 max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-300">{diff || "No diff evidence available."}</pre></section>;
}
