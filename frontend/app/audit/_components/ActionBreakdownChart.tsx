import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";

interface Props {
  actionData: { action: string; count: number }[];
}

export default function ActionBreakdownChart({ actionData }: Props) {
  return (
    <div className="glass rounded-2xl overflow-hidden">
      <div className="px-6 py-4 border-b border-white/5">
        <h2 className="text-white font-semibold">Action Breakdown</h2>
      </div>
      <div className="p-6 h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={actionData} layout="vertical" barCategoryGap="20%" margin={{ top: 0, right: 24, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
            <XAxis type="number" tick={{ fill: "#9ca3af", fontSize: 12 }} axisLine={false} tickLine={false} />
            <YAxis
              type="category"
              dataKey="action"
              tick={{ fill: "#9ca3af", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={110}
              tickFormatter={(v: string) => v.replace(/_/g, " ")}
            />
            <Tooltip
              contentStyle={{ background: "#0f1117", border: "1px solid #1e2030", borderRadius: "4px", color: "#e4e4e8" }}
              labelStyle={{ color: "#e4e4e8" }}
              itemStyle={{ color: "#fbbf24" }}
              cursor={{ fill: "rgba(255,255,255,0.03)" }}
            />
            <Bar dataKey="count" fill="#6366f1" radius={[0, 6, 6, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
