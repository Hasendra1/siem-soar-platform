export default function StatCard({ label, value, sub, icon: Icon, color = '#00d4ff', trend }) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 card-hover relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute inset-0 opacity-5 rounded-xl"
        style={{ background: `radial-gradient(circle at top right, ${color}, transparent)` }}
      />
      <div className="relative">
        <div className="flex items-start justify-between mb-3">
          <p className="text-dark-secondary text-xs font-medium uppercase tracking-wider">{label}</p>
          {Icon && (
            <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                 style={{ background: `${color}18` }}>
              <Icon size={16} style={{ color }} />
            </div>
          )}
        </div>
        <p className="text-3xl font-bold text-white font-mono">{value ?? '—'}</p>
        {sub && <p className="text-dark-secondary text-xs mt-1">{sub}</p>}
        {trend != null && (
          <p className={`text-xs mt-2 font-medium ${trend >= 0 ? 'text-accent-red' : 'text-accent-green'}`}>
            {trend >= 0 ? '▲' : '▼'} {Math.abs(trend)}% from last hour
          </p>
        )}
      </div>
    </div>
  );
}
