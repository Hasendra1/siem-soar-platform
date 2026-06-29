import { Bell, RefreshCw } from 'lucide-react';

export default function Header({ title, subtitle, onRefresh, loading }) {
  return (
    <header className="h-16 bg-dark-sidebar border-b border-dark-border flex items-center px-6 justify-between shrink-0">
      <div>
        <h1 className="text-white font-semibold text-base leading-none">{title}</h1>
        {subtitle && <p className="text-dark-secondary text-xs mt-1">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            id="header-refresh-btn"
            onClick={onRefresh}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs text-dark-secondary hover:text-white hover:bg-dark-hover border border-dark-border transition-all duration-200"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        )}
        <button className="relative p-2 rounded-lg text-dark-secondary hover:text-white hover:bg-dark-hover transition-colors">
          <Bell size={18} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-accent-red rounded-full" />
        </button>
      </div>
    </header>
  );
}
