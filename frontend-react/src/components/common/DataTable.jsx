import { ChevronUp, ChevronDown } from 'lucide-react';
import { useState } from 'react';

export default function DataTable({ columns = [], rows = [], emptyMsg = 'No data', maxH = null }) {
  const [sort, setSort] = useState({ key: null, dir: 'asc' });

  const sorted = [...rows].sort((a, b) => {
    if (!sort.key) return 0;
    const av = a[sort.key] ?? '';
    const bv = b[sort.key] ?? '';
    const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
    return sort.dir === 'asc' ? cmp : -cmp;
  });

  const toggle = (key) =>
    setSort(p => p.key === key ? { key, dir: p.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' });

  return (
    <div className={`overflow-auto rounded-lg border border-dark-border ${maxH ? `max-h-[${maxH}]` : ''}`}>
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-dark-sidebar z-10">
          <tr>
            {columns.map(col => (
              <th
                key={col.key}
                onClick={() => col.sortable !== false && toggle(col.key)}
                className={`px-4 py-3 text-left text-dark-secondary font-semibold uppercase tracking-wider whitespace-nowrap
                  ${col.sortable !== false ? 'cursor-pointer hover:text-white' : ''}`}
              >
                <span className="inline-flex items-center gap-1">
                  {col.label}
                  {sort.key === col.key && (sort.dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="text-center py-12 text-dark-secondary">{emptyMsg}</td>
            </tr>
          ) : (
            sorted.map((row, i) => (
              <tr key={i} className="border-t border-dark-border tr-hover">
                {columns.map(col => (
                  <td key={col.key} className="px-4 py-3 text-white">
                    {col.render ? col.render(row[col.key], row) : (row[col.key] ?? '—')}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
