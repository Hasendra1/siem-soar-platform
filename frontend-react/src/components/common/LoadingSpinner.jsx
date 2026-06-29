export default function LoadingSpinner({ size = 'md', text = '' }) {
  const sz = { sm: 'w-4 h-4 border-2', md: 'w-8 h-8 border-2', lg: 'w-12 h-12 border-3' }[size];
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-dark-secondary">
      <div className={`${sz} border-dark-border border-t-accent-cyan rounded-full animate-spin`} />
      {text && <p className="text-xs">{text}</p>}
    </div>
  );
}
