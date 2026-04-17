interface SkeletonCardProps {
  rows?: number
  height?: number
}

export default function SkeletonCard({ rows = 3, height }: SkeletonCardProps) {
  return (
    <div className="card skeleton-card" style={height ? { height } : undefined}>
      <div className="skeleton skeleton-text-sm skeleton-card-kicker" style={{ width: '34%', marginBottom: 14 }} />
      <div className="skeleton skeleton-value skeleton-card-value" style={{ marginBottom: 16 }} />
      <div className="skeleton-card-stack">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="skeleton skeleton-text" style={{ width: `${70 + (i % 3) * 10}%`, marginBottom: 8 }} />
        ))}
      </div>
    </div>
  )
}
