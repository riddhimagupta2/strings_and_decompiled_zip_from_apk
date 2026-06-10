export default function ProgressBar({
  value = 0,
  label,
  showPercent = true,
  indeterminate = false,
  variant = 'default',
  size = 'md',
}) {
  const clamped = Math.min(Math.max(value, 0), 100)

  return (
    <div className={`progress-wrap progress-${size}`}>
      {(label || showPercent) && (
        <div className="progress-header">
          {label && <span className="progress-label">{label}</span>}
          {showPercent && !indeterminate && (
            <span className="progress-percent">{clamped}%</span>
          )}
        </div>
      )}
      <div className={`progress-track progress-track-${variant}`}>
        <div
          className={`progress-fill ${indeterminate ? 'progress-fill-indeterminate' : ''}`}
          style={indeterminate ? undefined : { width: `${clamped}%` }}
        />
      </div>
    </div>
  )
}
