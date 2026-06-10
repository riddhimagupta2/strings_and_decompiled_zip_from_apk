export default function Spinner({ size = 'md', label }) {
  return (
    <div className={`spinner-wrap spinner-${size}`} role="status">
      <div className="spinner" />
      {label && <span className="spinner-label">{label}</span>}
    </div>
  )
}
