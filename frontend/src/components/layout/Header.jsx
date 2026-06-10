export default function Header({ indexedChunks }) {
  return (
    <header className="header">
      <div className="header-brand">
        <div className="header-icon">🛡️</div>
        <div>
          <h1>APK Malware Analyzer</h1>
          <p>Static extraction · Threat intel · AI verdict</p>
        </div>
      </div>
      {indexedChunks != null && (
        <div className="header-stat">
          <span className="header-stat-value">{indexedChunks}</span>
          <span className="header-stat-label">Indexed chunks</span>
        </div>
      )}
    </header>
  )
}
