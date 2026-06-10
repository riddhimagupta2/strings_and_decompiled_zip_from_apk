import Badge from '../common/Badge'
import ProgressBar from '../common/ProgressBar'
import { useSimulatedProgress } from '../../hooks/useSimulatedProgress'
import { getLoadingLabel } from '../../utils/progress'

function VirusTotalResult({ result }) {
  if (!result) return null

  if (result.error) {
    return <p className="form-error">{result.error}</p>
  }

  if (!result.found) {
    return <p className="muted">Hash not found on VirusTotal</p>
  }

  const data = result.data || {}

  return (
    <>
      <div className="intel-stats">
        <div>
          <span>Malicious</span>
          <strong className="text-danger">{data.malicious ?? 0}</strong>
        </div>
        <div>
          <span>Suspicious</span>
          <strong className="text-warning">{data.suspicious ?? 0}</strong>
        </div>
        <div>
          <span>Undetected</span>
          <strong>{data.undetected ?? 0}</strong>
        </div>
        <div>
          <span>Total engines</span>
          <strong>{data.total_engines ?? 0}</strong>
        </div>
      </div>
      {data.popular_threat_name && (
        <p className="intel-threat"><strong>Threat:</strong> {data.popular_threat_name}</p>
      )}
      {data.tags?.length > 0 && (
        <div className="chip-list inline">
          {data.tags.map((tag) => (
            <Badge key={tag} className="ioc-chip">{tag}</Badge>
          ))}
        </div>
      )}
    </>
  )
}

export default function IntelPanel({ intel, loading, error }) {
  const progress = useSimulatedProgress(loading, 88)

  if (loading) {
    return (
      <section className="card intel-card">
        <ProgressBar value={progress} label={getLoadingLabel('intel')} variant="primary" />
      </section>
    )
  }

  if (error) return <section className="card"><p className="form-error">{error}</p></section>
  if (!intel) return null

  const vtResult = (intel.results || []).find((r) => r.source === 'virustotal')

  return (
    <section className="card intel-card">
      <div className="card-header">
        <div>
          <h2>VirusTotal</h2>
          <p className="card-subtitle">External AV engine consensus</p>
        </div>
        <span className="mono muted intel-hash">{intel.sha256}</span>
      </div>
      <VirusTotalResult result={vtResult} />
    </section>
  )
}
