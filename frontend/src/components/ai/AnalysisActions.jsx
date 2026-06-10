import ProgressBar from '../common/ProgressBar'
import { useSimulatedProgress } from '../../hooks/useSimulatedProgress'
import { getLoadingLabel } from '../../utils/progress'

const VERDICTS = ['UNKNOWN', 'MALICIOUS', 'SUSPICIOUS', 'SAFE']

export default function AnalysisActions({
  job,
  onRunAi,
  onFetchIntel,
  onIndex,
  onDownload,
  aiLoading,
  intelLoading,
  indexLoading,
  indexVerdict,
  onVerdictChange,
  message,
  error,
}) {
  const isCompleted = (job?.status || '').toLowerCase() === 'completed'
  const intelProgress = useSimulatedProgress(intelLoading, 90)
  const indexProgress = useSimulatedProgress(indexLoading, 90)
  const anyActionLoading = intelLoading || indexLoading

  return (
    <section className="card actions-card">
      <div className="card-header">
        <h2>Actions</h2>
      </div>
      <div className="actions-row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!isCompleted || aiLoading}
          onClick={onRunAi}
        >
          {aiLoading ? 'Running AI…' : 'Run AI Analysis'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={!isCompleted || intelLoading}
          onClick={onFetchIntel}
        >
          {intelLoading ? 'Checking…' : 'Check VirusTotal'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={!isCompleted || !job?.zip_artifact_available}
          onClick={onDownload}
        >
          Download ZIP
        </button>
      </div>

      <div className="index-row">
        <select
          value={indexVerdict}
          onChange={(event) => onVerdictChange(event.target.value)}
          disabled={!isCompleted || indexLoading}
        >
          {VERDICTS.map((verdict) => (
            <option key={verdict} value={verdict}>{verdict}</option>
          ))}
        </select>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={!isCompleted || indexLoading}
          onClick={onIndex}
        >
          {indexLoading ? 'Indexing…' : 'Index to Knowledge Base'}
        </button>
      </div>

      {intelLoading && (
        <div className="action-progress">
          <ProgressBar value={intelProgress} label={getLoadingLabel('intel')} variant="primary" />
        </div>
      )}

      {indexLoading && (
        <div className="action-progress">
          <ProgressBar value={indexProgress} label={getLoadingLabel('index')} variant="primary" />
        </div>
      )}

      {message && !anyActionLoading && !aiLoading && <p className="form-success">{message}</p>}
      {error && <p className="form-error">{error}</p>}
    </section>
  )
}
