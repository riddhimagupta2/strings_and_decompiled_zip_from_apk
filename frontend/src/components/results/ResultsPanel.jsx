import Badge from '../common/Badge'
import ProgressBar from '../common/ProgressBar'
import EmptyState from '../common/EmptyState'
import RiskGauge from './RiskGauge'
import OverviewSection from './OverviewSection'
import DetailTabs from './DetailTabs'
import AnalysisActions from '../ai/AnalysisActions'
import VerdictCard from '../ai/VerdictCard'
import IntelPanel from '../ai/IntelPanel'
import { formatDate } from '../../utils/format'
import { getStatusClass, getRiskLevel } from '../../utils/risk'
import { useJobProgress } from '../../hooks/useJobProgress'
import { getLoadingLabel } from '../../utils/progress'

export default function ResultsPanel({
  job,
  loading,
  error,
  selectedJobId,
  aiResult,
  intelResult,
  aiLoading,
  intelLoading,
  indexLoading,
  indexVerdict,
  actionMessage,
  actionError,
  onRunAi,
  onFetchIntel,
  onIndex,
  onDownload,
  onVerdictChange,
}) {
  const jobProgress = useJobProgress(job)

  if (!selectedJobId) {
    return (
      <section className="card results-empty">
        <EmptyState
          title="Select a job"
          description="Choose a job from the list to view extraction results and run AI analysis."
        />
      </section>
    )
  }

  if (loading && !job) {
    return (
      <section className="card">
        <ProgressBar indeterminate label={getLoadingLabel('detail')} variant="primary" showPercent={false} />
      </section>
    )
  }

  if (error) {
    return (
      <section className="card">
        <p className="form-error">{error}</p>
      </section>
    )
  }

  if (!job) return null

  const status = (job.status || '').toLowerCase()
  const isProcessing = status === 'pending' || status === 'running'
  const risk = getRiskLevel(job.risk_score)

  return (
    <div className="results-stack">
      <section className="card results-hero">
        <div className="results-header">
          <div className="results-title-block">
            <h2>{job.filename}</h2>
            {job.package_name && <p className="package-subtitle mono">{job.package_name}</p>}
            <p className="muted">Updated {formatDate(job.updated_at)}</p>
          </div>
          <Badge className={getStatusClass(job.status)}>{job.status}</Badge>
        </div>

        {isProcessing && (
          <div className="processing-banner">
            <ProgressBar
              value={jobProgress.percent}
              label={jobProgress.label}
              variant="primary"
            />
          </div>
        )}

        {status === 'failed' && (
          <p className="form-error">{job.error_message || 'Analysis failed'}</p>
        )}

        {status === 'completed' && (
          <div className="results-hero-body">
            <div className={`risk-score-card ${risk.className}`}>
              <RiskGauge score={job.risk_score} />
              <div className="risk-score-caption">
                <span>Risk Score</span>
                <strong>{risk.label}</strong>
              </div>
            </div>
            <OverviewSection job={job} />
          </div>
        )}
      </section>

      {status === 'completed' && (
        <>
          <AnalysisActions
            job={job}
            onRunAi={onRunAi}
            onFetchIntel={onFetchIntel}
            onIndex={onIndex}
            onDownload={onDownload}
            aiLoading={aiLoading}
            intelLoading={intelLoading}
            indexLoading={indexLoading}
            indexVerdict={indexVerdict}
            onVerdictChange={onVerdictChange}
            message={actionMessage}
            error={actionError}
          />

          {aiLoading && (
            <section className="card action-progress-card">
              <ProgressBar
                indeterminate
                label={getLoadingLabel('ai')}
                variant="primary"
                showPercent={false}
              />
            </section>
          )}

          <VerdictCard
            analysis={aiResult}
            similarCases={aiResult?.similar_cases_found}
          />

          <IntelPanel
            intel={intelResult}
            loading={intelLoading}
            error={null}
          />

          <section className="card details-card">
            <div className="card-header">
              <div>
                <h2>Extraction Details</h2>
                <p className="card-subtitle">Permissions, IOCs, API calls, components & certificate</p>
              </div>
            </div>
            <DetailTabs job={job} />
          </section>
        </>
      )}
    </div>
  )
}
