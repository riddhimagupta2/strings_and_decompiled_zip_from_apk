import Badge from '../common/Badge'
import ProgressBar from '../common/ProgressBar'
import EmptyState from '../common/EmptyState'
import { formatDate, getJobId, truncate } from '../../utils/format'
import { getRiskLevel, getStatusClass } from '../../utils/risk'
import { isJobProcessing } from '../../utils/progress'

function JobStatusCell({ job }) {
  if (!isJobProcessing(job.status)) {
    return <Badge className={getStatusClass(job.status)}>{job.status}</Badge>
  }

  const percent = job.progress_percent ?? 1
  const label = job.progress_label || (job.status === 'pending' ? 'Queued' : 'Analyzing…')

  return (
    <div className="job-status-progress">
      <Badge className={getStatusClass(job.status)}>{job.status}</Badge>
      <ProgressBar
        value={percent}
        label={label}
        size="sm"
        variant="primary"
      />
    </div>
  )
}

export default function JobList({
  jobs,
  loading,
  error,
  selectedJobId,
  onSelect,
  onDelete,
  deletingId,
}) {
  if (loading && jobs.length === 0) {
    return (
      <section className="card">
        <ProgressBar indeterminate label="Loading jobs…" showPercent={false} variant="primary" />
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

  if (jobs.length === 0) {
    return (
      <section className="card">
        <EmptyState
          title="No analysis jobs yet"
          description="Upload an APK to start your first scan."
        />
      </section>
    )
  }

  return (
    <section className="card">
      <div className="card-header">
        <h2>Recent Jobs</h2>
        <span className="muted">{jobs.length} total</span>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>File</th>
              <th>Package</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => {
              const jobId = getJobId(job)
              const risk = getRiskLevel(job.risk_score)
              const isSelected = selectedJobId === jobId
              return (
                <tr
                  key={jobId}
                  className={isSelected ? 'row-selected' : ''}
                  onClick={() => onSelect(jobId)}
                >
                  <td>{truncate(job.filename, 32)}</td>
                  <td className="mono">{truncate(job.package_name, 28)}</td>
                  <td>
                    {job.risk_score != null ? (
                      <Badge className={risk.className}>
                        {job.risk_score.toFixed(1)} · {risk.label}
                      </Badge>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="job-status-cell">
                    <JobStatusCell job={job} />
                  </td>
                  <td className="muted">{formatDate(job.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      disabled={deletingId === jobId}
                      onClick={(event) => {
                        event.stopPropagation()
                        onDelete(jobId)
                      }}
                    >
                      {deletingId === jobId ? '…' : 'Delete'}
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}
