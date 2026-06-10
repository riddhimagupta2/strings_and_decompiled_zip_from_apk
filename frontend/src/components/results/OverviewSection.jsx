import Badge from '../common/Badge'
import { formatBytes, shortHash } from '../../utils/format'
import { getSeverityClass } from '../../utils/risk'

const STAT_ITEMS = [
  { key: 'package_name', label: 'Package', mono: true, format: (j) => j.package_name || '—' },
  { key: 'version_name', label: 'Version', format: (j) => j.version_name || '—' },
  { key: 'file_size', label: 'File Size', format: (j) => formatBytes(j.file_size) },
  { key: 'sha256', label: 'SHA256', mono: true, format: (j) => shortHash(j.sha256), title: (j) => j.sha256 },
  { key: 'permissions', label: 'Permissions', format: (j) => j.permissions?.length ?? 0 },
  { key: 'api_calls', label: 'API Calls', format: (j) => j.api_calls?.length ?? 0 },
  { key: 'classes_count', label: 'Classes', format: (j) => j.classes_count ?? '—' },
  { key: 'cert', label: 'Self-signed', format: (j) => (j.certificate?.is_self_signed ? 'Yes' : j.certificate ? 'No' : '—') },
]

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

function groupFlags(flags) {
  const groups = {}
  flags.forEach((flag) => {
    const key = (flag.severity || 'low').toLowerCase()
    if (!groups[key]) groups[key] = []
    groups[key].push(flag)
  })
  return SEVERITY_ORDER.filter((s) => groups[s]).map((s) => ({ severity: s, flags: groups[s] }))
}

export default function OverviewSection({ job }) {
  const flags = job.risk_flags || []
  const grouped = groupFlags(flags)

  return (
    <div className="overview-grid">
      <div className="details-block">
        <h3 className="details-block-title">App Overview</h3>
        <div className="stat-grid">
          {STAT_ITEMS.map((item) => (
            <div key={item.key} className="stat-item">
              <span className="stat-label">{item.label}</span>
              <span
                className={`stat-value ${item.mono ? 'mono' : ''}`}
                title={item.title ? item.title(job) : undefined}
              >
                {item.format(job)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {grouped.length > 0 && (
        <div className="details-block flags-block">
          <div className="flags-block-header">
            <h3 className="details-block-title">Risk Flags</h3>
            <span className="flags-count">{flags.length} detected</span>
          </div>
          <div className="flags-groups">
            {grouped.map(({ severity, flags: groupFlags }) => (
              <div key={severity} className="flags-group">
                <div className={`flags-group-label ${getSeverityClass(severity)}`}>
                  {severity}
                  <span className="flags-group-count">{groupFlags.length}</span>
                </div>
                <div className="flags-list">
                  {groupFlags.map((flag, index) => (
                    <div key={`${flag.flag}-${index}`} className={`flag-card flag-card-${severity}`}>
                      <div className="flag-card-top">
                        <strong className="flag-name">{flag.flag}</strong>
                        <Badge className={getSeverityClass(flag.severity)}>{flag.severity}</Badge>
                      </div>
                      <p className="flag-detail">{flag.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
