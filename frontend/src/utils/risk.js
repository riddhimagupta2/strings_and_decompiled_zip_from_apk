export function getRiskLevel(score) {
  if (score == null || score < 0) return { label: 'Unknown', className: 'risk-unknown' }
  if (score < 2) return { label: 'Low', className: 'risk-low' }
  if (score < 4) return { label: 'Medium', className: 'risk-medium' }
  if (score < 7) return { label: 'High', className: 'risk-high' }
  return { label: 'Critical', className: 'risk-critical' }
}

export function getSeverityClass(severity) {
  const key = (severity || '').toLowerCase()
  if (key === 'critical') return 'severity-critical'
  if (key === 'high') return 'severity-high'
  if (key === 'medium') return 'severity-medium'
  return 'severity-low'
}

export function getVerdictClass(verdict) {
  const key = (verdict || '').toUpperCase()
  if (key === 'MALICIOUS') return 'verdict-malicious'
  if (key === 'SUSPICIOUS') return 'verdict-suspicious'
  if (key === 'SAFE') return 'verdict-safe'
  return 'verdict-unknown'
}

export function getStatusClass(status) {
  const key = (status || '').toLowerCase()
  if (key === 'completed') return 'status-completed'
  if (key === 'running') return 'status-running'
  if (key === 'pending') return 'status-pending'
  if (key === 'failed') return 'status-failed'
  return 'status-unknown'
}
