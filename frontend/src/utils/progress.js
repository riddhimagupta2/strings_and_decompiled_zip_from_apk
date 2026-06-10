export function isJobProcessing(status) {
  const key = (status || '').toLowerCase()
  return key === 'pending' || key === 'running'
}

export function getLoadingLabel(type) {
  const labels = {
    upload: 'Uploading APK…',
    ai: 'Running AI analysis…',
    intel: 'Querying VirusTotal…',
    index: 'Indexing to knowledge base…',
    jobs: 'Loading jobs…',
    detail: 'Loading results…',
  }
  return labels[type] || 'Loading…'
}
