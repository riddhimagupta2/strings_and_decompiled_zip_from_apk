export function useJobProgress(job) {
  if (!job) {
    return { percent: 0, label: '', active: false }
  }

  const status = (job.status || '').toLowerCase()
  const percent = job.progress_percent ?? 0
  const label = job.progress_label || ''

  if (status === 'completed') {
    return { percent: 100, label: label || 'Analysis complete', active: false }
  }

  if (status === 'failed') {
    return { percent: 100, label: label || 'Analysis failed', active: false, failed: true }
  }

  if (status === 'pending') {
    return {
      percent: percent || 1,
      label: label || 'Queued for analysis…',
      active: true,
    }
  }

  if (status === 'running') {
    return {
      percent: Math.max(percent, 1),
      label: label || 'Analyzing APK…',
      active: true,
    }
  }

  return { percent: 0, label: '', active: false }
}
