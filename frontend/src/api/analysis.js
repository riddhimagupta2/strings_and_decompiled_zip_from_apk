import { request, getBaseUrl } from './client'

export async function uploadApk(file) {
  const formData = new FormData()
  formData.append('file', file)
  return request('/api/v1/analyze', {
    method: 'POST',
    body: formData,
  })
}

export async function fetchJobs(params = {}) {
  const search = new URLSearchParams()
  if (params.skip != null) search.set('skip', params.skip)
  if (params.limit != null) search.set('limit', params.limit)
  if (params.status) search.set('status', params.status)
  const query = search.toString()
  return request(`/api/v1/jobs${query ? `?${query}` : ''}`)
}

export async function fetchJob(jobId) {
  return request(`/api/v1/jobs/${jobId}`)
}

export async function deleteJob(jobId) {
  return request(`/api/v1/jobs/${jobId}`, { method: 'DELETE' })
}

export function getDownloadUrl(jobId) {
  const base = getBaseUrl()
  const path = `/api/v1/jobs/${jobId}/download`
  if (base) return `${base}${path}`
  if (typeof window !== 'undefined') return `${window.location.origin}${path}`
  return path
}
