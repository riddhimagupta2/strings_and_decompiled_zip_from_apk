import { request } from './client'

export async function analyzeWithRag(jobId) {
  return request('/api/v1/rag/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId }),
  })
}

export async function indexApk(jobId, verdict = 'UNKNOWN') {
  return request('/api/v1/rag/index', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId, verdict }),
  })
}

export async function fetchRagStatus() {
  return request('/api/v1/rag/status')
}
