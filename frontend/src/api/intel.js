import { request } from './client'

export async function fetchIntelForJob(jobId) {
  return request(`/api/v1/intel/job/${jobId}`)
}
