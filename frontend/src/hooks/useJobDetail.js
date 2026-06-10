import { useCallback, useEffect, useState } from 'react'
import { fetchJob } from '../api/analysis'

export function useJobDetail(jobId) {
  const [job, setJob] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(async (silent = false) => {
    if (!jobId) {
      setJob(null)
      return
    }

    if (!silent) setLoading(true)
    try {
      const data = await fetchJob(jobId)
      setJob(data)
      setError(null)
    } catch (err) {
      setError(err.message)
      if (!silent) setJob(null)
    } finally {
      if (!silent) setLoading(false)
    }
  }, [jobId])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!jobId) return undefined
    const status = (job?.status || '').toLowerCase()
    if (job && status !== 'pending' && status !== 'running') return undefined

    const timer = setInterval(() => load(true), 1000)
    return () => clearInterval(timer)
  }, [jobId, job?.status, load])

  return { job, loading, error, refresh: load }
}
