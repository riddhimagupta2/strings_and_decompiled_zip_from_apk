import { useCallback, useEffect, useState } from 'react'
import { fetchJobs } from '../api/analysis'

export function useJobs(pollInterval = 1500) {
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async (silent = false) => {
    try {
      const data = await fetchJobs({ limit: 50 })
      setJobs(data)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      if (!silent) setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    const hasActive = jobs.some((job) => {
      const status = (job.status || '').toLowerCase()
      return status === 'pending' || status === 'running'
    })
    if (!hasActive) return undefined

    const timer = setInterval(() => load(true), pollInterval)
    return () => clearInterval(timer)
  }, [jobs, load, pollInterval])

  return { jobs, loading, error, refresh: load }
}
