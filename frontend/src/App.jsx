import { useEffect, useState } from 'react'
import Layout from './components/layout/Layout'
import UploadZone from './components/upload/UploadZone'
import JobList from './components/jobs/JobList'
import ResultsPanel from './components/results/ResultsPanel'
import { uploadApk, deleteJob, getDownloadUrl } from './api/analysis'
import { fetchIntelForJob } from './api/intel'
import { analyzeWithRag, indexApk } from './api/rag'
import { useJobs } from './hooks/useJobs'
import { useJobDetail } from './hooks/useJobDetail'
export default function App() {
  const { jobs, loading: jobsLoading, error: jobsError, refresh: refreshJobs } = useJobs()
  const [selectedJobId, setSelectedJobId] = useState(null)
  const { job, loading: jobLoading, error: jobError, refresh: refreshJob } = useJobDetail(selectedJobId)

  const [uploading, setUploading] = useState(false)
  const [deletingId, setDeletingId] = useState(null)

  const [aiResult, setAiResult] = useState(null)
  const [intelResult, setIntelResult] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [intelLoading, setIntelLoading] = useState(false)
  const [indexLoading, setIndexLoading] = useState(false)
  const [indexVerdict, setIndexVerdict] = useState('UNKNOWN')
  const [actionMessage, setActionMessage] = useState('')
  const [actionError, setActionError] = useState('')

  useEffect(() => {
    setAiResult(null)
    setIntelResult(null)
    setActionMessage('')
    setActionError('')
  }, [selectedJobId])

  const handleUpload = async (file) => {
    setUploading(true)
    try {
      const response = await uploadApk(file)
      const jobId = response.job_id
      await refreshJobs()
      setSelectedJobId(jobId)
    } finally {
      setUploading(false)
    }
  }

  const handleDelete = async (jobId) => {
    setDeletingId(jobId)
    try {
      await deleteJob(jobId)
      if (selectedJobId === jobId) setSelectedJobId(null)
      await refreshJobs()
    } catch (err) {
      setActionError(err.message)
    } finally {
      setDeletingId(null)
    }
  }

  const handleRunAi = async () => {
    if (!selectedJobId) return
    setAiLoading(true)
    setActionError('')
    setActionMessage('')
    try {
      const result = await analyzeWithRag(selectedJobId)
      setAiResult(result)
      setActionMessage('AI analysis completed')
    } catch (err) {
      setActionError(err.message)
    } finally {
      setAiLoading(false)
    }
  }

  const handleFetchIntel = async () => {
    if (!selectedJobId) return
    setIntelLoading(true)
    setActionError('')
    try {
      const result = await fetchIntelForJob(selectedJobId)
      setIntelResult(result)
    } catch (err) {
      setActionError(err.message)
    } finally {
      setIntelLoading(false)
    }
  }

  const handleIndex = async () => {
    if (!selectedJobId) return
    setIndexLoading(true)
    setActionError('')
    setActionMessage('')
    try {
      const result = await indexApk(selectedJobId, indexVerdict)
      setActionMessage(`Indexed ${result.chunks_indexed} chunks (${result.verdict_stored})`)
    } catch (err) {
      setActionError(err.message)
    } finally {
      setIndexLoading(false)
    }
  }

  const handleDownload = () => {
    if (!selectedJobId) return
    window.open(getDownloadUrl(selectedJobId), '_blank')
  }

  const handleSelect = (jobId) => {
    setSelectedJobId(jobId)
  }

  return (
    <Layout>
      <div className="app-grid">
        <div className="left-column">
          <UploadZone onUpload={handleUpload} uploading={uploading} />
          <JobList
            jobs={jobs}
            loading={jobsLoading}
            error={jobsError}
            selectedJobId={selectedJobId}
            onSelect={handleSelect}
            onDelete={handleDelete}
            deletingId={deletingId}
          />
        </div>
        <div className="right-column">
          <ResultsPanel
            job={job}
            loading={jobLoading}
            error={jobError}
            selectedJobId={selectedJobId}
            aiResult={aiResult}
            intelResult={intelResult}
            aiLoading={aiLoading}
            intelLoading={intelLoading}
            indexLoading={indexLoading}
            indexVerdict={indexVerdict}
            actionMessage={actionMessage}
            actionError={actionError}
            onRunAi={handleRunAi}
            onFetchIntel={handleFetchIntel}
            onIndex={handleIndex}
            onDownload={handleDownload}
            onVerdictChange={setIndexVerdict}
          />
        </div>
      </div>
    </Layout>
  )
}
