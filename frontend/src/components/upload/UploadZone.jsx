import { useRef, useState } from 'react'
import ProgressBar from '../common/ProgressBar'
import { useSimulatedProgress } from '../../hooks/useSimulatedProgress'
import { getLoadingLabel } from '../../utils/progress'

export default function UploadZone({ onUpload, uploading }) {
  const inputRef = useRef(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState(null)
  const uploadProgress = useSimulatedProgress(uploading, 85)

  const handleFile = async (file) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are accepted')
      return
    }
    setError(null)
    try {
      await onUpload(file)
    } catch (err) {
      setError(err.message)
    }
  }

  const onDrop = (event) => {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files?.[0]
    handleFile(file)
  }

  return (
    <section className="card upload-card">
      <div
        className={`upload-zone ${dragging ? 'upload-zone-active' : ''} ${uploading ? 'upload-zone-busy' : ''}`}
        onDragOver={(event) => {
          event.preventDefault()
          if (!uploading) setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !uploading && inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click()
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk"
          hidden
          disabled={uploading}
          onChange={(event) => handleFile(event.target.files?.[0])}
        />
        {uploading ? (
          <div className="upload-progress">
            <div className="upload-icon">📁</div>
            <ProgressBar
              value={uploadProgress}
              label={getLoadingLabel('upload')}
              variant="primary"
            />
          </div>
        ) : (
          <>
            <div className="upload-icon">📁</div>
            <h2>Drop APK here or click to upload</h2>
            <p>Max 150 MB · Static analysis runs in the background</p>
          </>
        )}
      </div>
      {error && <p className="form-error">{error}</p>}
    </section>
  )
}
