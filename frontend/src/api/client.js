const BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')

function resolveUrl(path) {
  if (path.startsWith('http')) return path
  if (BASE_URL) return `${BASE_URL}${path}`
  return path
}

function parseErrorBody(body, status) {
  if (!body) return `Request failed (${status})`
  if (typeof body === 'string') {
    if (body.includes('Invalid access token')) {
      return 'Backend connection failed — API is not reachable. Start the FastAPI server on port 8000 and restart the frontend (npm run dev).'
    }
    return body
  }
  const detail = body.detail ?? body.message ?? body.error
  if (typeof detail === 'string') {
    if (detail.includes('Invalid access token')) {
      return 'Backend connection failed — wrong service on port 8000. Use empty VITE_API_BASE_URL in dev so Vite proxies to your FastAPI backend.'
    }
    return detail
  }
  if (detail) return JSON.stringify(detail)
  return `Request failed (${status})`
}

export async function request(path, options = {}) {
  const url = resolveUrl(path)

  let response
  try {
    response = await fetch(url, options)
  } catch {
    throw new Error(
      'Cannot reach backend. Run: python3 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000'
    )
  }

  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('application/json')) {
        detail = parseErrorBody(await response.json(), response.status)
      } else {
        detail = parseErrorBody(await response.text(), response.status)
      }
    } catch {
      detail = `Request failed (${response.status})`
    }
    throw new Error(detail)
  }

  if (response.status === 204) return null

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return response.json()
  }

  return response
}

export function getBaseUrl() {
  return BASE_URL
}
