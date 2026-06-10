import { useState } from 'react'

function TagList({ items, emptyLabel }) {
  if (!items || items.length === 0) {
    return <p className="empty-label">{emptyLabel}</p>
  }
  return (
    <div className="tag-cloud">
      {items.map((item, index) => (
        <span key={`${item}-${index}`} className="tag-item">{item}</span>
      ))}
    </div>
  )
}

function ListPanel({ items, emptyLabel }) {
  if (!items || items.length === 0) {
    return <p className="empty-label">{emptyLabel}</p>
  }
  return (
    <ul className="detail-list">
      {items.map((item, index) => (
        <li key={`${item}-${index}`}>
          <code>{item}</code>
        </li>
      ))}
    </ul>
  )
}

function KeyValuePanel({ data }) {
  const entries = Object.entries(data || {}).filter(([, values]) => values?.length)
  if (entries.length === 0) return <p className="empty-label">No IOCs found</p>

  return (
    <div className="kv-panels">
      {entries.map(([key, values]) => (
        <div key={key} className="kv-panel">
          <div className="kv-panel-head">
            <h4>{key.replace(/_/g, ' ')}</h4>
            <span className="kv-count">{values.length}</span>
          </div>
          <TagList items={values} emptyLabel="None" />
        </div>
      ))}
    </div>
  )
}

function CertificatePanel({ certificate }) {
  if (!certificate) return <p className="empty-label">No certificate data</p>

  const rows = [
    ['Subject', certificate.subject],
    ['Issuer', certificate.issuer],
    ['Serial', certificate.serial],
    ['Valid from', certificate.not_before],
    ['Valid until', certificate.not_after],
    ['SHA1', certificate.sha1],
    ['SHA256', certificate.sha256],
    ['Self-signed', certificate.is_self_signed ? 'Yes' : 'No'],
  ]

  return (
    <dl className="detail-dl">
      {rows.map(([label, value]) => (
        <div key={label} className="detail-dl-row">
          <dt>{label}</dt>
          <dd><code>{value || '—'}</code></dd>
        </div>
      ))}
    </dl>
  )
}

function getTabCount(job, tabId) {
  if (tabId === 'permissions') return job.permissions?.length ?? 0
  if (tabId === 'apis') return job.api_calls?.length ?? 0
  if (tabId === 'iocs') {
    return Object.values(job.hardcoded || {}).reduce((sum, arr) => sum + (arr?.length ?? 0), 0)
  }
  if (tabId === 'components') {
    return (job.activities?.length ?? 0) + (job.services?.length ?? 0)
      + (job.receivers?.length ?? 0) + (job.providers?.length ?? 0)
  }
  return null
}

const TABS = [
  { id: 'permissions', label: 'Permissions' },
  { id: 'iocs', label: 'IOCs' },
  { id: 'apis', label: 'API Calls' },
  { id: 'components', label: 'Components' },
  { id: 'certificate', label: 'Certificate' },
]

export default function DetailTabs({ job }) {
  const [activeTab, setActiveTab] = useState('permissions')

  return (
    <div className="detail-tabs">
      <div className="tab-bar">
        {TABS.map((tab) => {
          const count = getTabCount(job, tab.id)
          return (
            <button
              key={tab.id}
              type="button"
              className={`tab-btn ${activeTab === tab.id ? 'tab-btn-active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
              {count != null && count > 0 && <span className="tab-count">{count}</span>}
            </button>
          )
        })}
      </div>

      <div className="tab-panel">
        {activeTab === 'permissions' && (
          <TagList items={job.permissions} emptyLabel="No permissions found" />
        )}
        {activeTab === 'iocs' && <KeyValuePanel data={job.hardcoded} />}
        {activeTab === 'apis' && (
          <TagList items={job.api_calls} emptyLabel="No sensitive API calls found" />
        )}
        {activeTab === 'components' && (
          <div className="component-panels">
            <div className="component-panel">
              <div className="kv-panel-head">
                <h4>Activities</h4>
                <span className="kv-count">{job.activities?.length ?? 0}</span>
              </div>
              <ListPanel items={job.activities} emptyLabel="None" />
            </div>
            <div className="component-panel">
              <div className="kv-panel-head">
                <h4>Services</h4>
                <span className="kv-count">{job.services?.length ?? 0}</span>
              </div>
              <ListPanel items={job.services} emptyLabel="None" />
            </div>
            <div className="component-panel">
              <div className="kv-panel-head">
                <h4>Receivers</h4>
                <span className="kv-count">{job.receivers?.length ?? 0}</span>
              </div>
              <ListPanel items={job.receivers} emptyLabel="None" />
            </div>
            <div className="component-panel">
              <div className="kv-panel-head">
                <h4>Providers</h4>
                <span className="kv-count">{job.providers?.length ?? 0}</span>
              </div>
              <ListPanel items={job.providers} emptyLabel="None" />
            </div>
          </div>
        )}
        {activeTab === 'certificate' && <CertificatePanel certificate={job.certificate} />}
      </div>
    </div>
  )
}
