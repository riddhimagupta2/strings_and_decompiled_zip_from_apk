import Badge from '../common/Badge'
import { getVerdictClass } from '../../utils/risk'

export default function VerdictCard({ analysis, similarCases }) {
  if (!analysis) return null

  const llm = analysis.llm_analysis || analysis
  const verdictClass = getVerdictClass(llm.verdict)

  return (
    <section className={`card verdict-card ${verdictClass}`}>
      <div className="verdict-header">
        <div>
          <span className="verdict-label">AI Verdict</span>
          <h2>{llm.verdict || 'UNKNOWN'}</h2>
        </div>
        <div className="verdict-meta">
          <Badge className={verdictClass}>{llm.confidence || 'LOW'}</Badge>
          {llm.risk_score != null && llm.risk_score >= 0 && (
            <span className="verdict-score">Risk {llm.risk_score}/10</span>
          )}
        </div>
      </div>

      <div className="verdict-body">
        <div className="verdict-row">
          <span>Threat category</span>
          <strong>{llm.threat_category || 'Unknown'}</strong>
        </div>
        <div className="verdict-row">
          <span>Recommended action</span>
          <strong>{llm.recommended_action || 'INVESTIGATE'}</strong>
        </div>
        {similarCases != null && (
          <div className="verdict-row">
            <span>Similar cases</span>
            <strong>{similarCases}</strong>
          </div>
        )}
      </div>

      {llm.behavior_summary && (
        <p className="verdict-summary">{llm.behavior_summary}</p>
      )}

      {llm.reasons?.length > 0 && (
        <div className="verdict-section">
          <h3>Reasons</h3>
          <ul>
            {llm.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </div>
      )}

      {llm.ioc_highlights?.length > 0 && (
        <div className="verdict-section">
          <h3>IOC Highlights</h3>
          <div className="chip-list inline">
            {llm.ioc_highlights.map((ioc, index) => (
              <Badge key={index} className="ioc-chip">{ioc}</Badge>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
