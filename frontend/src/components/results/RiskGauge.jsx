import { getRiskLevel } from '../../utils/risk'

export default function RiskGauge({ score }) {
  const risk = getRiskLevel(score)
  const value = score != null && score >= 0 ? score : 0
  const percent = Math.min((value / 10) * 100, 100)

  return (
    <div className={`risk-gauge ${risk.className}`}>
      <div className="risk-gauge-ring">
        <svg viewBox="0 0 120 120">
          <circle className="risk-gauge-track" cx="60" cy="60" r="52" />
          <circle
            className="risk-gauge-fill"
            cx="60"
            cy="60"
            r="52"
            style={{ strokeDashoffset: `${326 - (326 * percent) / 100}` }}
          />
        </svg>
        <div className="risk-gauge-center">
          <strong>{score != null ? score.toFixed(1) : '—'}</strong>
          <span>{risk.label}</span>
        </div>
      </div>
    </div>
  )
}
