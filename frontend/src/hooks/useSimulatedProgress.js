import { useEffect, useState } from 'react'

export function useSimulatedProgress(active, maxWhileActive = 92) {
  const [percent, setPercent] = useState(0)

  useEffect(() => {
    if (!active) {
      setPercent(0)
      return undefined
    }

    setPercent(10)
    const timer = setInterval(() => {
      setPercent((prev) => {
        if (prev >= maxWhileActive) return prev
        const step = prev < 40 ? 4 : prev < 70 ? 2.5 : 1.2
        return Math.min(prev + step, maxWhileActive)
      })
    }, 250)

    return () => clearInterval(timer)
  }, [active, maxWhileActive])

  return Math.round(percent)
}
