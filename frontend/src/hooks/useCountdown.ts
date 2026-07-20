import { useEffect, useState } from "react"

interface Countdown {
  totalSeconds: number
  hours: number
  minutes: number
  seconds: number
  expired: boolean
}

export function useCountdown(targetIso: string): Countdown {
  const compute = (): Countdown => {
    const diff = Math.max(0, new Date(targetIso).getTime() - Date.now() - 30 * 60 * 1000)
    const totalSeconds = Math.floor(diff / 1000)
    return {
      totalSeconds,
      hours: Math.floor(totalSeconds / 3600),
      minutes: Math.floor((totalSeconds % 3600) / 60),
      seconds: totalSeconds % 60,
      expired: totalSeconds === 0,
    }
  }

  const [state, setState] = useState<Countdown>(compute)

  useEffect(() => {
    if (state.expired) return
    const id = setInterval(() => {
      const next = compute()
      setState(next)
      if (next.expired) clearInterval(id)
    }, 1000)
    return () => clearInterval(id)
  }, [targetIso, state.expired])

  return state
}
