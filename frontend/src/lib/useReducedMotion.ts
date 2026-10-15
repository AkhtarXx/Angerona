import { useEffect, useState } from 'react'

let cached: boolean | null = null
const listeners = new Set<(value: boolean) => void>()

function init() {
  if (typeof window === 'undefined') return
  const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
  cached = mq.matches
  const sync = () => {
    cached = mq.matches
    listeners.forEach((cb) => cb(cached!))
  }
  mq.addEventListener('change', sync)
}

if (typeof window !== 'undefined') init()

export function useReducedMotion() {
  const [reduce, setReduce] = useState(cached ?? false)

  useEffect(() => {
    if (cached === null && typeof window !== 'undefined') init()
    listeners.add(setReduce)
    if (cached !== null) setReduce(cached)
    return () => {
      listeners.delete(setReduce)
    }
  }, [])

  return reduce
}
