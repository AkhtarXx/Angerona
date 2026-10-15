import { useEffect, useMemo, useRef, useState } from 'react'
import { ScrollContext } from './ScrollContext'
import type { ScrollState } from './ScrollContext'

export function ScrollProvider({ children }: { children: React.ReactNode }) {
  const [y, setY] = useState(0)
  const [vh, setVh] = useState(() =>
    typeof window !== 'undefined' ? window.innerHeight : 1,
  )
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    const sync = () => {
      rafRef.current = null
      setY(window.scrollY)
    }

    const onScroll = () => {
      if (rafRef.current !== null) return
      rafRef.current = requestAnimationFrame(sync)
    }

    const onResize = () => {
      setVh(window.innerHeight)
    }

    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onResize, { passive: true })
    sync()

    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onResize)
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current)
    }
  }, [])

  const state = useMemo<ScrollState>(
    () => ({ y, viewportProgress: Math.min(1, y / vh) }),
    [y, vh],
  )

  return <ScrollContext.Provider value={state}>{children}</ScrollContext.Provider>
}
