import {
  useEffect,
  useRef,
  useState,
  type ElementType,
  type ReactNode,
} from 'react'

/*
  VolumetricCard — a glass card with real 3D thickness and hover parallax tilt.

  - User-initiated hover tilt with inertia damping.
  - Fully disabled under prefers-reduced-motion and on touch / small screens.
  - No external animation libraries; native CSS transforms via refs.
*/

const TILT_MAX_X = 6
const TILT_MAX_Y = 8
const DAMPING = 0.12
const RESET_DAMPING = 0.18
const ENABLE_BREAKPOINT = 1024

const THICKNESS_LAYERS = [-3, -1.5, 0]

function useTiltEnabled() {
  const [enabled, setEnabled] = useState(false)
  const [reduce, setReduce] = useState(false)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduce(mq.matches)
    const sync = () => setReduce(mq.matches)
    mq.addEventListener('change', sync)

    const check = () => {
      const mq2 = window.matchMedia(
        `(min-width: ${ENABLE_BREAKPOINT}px) and (hover: hover) and (pointer: fine)`,
      )
      setEnabled(!reduce && mq2.matches)
    }
    check()
    const sizeMq = window.matchMedia(`(min-width: ${ENABLE_BREAKPOINT}px)`)
    sizeMq.addEventListener('change', check)
    return () => {
      mq.removeEventListener('change', sync)
      sizeMq.removeEventListener('change', check)
    }
  }, [reduce])

  return enabled
}

export function VolumetricCard({
  children,
  className = '',
  as: Tag = 'div',
  frontClassName = '',
}: {
  children: ReactNode
  className?: string
  as?: ElementType
  frontClassName?: string
}) {
  const enabled = useTiltEnabled()
  const wrapRef = useRef<HTMLDivElement>(null)
  const frontRef = useRef<HTMLElement>(null)
  const target = useRef({ x: 0, y: 0 })
  const current = useRef({ x: 0, y: 0 })
  const raf = useRef<number | undefined>(undefined)
  const hovering = useRef(false)

  useEffect(() => {
    if (!enabled) return
    const el = wrapRef.current
    const front = frontRef.current
    if (!el || !front) return

    const loop = () => {
      const damping = hovering.current ? DAMPING : RESET_DAMPING
      current.current.x += (target.current.x - current.current.x) * damping
      current.current.y += (target.current.y - current.current.y) * damping

      if (
        !hovering.current &&
        Math.abs(current.current.x) < 0.01 &&
        Math.abs(current.current.y) < 0.01
      ) {
        current.current.x = 0
        current.current.y = 0
        front.style.transform = 'rotateX(0deg) rotateY(0deg)'
        front.style.transition = 'transform 0.4s cubic-bezier(0.16,1,1,0.3)'
        raf.current = undefined
        return
      }

      front.style.transform = `rotateX(${current.current.x.toFixed(2)}deg) rotateY(${current.current.y.toFixed(2)}deg)`
      front.style.transition = hovering.current ? 'none' : 'transform 0.4s cubic-bezier(0.16,1,1,0.3)'
      raf.current = requestAnimationFrame(loop)
    }

    const startLoop = () => {
      if (raf.current === undefined) raf.current = requestAnimationFrame(loop)
    }

    const onMove = (e: PointerEvent) => {
      const r = el.getBoundingClientRect()
      const px = (e.clientX - r.left) / r.width
      const py = (e.clientY - r.top) / r.height
      target.current.x = (0.5 - py) * 2 * TILT_MAX_X
      target.current.y = (px - 0.5) * 2 * TILT_MAX_Y
      hovering.current = true
      front.style.setProperty('--spotlight-x', `${px * 100}%`)
      front.style.setProperty('--spotlight-y', `${py * 100}%`)
      front.style.setProperty('--spotlight-opacity', '1')
      startLoop()
    }

    const onLeave = () => {
      target.current.x = 0
      target.current.y = 0
      hovering.current = false
      front.style.setProperty('--spotlight-opacity', '0')
      startLoop()
    }

    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerleave', onLeave)
    return () => {
      el.removeEventListener('pointermove', onMove)
      el.removeEventListener('pointerleave', onLeave)
      if (raf.current !== undefined) cancelAnimationFrame(raf.current)
      raf.current = undefined
    }
  }, [enabled])

  return (
    <div
      ref={wrapRef}
      className={className}
      style={enabled ? { perspective: '1100px' } : undefined}
    >
      <Tag
        ref={frontRef as React.Ref<HTMLElement>}
        style={
          enabled
            ? ({
                transformStyle: 'preserve-3d',
                transform: 'rotateX(0deg) rotateY(0deg)',
                '--spotlight-x': '50%',
                '--spotlight-y': '50%',
                '--spotlight-opacity': '0',
              } as React.CSSProperties)
            : undefined
        }
        className={`relative volumetric-card-front ${frontClassName}`}
      >
        {enabled &&
          THICKNESS_LAYERS.slice(0, -1).map((z, i) => (
            <span
              key={i}
              aria-hidden
              className="absolute inset-0 rounded-[inherit] border border-foreground/10 bg-background-soft/60"
              style={{ transform: `translateZ(${z}px)` }}
            />
          ))}
        <div
          className="relative rounded-[inherit]"
          style={enabled ? { transform: 'translateZ(1.5px)' } : undefined}
        >
          <div className="translate-z-0">{children}</div>
        </div>
      </Tag>
    </div>
  )
}
