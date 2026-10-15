import { cn } from '../../lib/cn'

export function Section({
  children,
  className,
  ...rest
}: { children: React.ReactNode; className?: string } & React.HTMLAttributes<HTMLElement>) {
  return (
    <section
      className={cn(
        'relative mx-auto w-full max-w-[1200px] px-6 py-24 sm:py-32',
        className,
      )}
      {...rest}
    >
      {children}
    </section>
  )
}
