import { AmbientBackground } from './components/AmbientBackground'
import { ScrollProgress } from './components/ScrollProgress'
import { NavBar } from './components/NavBar'
import Hero from './components/sections/Hero'
import { CoordinateFooter } from './components/CoordinateFooter'

import Proof from './components/sections/Proof'
import Problem from './components/sections/Problem'
import HowItWorks from './components/sections/HowItWorks'
import Engine from './components/sections/Engine'
import SampleReport from './components/sections/SampleReport'
import UseCases from './components/sections/UseCases'
import Security from './components/sections/Security'
import Team from './components/sections/Team'
import FAQ from './components/sections/FAQ'
import CTA from './components/sections/CTA'

/** Hairline gradient divider between sections. */
function Divider() {
  return <div className="section-divider" aria-hidden />
}

export default function App() {
  return (
    <>
      <AmbientBackground />
      <ScrollProgress />
      <NavBar />
      <main className="relative z-10 overflow-x-clip">
        <Hero />
          <Proof />
        <Divider />
          <Problem />
        <Divider />
          <HowItWorks />
        <Divider />
          <Engine />
        <Divider />
          <SampleReport />
        <Divider />
          <UseCases />
        <Divider />
          <Security />
        <Divider />
          <Team />
        <Divider />
          <FAQ />
        <Divider />
          <CTA />
      </main>
      <CoordinateFooter />
    </>
  )
}
