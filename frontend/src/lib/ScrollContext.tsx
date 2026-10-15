import { createContext } from 'react'

export interface ScrollState {
  y: number
  viewportProgress: number
}

export const ScrollContext = createContext<ScrollState>({ y: 0, viewportProgress: 0 })
