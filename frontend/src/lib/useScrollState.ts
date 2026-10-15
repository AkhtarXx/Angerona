import { useContext } from 'react'
import { ScrollContext } from './ScrollContext'

export function useScrollState() {
  return useContext(ScrollContext)
}
