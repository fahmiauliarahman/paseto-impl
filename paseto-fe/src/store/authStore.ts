import { create } from 'zustand'

export type EventItem = {
  id: string
  ts: string
  action: string
  status: number | 'error'
  message: string
  payload?: unknown
}

type AuthState = {
  accessToken: string | null
  refreshToken: string | null
  apiBaseUrl: string
  lastAction: string | null
  events: EventItem[]
  setTokens: (accessToken: string, refreshToken: string) => void
  clearTokens: () => void
  pushEvent: (event: EventItem) => void
  setLastAction: (action: string) => void
}

const defaultApiBaseUrl =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001'

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  refreshToken: null,
  apiBaseUrl: defaultApiBaseUrl,
  lastAction: null,
  events: [],
  setTokens: (accessToken, refreshToken) =>
    set({ accessToken, refreshToken }),
  clearTokens: () => set({ accessToken: null, refreshToken: null }),
  pushEvent: (event) =>
    set((state) => ({
      events: [event, ...state.events].slice(0, 20),
    })),
  setLastAction: (action) => set({ lastAction: action }),
}))
