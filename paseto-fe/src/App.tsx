import { useMemo, useState } from 'react'

import { Badge } from './components/ui/badge'
import { Button } from './components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from './components/ui/card'
import { Input } from './components/ui/input'
import { useAuthStore } from './store/authStore'

type ApiResult = {
  ok: boolean
  status: number
  message: string
  payload?: unknown
}

type TokenPayload = {
  access_token: string
  refresh_token: string
  token_type?: string
  expires_in?: number
}

function parseJson(text: string) {
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function formatToken(token: string | null) {
  if (!token) return '—'
  if (token.length <= 28) return token
  return `${token.slice(0, 16)}…${token.slice(-10)}`
}

function createEvent(action: string, result: ApiResult) {
  return {
    id: crypto.randomUUID(),
    ts: new Date().toLocaleTimeString(),
    action,
    status: result.ok ? result.status : 'error',
    message: result.message,
    payload: result.payload,
  }
}

function getTokens(payload: unknown): TokenPayload | null {
  if (!payload || typeof payload !== 'object') return null
  const data = payload as Partial<TokenPayload>
  if (!data.access_token || !data.refresh_token) return null
  return data as TokenPayload
}

async function request(url: string, options: RequestInit = {}): Promise<ApiResult> {
  try {
    const res = await fetch(url, options)
    const text = await res.text()
    const payload = parseJson(text)
    return {
      ok: res.ok,
      status: res.status,
      message: res.ok ? 'ok' : 'request failed',
      payload,
    }
  } catch (error) {
    return {
      ok: false,
      status: 0,
      message: error instanceof Error ? error.message : 'network error',
      payload: null,
    }
  }
}

function App() {
  const {
    accessToken,
    refreshToken,
    apiBaseUrl,
    lastAction,
    events,
    setTokens,
    clearTokens,
    pushEvent,
    setLastAction,
  } = useAuthStore()

  const [response, setResponse] = useState<ApiResult | null>(null)
  const [loadingAction, setLoadingAction] = useState<string | null>(null)

  const baseUrl = useMemo(() => apiBaseUrl.replace(/\/$/, ''), [apiBaseUrl])

  const accessPreview = useMemo(() => formatToken(accessToken), [accessToken])
  const refreshPreview = useMemo(
    () => formatToken(refreshToken),
    [refreshToken]
  )

  const handleCopy = async (value: string | null) => {
    if (!value) return
    await navigator.clipboard.writeText(value)
  }

  const handleLogin = async () => {
    setLastAction('Login')
    setLoadingAction('login')
    const result = await request(`${baseUrl}/login`, { method: 'POST' })
    const tokens = getTokens(result.payload)
    if (result.ok && tokens) {
      setTokens(tokens.access_token, tokens.refresh_token)
      result.message = 'tokens issued'
    }
    pushEvent(createEvent('Login', result))
    setResponse(result)
    setLoadingAction(null)
  }

  const handleRefresh = async (
    actionLabel = 'Refresh',
    manageLoading = false
  ) => {
    if (manageLoading) {
      setLastAction(actionLabel)
      setLoadingAction('refresh')
    }
    if (!refreshToken) {
      const result: ApiResult = {
        ok: false,
        status: 0,
        message: 'missing refresh token',
      }
      pushEvent(createEvent(actionLabel, result))
      setResponse(result)
      if (manageLoading) setLoadingAction(null)
      return result
    }

    const result = await request(`${baseUrl}/refresh`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    })

    const tokens = getTokens(result.payload)
    if (result.ok && tokens) {
      setTokens(tokens.access_token, tokens.refresh_token)
      result.message = 'tokens rotated'
    } else if (!result.ok) {
      clearTokens()
    }

    pushEvent(createEvent(actionLabel, result))
    setResponse(result)
    if (manageLoading) setLoadingAction(null)
    return result
  }

  const handleProtected = async () => {
    setLastAction('Protected')
    setLoadingAction('protected')

    if (!accessToken) {
      const result: ApiResult = {
        ok: false,
        status: 0,
        message: 'missing access token',
      }
      pushEvent(createEvent('Protected', result))
      setResponse(result)
      setLoadingAction(null)
      return
    }

    let result = await request(`${baseUrl}/protected`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })

    if (result.status === 401 && refreshToken) {
      const refreshResult = await handleRefresh('Refresh (auto)')
      const tokens = getTokens(refreshResult.payload)
      if (refreshResult.ok && tokens) {
        result = await request(`${baseUrl}/protected`, {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
          },
        })
      }
    }

    pushEvent(createEvent('Protected', result))
    setResponse(result)
    setLoadingAction(null)
  }

  const handleLogout = async () => {
    setLastAction('Logout')
    setLoadingAction('logout')

    if (!refreshToken) {
      const result: ApiResult = {
        ok: false,
        status: 0,
        message: 'missing refresh token',
      }
      pushEvent(createEvent('Logout', result))
      setResponse(result)
      setLoadingAction(null)
      return
    }

    const result = await request(`${baseUrl}/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    })

    if (result.ok) {
      clearTokens()
      result.message = 'session revoked'
    }

    pushEvent(createEvent('Logout', result))
    setResponse(result)
    setLoadingAction(null)
  }

  return (
    <div className="min-h-screen px-6 py-10">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
        <header className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <Badge variant="accent">PASETO v4</Badge>
            <span className="text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
              Redis Rotation Flow
            </span>
          </div>
          <h1 className="text-4xl font-semibold text-balance">
            Token Control Room
          </h1>
          <p className="max-w-2xl text-sm text-muted-foreground">
            Demo UI for the Go/Fiber backend. Tokens stay in memory only. The
            Protected call will auto-refresh once on 401.
          </p>
        </header>

        <section className="grid gap-4 md:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <CardHeader>
              <CardTitle>Session Actions</CardTitle>
              <CardDescription>
                Issue, rotate, and revoke access using the demo endpoints.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <Button
                  onClick={handleLogin}
                  disabled={loadingAction === 'login'}
                >
                  Login
                </Button>
                <Button
                  variant="soft"
                  onClick={handleProtected}
                  disabled={loadingAction === 'protected'}
                >
                  Protected
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleRefresh('Refresh', true)}
                  disabled={loadingAction === 'refresh'}
                >
                  Refresh
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleLogout}
                  disabled={loadingAction === 'logout'}
                >
                  Logout
                </Button>
              </div>

              <div className="grid gap-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>Access Token</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleCopy(accessToken)}
                      disabled={!accessToken}
                    >
                      Copy
                    </Button>
                  </div>
                  <Input readOnly value={accessPreview} />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>Refresh Token</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleCopy(refreshToken)}
                      disabled={!refreshToken}
                    >
                      Copy
                    </Button>
                  </div>
                  <Input readOnly value={refreshPreview} />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Session Status</CardTitle>
              <CardDescription>Live snapshot of auth state.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid gap-2 text-sm">
                <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                  <span className="text-muted-foreground">Access</span>
                  <Badge variant={accessToken ? 'default' : 'outline'}>
                    {accessToken ? 'Loaded' : 'Empty'}
                  </Badge>
                </div>
                <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                  <span className="text-muted-foreground">Refresh</span>
                  <Badge variant={refreshToken ? 'default' : 'outline'}>
                    {refreshToken ? 'Loaded' : 'Empty'}
                  </Badge>
                </div>
                <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                  <span className="text-muted-foreground">Last Action</span>
                  <span className="font-medium">
                    {lastAction ?? '—'}
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                  <span className="text-muted-foreground">API Base</span>
                  <span className="font-medium">{baseUrl}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
          <Card>
            <CardHeader>
              <CardTitle>Response</CardTitle>
              <CardDescription>
                Latest response payload and status from the API.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-lg border border-input bg-muted/40 p-4 text-sm">
                {response ? (
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <Badge variant={response.ok ? 'default' : 'outline'}>
                        {response.ok ? 'OK' : 'Error'}
                      </Badge>
                      <span>Status: {response.status}</span>
                      <span className="text-muted-foreground">
                        {response.message}
                      </span>
                    </div>
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-background p-3 text-xs text-foreground">
                      {JSON.stringify(response.payload ?? null, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <p className="text-muted-foreground">
                    No requests yet. Start with Login.
                  </p>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Event Log</CardTitle>
              <CardDescription>Most recent activity first.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex max-h-64 flex-col gap-3 overflow-auto">
                {events.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Actions will show up here.
                  </p>
                ) : (
                  events.map((event) => (
                    <div
                      key={event.id}
                      className="rounded-md border border-input bg-background/80 p-3 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold">{event.action}</span>
                        <span className="text-muted-foreground">
                          {event.ts}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <Badge
                          variant={event.status === 'error' ? 'outline' : 'muted'}
                        >
                          {event.status}
                        </Badge>
                        <span className="text-muted-foreground">
                          {event.message}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  )
}

export default App
