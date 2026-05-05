import React, { useEffect, useState } from 'react'
import App from './App.jsx'
import OrgSetup from './OrgSetup.jsx'
import {
  AuthLayout,
  LoginScreen,
  RegisterScreen,
  ForgotPasswordScreen,
  ResetPasswordScreen,
  VerifyEmailScreen,
} from './AuthScreens.jsx'

export const orgProfileKey = (userId) => `tdl_org_${userId}`

// ── Tiny hash router for unauthenticated screens ───────────────────────────
function parseHashRoute() {
  const raw = window.location.hash || ''
  const stripped = raw.startsWith('#') ? raw.slice(1) : raw
  const [path, query] = stripped.split('?')
  const params = new URLSearchParams(query || '')
  return { path: path || '/login', params }
}

function useHashRoute() {
  const [route, setRoute] = useState(parseHashRoute)
  useEffect(() => {
    const onChange = () => setRoute(parseHashRoute())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}

function navigate(path) {
  window.location.hash = path
}

// ── Top-level shell ────────────────────────────────────────────────────────
export default function AppShell() {
  const [authState, setAuthState] = useState({ status: 'loading', user: null })
  const route = useHashRoute()

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const r = await fetch('/api/auth/me', { credentials: 'include' })
        if (cancelled) return
        if (r.ok) {
          const data = await r.json()
          setAuthState({ status: 'authed', user: data.user })
        } else {
          setAuthState({ status: 'anon', user: null })
        }
      } catch {
        if (!cancelled) setAuthState({ status: 'anon', user: null })
      }
    })()
    return () => { cancelled = true }
  }, [])

  if (authState.status === 'loading') return <CenteredMessage>Loading…</CenteredMessage>

  // Token-based screens (verify, reset) are accessible whether signed in or not
  // — the link arrives via email and needs to work in either state.
  if (route.path === '/verify-email') {
    return (
      <AuthLayout title="Verify email">
        <VerifyEmailScreen
          token={route.params.get('token') || ''}
          onDone={() => navigate(authState.status === 'authed' ? '/' : '/login')}
        />
      </AuthLayout>
    )
  }
  if (route.path === '/reset-password') {
    return (
      <AuthLayout title="Reset password">
        <ResetPasswordScreen
          token={route.params.get('token') || ''}
          onDone={(user) => {
            setAuthState({ status: 'authed', user })
            navigate('/')
          }}
        />
      </AuthLayout>
    )
  }

  if (authState.status !== 'authed') {
    if (route.path === '/register') {
      return (
        <AuthLayout title="Create your account">
          <RegisterScreen
            onAuthed={(user) => setAuthState({ status: 'authed', user })}
            onSwitchToLogin={() => navigate('/login')}
          />
        </AuthLayout>
      )
    }
    if (route.path === '/forgot-password') {
      return (
        <AuthLayout title="Forgot password">
          <ForgotPasswordScreen onSwitchToLogin={() => navigate('/login')} />
        </AuthLayout>
      )
    }
    return (
      <AuthLayout title="Sign in to TDL Playbook">
        <LoginScreen
          onAuthed={(user) => setAuthState({ status: 'authed', user })}
          onSwitchToRegister={() => navigate('/register')}
          onForgotPassword={() => navigate('/forgot-password')}
        />
      </AuthLayout>
    )
  }

  return <AuthedRoot user={authState.user} onSignOut={() => setAuthState({ status: 'anon', user: null })} />
}

// ── Authed: load org profile, then App ─────────────────────────────────────
function AuthedRoot({ user, onSignOut }) {
  const [profile, setProfile] = useState(null)
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const lsKey = orgProfileKey(user.id)
      const readLocal = () => {
        const raw = localStorage.getItem(lsKey)
        return raw ? JSON.parse(raw) : null
      }

      try {
        const r = await fetch('/api/org-profile', { credentials: 'include' })
        if (r.ok) {
          const data = await r.json()
          if (cancelled) return
          if (data && data.org_name) {
            setProfile(data)
            setHydrated(true)
            return
          }
          const local = readLocal()
          if (local && local.org_name) {
            try {
              const put = await fetch('/api/org-profile', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(local),
              })
              if (put.ok) {
                const migrated = await put.json()
                if (cancelled) return
                localStorage.removeItem(lsKey)
                setProfile(migrated)
                setHydrated(true)
                return
              }
            } catch { /* fall through */ }
          }
          if (cancelled) return
          setProfile(null)
          setHydrated(true)
          return
        }
      } catch { /* fall through to localStorage */ }

      if (cancelled) return
      setProfile(readLocal())
      setHydrated(true)
    })()

    return () => { cancelled = true }
  }, [user.id])

  if (!hydrated) return <CenteredMessage>Loading…</CenteredMessage>

  const persistProfile = async (p) => {
    localStorage.setItem(orgProfileKey(user.id), JSON.stringify(p))

    let r
    try {
      r = await fetch('/api/org-profile', {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(p),
      })
    } catch (e) {
      console.warn('[org-profile] PUT network error:', e)
      throw new Error('Could not reach the server. Try again.')
    }

    if (!r.ok) {
      let detail = ''
      try { detail = (await r.json()).error || '' } catch { /* non-JSON */ }
      console.warn('[org-profile] PUT failed:', r.status, detail)
      throw new Error(`Save failed (HTTP ${r.status})${detail ? `: ${detail}` : ''}`)
    }

    const saved = await r.json().catch(() => p)
    setProfile(saved)
    localStorage.removeItem(orgProfileKey(user.id))
    return saved
  }

  if (!profile) {
    return <OrgSetup userId={user.id} onComplete={persistProfile} />
  }

  return <App user={user} orgProfile={profile} onProfileChange={persistProfile} onSignOut={onSignOut} />
}

function CenteredMessage({ children }) {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'grid',
      placeItems: 'center',
      background: '#0B0B11',
      color: '#E6E7EE',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize: 14,
    }}>
      {children}
    </div>
  )
}
