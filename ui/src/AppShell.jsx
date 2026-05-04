import React, { useEffect, useState } from 'react'
import { Show, SignIn, useAuth, useUser } from '@clerk/react'
import App from './App.jsx'
import OrgSetup from './OrgSetup.jsx'

export const orgProfileKey = (userId) => `tdl_org_${userId}`

export default function AppShell() {
  return (
    <>
      <Show when="signed-out">
        <CenteredAuth>
          <SignIn routing="hash" appearance={signInAppearance} />
        </CenteredAuth>
      </Show>
      <Show when="signed-in">
        <AuthedRoot />
      </Show>
    </>
  )
}

function AuthedRoot() {
  const { user, isLoaded } = useUser()
  const { getToken } = useAuth()
  const [profile, setProfile] = useState(null)
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    if (!isLoaded || !user) return
    let cancelled = false

    ;(async () => {
      const lsKey = orgProfileKey(user.id)
      const readLocal = () => {
        const raw = localStorage.getItem(lsKey)
        return raw ? JSON.parse(raw) : null
      }

      let token = null
      try { token = await getToken() } catch { /* offline / signed-out race */ }
      const headers = token ? { Authorization: `Bearer ${token}` } : {}

      try {
        const r = await fetch('/api/org-profile', { headers })
        if (r.ok) {
          const data = await r.json()
          if (cancelled) return
          if (data && data.org_name) {
            setProfile(data)
            setHydrated(true)
            return
          }
          // No row yet — migrate localStorage if present.
          const local = readLocal()
          if (local && local.org_name) {
            try {
              const put = await fetch('/api/org-profile', {
                method: 'PUT',
                headers: { ...headers, 'Content-Type': 'application/json' },
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
  }, [isLoaded, user?.id, getToken])

  if (!isLoaded || !hydrated) return <CenteredMessage>Loading…</CenteredMessage>

  const persistProfile = async (p) => {
    // Stash locally first — if the network fails mid-save, a refresh recovers.
    localStorage.setItem(orgProfileKey(user.id), JSON.stringify(p))

    let token = null
    try { token = await getToken() } catch { /* signed-out race */ }

    let r
    try {
      r = await fetch('/api/org-profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
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
    // Postgres has it now → drop the localStorage copy.
    localStorage.removeItem(orgProfileKey(user.id))
    return saved
  }

  if (!profile) {
    return <OrgSetup userId={user.id} onComplete={persistProfile} />
  }

  return <App orgProfile={profile} onProfileChange={persistProfile} />
}

const signInAppearance = {
  variables: {
    colorBackground: '#15161D',
    colorInputBackground: '#0B0B11',
    colorText: '#E6E7EE',
    colorTextSecondary: '#9598A8',
    colorInputText: '#E6E7EE',
    colorPrimary: '#7C5CFF',
    colorNeutral: '#E6E7EE',
    colorDanger: '#F87171',
    borderRadius: '8px',
    fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  elements: {
    card: { backgroundColor: '#15161D', border: '1px solid #262833', boxShadow: 'none' },
    rootBox: { background: 'transparent' },
    headerTitle: { color: '#E6E7EE' },
    headerSubtitle: { color: '#9598A8' },
    socialButtonsBlockButton: {
      backgroundColor: '#0B0B11',
      border: '1px solid #262833',
      color: '#E6E7EE',
    },
    socialButtonsBlockButtonText: { color: '#E6E7EE' },
    dividerLine: { backgroundColor: '#262833' },
    dividerText: { color: '#9598A8' },
    formFieldLabel: { color: '#E6E7EE' },
    formFieldInput: {
      backgroundColor: '#0B0B11',
      border: '1px solid #262833',
      color: '#E6E7EE',
    },
    footer: { backgroundColor: '#15161D', borderTop: '1px solid #262833' },
    footerAction: { backgroundColor: 'transparent' },
    footerActionText: { color: '#9598A8' },
    footerActionLink: { color: '#7C5CFF' },
    formButtonPrimary: { backgroundColor: '#7C5CFF', color: '#fff' },
  },
}

function CenteredAuth({ children }) {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'grid',
      placeItems: 'center',
      background: '#0B0B11',
      padding: 24,
    }}>
      {children}
    </div>
  )
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
