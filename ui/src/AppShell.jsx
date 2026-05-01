import React, { useEffect, useState } from 'react'
import { Show, SignIn, useUser } from '@clerk/react'
import App from './App.jsx'
import OrgSetup from './OrgSetup.jsx'

export const orgProfileKey = (userId) => `tdl_org_${userId}`

export default function AppShell() {
  return (
    <>
      <Show when="signed-out">
        <CenteredAuth>
          <SignIn routing="hash" />
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
  const [profile, setProfile] = useState(null)
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    if (!isLoaded || !user) return
    const raw = localStorage.getItem(orgProfileKey(user.id))
    setProfile(raw ? JSON.parse(raw) : null)
    setHydrated(true)
  }, [isLoaded, user?.id])

  if (!isLoaded || !hydrated) return <CenteredMessage>Loading…</CenteredMessage>

  if (!profile) {
    return (
      <OrgSetup
        userId={user.id}
        onComplete={(p) => {
          localStorage.setItem(orgProfileKey(user.id), JSON.stringify(p))
          setProfile(p)
        }}
      />
    )
  }

  return <App orgProfile={profile} />
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
