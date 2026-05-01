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
