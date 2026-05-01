import React from 'react'
import ReactDOM from 'react-dom/client'
import { ClerkProvider } from '@clerk/react'
import AppShell from './AppShell.jsx'

if (!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY) {
  throw new Error(
    'Missing VITE_CLERK_PUBLISHABLE_KEY. Set it in ui/.env.local for local dev, ' +
    'or in Railway environment variables for production.'
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ClerkProvider afterSignOutUrl="/">
      <AppShell />
    </ClerkProvider>
  </React.StrictMode>
)
