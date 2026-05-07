import React from 'react'
import ReactDOM from 'react-dom/client'
import AppShell from './AppShell.jsx'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }
  static getDerivedStateFromError(error) {
    return { error }
  }
  componentDidCatch(error, info) {
    console.error('[tdl] React error boundary caught:', error, info)
  }
  render() {
    if (!this.state.error) return this.props.children
    const detail = (this.state.error && (this.state.error.stack || this.state.error.message)) || String(this.state.error)
    return (
      <div style={{
        minHeight: '100vh',
        background: '#0B0B11',
        color: '#E6E7EE',
        fontFamily: 'system-ui, -apple-system, sans-serif',
        padding: 24,
      }}>
        <div style={{ maxWidth: 560, margin: '64px auto' }}>
          <h1 style={{ color: '#F87171', fontSize: 18, marginBottom: 8 }}>Something went wrong.</h1>
          <p style={{ color: '#9598A8', fontSize: 14, marginBottom: 16 }}>
            Try reloading the page. If the problem keeps happening, contact support.
          </p>
          <button
            onClick={() => window.location.reload()}
            style={{
              background: '#7C5CFF', color: '#fff', border: 'none',
              borderRadius: 8, padding: '10px 14px', fontSize: 14, fontWeight: 600, cursor: 'pointer',
            }}
          >
            Reload
          </button>
          <details style={{ marginTop: 24, color: '#6B6E80', fontSize: 12 }}>
            <summary style={{ cursor: 'pointer' }}>Technical details</summary>
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: 8 }}>{detail}</pre>
          </details>
        </div>
      </div>
    )
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <AppShell />
    </ErrorBoundary>
  </React.StrictMode>
)

// Tell the boot-time global error handler that React has mounted successfully,
// so any further window-level errors (typically from browser extensions / password
// managers) don't blow away the rendered UI.
queueMicrotask(() => {
  if (typeof window.__markAppBooted === 'function') window.__markAppBooted()
})
