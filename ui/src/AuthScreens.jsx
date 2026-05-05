import React, { useEffect, useState } from 'react'

const PASSWORD_MIN = 12

const styles = {
  page: {
    minHeight: '100vh',
    display: 'grid',
    placeItems: 'center',
    background: '#0B0B11',
    padding: 24,
    fontFamily: 'system-ui, -apple-system, sans-serif',
  },
  card: {
    width: '100%',
    maxWidth: 380,
    background: '#15161D',
    border: '1px solid #262833',
    borderRadius: 12,
    padding: 28,
    boxSizing: 'border-box',
  },
  brand: {
    color: '#7C5CFF',
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    marginBottom: 8,
  },
  title: { color: '#E6E7EE', fontSize: 20, fontWeight: 600, margin: 0, marginBottom: 4 },
  subtitle: { color: '#9598A8', fontSize: 13, marginBottom: 20 },
  field: { marginBottom: 14 },
  label: { display: 'block', color: '#E6E7EE', fontSize: 12, fontWeight: 500, marginBottom: 6 },
  input: {
    width: '100%',
    boxSizing: 'border-box',
    background: '#0B0B11',
    border: '1px solid #262833',
    borderRadius: 8,
    color: '#E6E7EE',
    fontSize: 14,
    padding: '10px 12px',
    outline: 'none',
  },
  hint: { color: '#9598A8', fontSize: 11, marginTop: 6 },
  button: {
    width: '100%',
    background: '#7C5CFF',
    color: '#fff',
    border: 'none',
    borderRadius: 8,
    padding: '11px 14px',
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  },
  buttonGhost: {
    width: '100%',
    background: 'transparent',
    color: '#E6E7EE',
    border: '1px solid #262833',
    borderRadius: 8,
    padding: '11px 14px',
    fontSize: 14,
    fontWeight: 500,
    cursor: 'pointer',
    marginTop: 10,
  },
  link: { background: 'none', border: 0, color: '#7C5CFF', cursor: 'pointer', padding: 0, fontSize: 13 },
  error: {
    background: 'rgba(248, 113, 113, 0.08)',
    border: '1px solid rgba(248, 113, 113, 0.3)',
    color: '#F87171',
    fontSize: 13,
    padding: '8px 10px',
    borderRadius: 6,
    marginBottom: 14,
  },
  success: {
    background: 'rgba(124, 92, 255, 0.08)',
    border: '1px solid rgba(124, 92, 255, 0.3)',
    color: '#B7A4FF',
    fontSize: 13,
    padding: '8px 10px',
    borderRadius: 6,
    marginBottom: 14,
  },
  footerRow: {
    marginTop: 16,
    paddingTop: 14,
    borderTop: '1px solid #262833',
    color: '#9598A8',
    fontSize: 13,
    display: 'flex',
    justifyContent: 'space-between',
    gap: 8,
  },
}

export function AuthLayout({ title, children }) {
  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.brand}>TDL Playbook</div>
        <h1 style={styles.title}>{title}</h1>
        {children}
      </div>
    </div>
  )
}

async function postJSON(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  })
  let data = null
  try { data = await r.json() } catch { /* non-JSON */ }
  return { ok: r.ok, status: r.status, data }
}

export function LoginScreen({ onAuthed, onSwitchToRegister, onForgotPassword }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    const { ok, data } = await postJSON('/api/auth/login', { email, password })
    setBusy(false)
    if (!ok) {
      setError(data?.error || 'Sign in failed.')
      return
    }
    onAuthed(data.user)
  }

  return (
    <form onSubmit={submit}>
      {error && <div style={styles.error}>{error}</div>}
      <div style={styles.field}>
        <label style={styles.label}>Email</label>
        <input
          type="email"
          autoComplete="email"
          autoFocus
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={styles.input}
        />
      </div>
      <div style={styles.field}>
        <label style={styles.label}>Password</label>
        <input
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
        />
      </div>
      <button type="submit" style={styles.button} disabled={busy}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
      <div style={styles.footerRow}>
        <button type="button" style={styles.link} onClick={onForgotPassword}>Forgot password?</button>
        <button type="button" style={styles.link} onClick={onSwitchToRegister}>Create account</button>
      </div>
    </form>
  )
}

export function RegisterScreen({ onAuthed, onSwitchToLogin }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < PASSWORD_MIN) {
      setError(`Password must be at least ${PASSWORD_MIN} characters.`)
      return
    }
    setBusy(true)
    const { ok, data } = await postJSON('/api/auth/register', { email, password })
    setBusy(false)
    if (!ok) {
      setError(data?.error || 'Could not create account.')
      return
    }
    onAuthed(data.user)
  }

  return (
    <form onSubmit={submit}>
      {error && <div style={styles.error}>{error}</div>}
      <div style={styles.field}>
        <label style={styles.label}>Email</label>
        <input
          type="email"
          autoComplete="email"
          autoFocus
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={styles.input}
        />
      </div>
      <div style={styles.field}>
        <label style={styles.label}>Password</label>
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
        />
        <div style={styles.hint}>At least {PASSWORD_MIN} characters.</div>
      </div>
      <div style={styles.field}>
        <label style={styles.label}>Confirm password</label>
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          style={styles.input}
        />
      </div>
      <button type="submit" style={styles.button} disabled={busy}>
        {busy ? 'Creating account…' : 'Create account'}
      </button>
      <div style={styles.footerRow}>
        <span>Already have an account?</span>
        <button type="button" style={styles.link} onClick={onSwitchToLogin}>Sign in</button>
      </div>
    </form>
  )
}

export function ForgotPasswordScreen({ onSwitchToLogin }) {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    await postJSON('/api/auth/forgot-password', { email })
    setBusy(false)
    setDone(true)
  }

  if (done) {
    return (
      <>
        <div style={styles.success}>
          If an account exists for that email, a reset link is on its way. Check your inbox.
        </div>
        <button type="button" style={styles.buttonGhost} onClick={onSwitchToLogin}>Back to sign in</button>
      </>
    )
  }

  return (
    <form onSubmit={submit}>
      <p style={styles.subtitle}>Enter the email on your account and we'll send a reset link.</p>
      <div style={styles.field}>
        <label style={styles.label}>Email</label>
        <input
          type="email"
          autoComplete="email"
          autoFocus
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={styles.input}
        />
      </div>
      <button type="submit" style={styles.button} disabled={busy}>
        {busy ? 'Sending…' : 'Send reset link'}
      </button>
      <div style={styles.footerRow}>
        <button type="button" style={styles.link} onClick={onSwitchToLogin}>Back to sign in</button>
      </div>
    </form>
  )
}

export function ResetPasswordScreen({ token, onDone }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setError(null)
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < PASSWORD_MIN) {
      setError(`Password must be at least ${PASSWORD_MIN} characters.`)
      return
    }
    setBusy(true)
    const { ok, data } = await postJSON('/api/auth/reset-password', { token, password })
    setBusy(false)
    if (!ok) {
      setError(data?.error || 'Could not reset password.')
      return
    }
    onDone(data.user)
  }

  if (!token) {
    return (
      <>
        <div style={styles.error}>This reset link is missing its token. Request a new one.</div>
        <button type="button" style={styles.buttonGhost} onClick={() => onDone(null)}>Back to sign in</button>
      </>
    )
  }

  return (
    <form onSubmit={submit}>
      {error && <div style={styles.error}>{error}</div>}
      <div style={styles.field}>
        <label style={styles.label}>New password</label>
        <input
          type="password"
          autoComplete="new-password"
          autoFocus
          required
          minLength={PASSWORD_MIN}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={styles.input}
        />
        <div style={styles.hint}>At least {PASSWORD_MIN} characters.</div>
      </div>
      <div style={styles.field}>
        <label style={styles.label}>Confirm new password</label>
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          style={styles.input}
        />
      </div>
      <button type="submit" style={styles.button} disabled={busy}>
        {busy ? 'Resetting…' : 'Reset password'}
      </button>
    </form>
  )
}

export function VerifyEmailScreen({ token, onDone }) {
  const [state, setState] = useState({ status: token ? 'verifying' : 'no-token', error: null })

  useEffect(() => {
    if (!token) return
    let cancelled = false
    ;(async () => {
      const { ok, data } = await postJSON('/api/auth/verify-email', { token })
      if (cancelled) return
      if (ok) setState({ status: 'verified', error: null })
      else setState({ status: 'failed', error: data?.error || 'Verification failed.' })
    })()
    return () => { cancelled = true }
  }, [token])

  if (state.status === 'verifying') {
    return <p style={{ color: '#9598A8' }}>Verifying your email…</p>
  }
  if (state.status === 'verified') {
    return (
      <>
        <div style={styles.success}>Email verified. You're all set.</div>
        <button type="button" style={styles.button} onClick={onDone}>Continue</button>
      </>
    )
  }
  return (
    <>
      <div style={styles.error}>{state.error || 'This verification link is invalid.'}</div>
      <button type="button" style={styles.buttonGhost} onClick={onDone}>Continue</button>
    </>
  )
}
