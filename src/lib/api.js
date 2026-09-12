const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')
const TOKEN_KEY = 'playpal_access_token'

const token = () => {
  try { return localStorage.getItem(TOKEN_KEY) } catch { return null }
}

const errorMessage = async (response) => {
  let message = `Request failed (${response.status})`
  try {
    const body = await response.json()
    message = body.detail || body.message || message
  } catch {
    const text = await response.text().catch(() => '')
    if (text) message = text
  }
  return message
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (options.body !== undefined) headers.set('Content-Type', 'application/json')
  const accessToken = token()
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (!response.ok) {
    const error = new Error(await errorMessage(response))
    error.status = response.status
    if (response.status === 401) api.clearToken()
    throw error
  }
  if (response.status === 204) return null
  return response.json()
}

export const api = {
  baseUrl: API_BASE,
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  patch: (path, body) => request(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) }),
  del: (path) => request(path, { method: 'DELETE' }),
  token,
  setToken(value) {
    if (value) localStorage.setItem(TOKEN_KEY, value)
    else this.clearToken()
  },
  clearToken() { localStorage.removeItem(TOKEN_KEY) },
  auth: {
    signup: (body) => request('/auth/signup', { method: 'POST', body: JSON.stringify(body) }),
    login: (body) => request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
    me: () => request('/auth/me'),
  },
  signup: (body) => request('/auth/signup', { method: 'POST', body: JSON.stringify(body) }),
  login: (body) => request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  me: () => request('/auth/me'),
  sports: () => request('/sports'),
  venues: (city) => request(`/venues${city ? `?city=${encodeURIComponent(city)}` : ''}`),
  players(filters = {}) {
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value && value !== 'All')).toString()
    return request(`/players${query ? `?${query}` : ''}`)
  },
  playerFilters: (sport) => request(`/filters/players${sport ? `?sport=${encodeURIComponent(sport)}` : ''}`),
  sessions(filters = {}) {
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value && value !== 'All')).toString()
    return request(`/sessions${query ? `?${query}` : ''}`)
  },
  createSession: (body) => request('/sessions', { method: 'POST', body: JSON.stringify(body) }),
  createTournament: (body) => request('/tournaments', { method: 'POST', body: JSON.stringify(body) }),
  deleteTournament: (id) => request(`/tournaments/${id}`, { method: 'DELETE' }),
  deleteSession: (id) => request(`/sessions/${id}`, { method: 'DELETE' }),
  inviteToSession: (id, userIds) => request(`/sessions/${id}/invite`, { method: 'POST', body: JSON.stringify({ user_ids: userIds }) }),
  joinSession: (id) => request(`/sessions/${id}/join`, { method: 'POST' }),
  leaveSession: (id) => request(`/sessions/${id}/join`, { method: 'DELETE' }),
  tournaments: (sport) => request(`/tournaments${sport ? `?sport=${encodeURIComponent(sport)}` : ''}`),
  tournament: (id) => request(`/tournaments/${id}`),
  registerTournament: (id, teamName) => request(`/tournaments/${id}/register`, { method: 'POST', body: JSON.stringify(teamName ? { team_name: teamName } : {}) }),
  unregisterTournament: (id) => request(`/tournaments/${id}/register`, { method: 'DELETE' }),
  tournamentRegistrations: (id) => request(`/tournaments/${id}/registrations`),
  notifications: (unread = false) => request(`/notifications${unread ? '?unread=true' : ''}`),
  markNotificationRead: (id) => request(`/notifications/${id}/read`, { method: 'PATCH' }),
  markAllNotificationsRead: () => request('/notifications/read-all', { method: 'POST' }),
  deleteNotification: (id) => request(`/notifications/${id}`, { method: 'DELETE' }),
  deleteAllNotifications: () => request('/notifications', { method: 'DELETE' }),
  updateProfile: (body) => request('/auth/me', { method: 'PATCH', body: JSON.stringify(body) }),
  deleteAccount: () => request('/auth/me', { method: 'DELETE' }),
  connections: (status) => request(`/connections${status ? `?status=${encodeURIComponent(status)}` : ''}`),
  createConnection: (userId) => request('/connections', { method: 'POST', body: JSON.stringify({ user_id: userId }) }),
  updateConnection: (id, status) => request(`/connections/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  deleteConnectionByUser: async (userId) => {
    return request(`/connections/by-user/${encodeURIComponent(userId)}`, { method: 'DELETE' })
  },
  deleteConnection: async (id) => {
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 10000)
    try {
      return await request(`/connections/${id}`, { method: 'DELETE', signal: controller.signal })
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Removing the friend timed out. Please try again.')
      throw error
    } finally {
      window.clearTimeout(timeout)
    }
  },
  connectEvents(onEvent, onError) {
    let closed = false
    let reader = null
    let retryTimer = null

    const connect = async () => {
      if (closed) return
      const accessToken = token()
      if (!accessToken) return

      try {
        const response = await fetch(`${API_BASE}/events`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        })
        if (!response.ok || !response.body) {
          throw new Error(`Event stream failed (${response.status})`)
        }

        reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        while (!closed) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })

          let boundary = buffer.indexOf('\n\n')
          while (boundary >= 0) {
            const block = buffer.slice(0, boundary)
            buffer = buffer.slice(boundary + 2)
            const data = block
              .split('\n')
              .filter(line => line.startsWith('data:'))
              .map(line => line.slice(5).trim())
              .join('\n')
            if (data) {
              try { onEvent(JSON.parse(data)) } catch {}
            }
            boundary = buffer.indexOf('\n\n')
          }
        }
      } catch (error) {
        if (!closed) onError?.(error)
      } finally {
        reader = null
        if (!closed) retryTimer = window.setTimeout(connect, 1500)
      }
    }

    connect()

    return () => {
      closed = true
      if (retryTimer) window.clearTimeout(retryTimer)
      reader?.cancel().catch(() => {})
    }
  },
}
