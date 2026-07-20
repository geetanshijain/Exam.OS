import { createContext, useCallback, useContext, useEffect, useState } from "react"
import { api, type AuthUser } from "@/lib/api"

interface AuthState {
  user: AuthUser | null
  token: string | null
  loading: boolean
  login: (email: string, password: string) => Promise<AuthUser>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem("access_token"))
  const [loading, setLoading] = useState(!!localStorage.getItem("access_token"))

  useEffect(() => {
    if (!token) {
      setLoading(false)
      return
    }
    api.auth
      .me()
      .then(setUser)
      .catch(() => {
        localStorage.removeItem("access_token")
        setToken(null)
      })
      .finally(() => setLoading(false))
  }, [token])

  const login = useCallback(async (email: string, password: string): Promise<AuthUser> => {
    const { access_token } = await api.auth.login(email, password)
    localStorage.setItem("access_token", access_token)
    setToken(access_token)
    const me = await api.auth.me()
    setUser(me)
    return me
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem("access_token")
    setToken(null)
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>")
  return ctx
}
