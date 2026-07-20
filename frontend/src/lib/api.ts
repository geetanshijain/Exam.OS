const BASE = "/api/v1"

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("access_token")
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init.headers ?? {}),
    },
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(body.detail ?? `HTTP ${res.status}`)
  }

  return res.json() as Promise<T>
}

export type UserRole = "setter" | "controller" | "printer" | "admin"

export interface AuthUser {
  id: number
  email: string
  full_name: string
  role: UserRole
  is_active: boolean
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface Paper {
  id: number
  title: string
  subject: string
  exam_date: string
  status: string
  created_by: number
  created_at: string
  description: string | null
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<TokenResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      }),
    me: () => request<AuthUser>("/auth/me"),
  },

  papers: {
    list: () => request<Paper[]>("/papers/", { headers: authHeaders() }),

    upload: (formData: FormData) =>
      fetch(`${BASE}/papers/upload`, {
        method: "POST",
        headers: authHeaders(),
        body: formData,
      }).then(async (res) => {
        if (!res.ok) {
          const body = await res.json().catch(() => ({ detail: res.statusText }))
          throw new Error(body.detail ?? `HTTP ${res.status}`)
        }
        return res.json() as Promise<Paper>
      }),

    hodReview: (paperId: number, action: "approve" | "reject") =>
      request<{ id: number; status: string }>(`/papers/${paperId}/hod-review?action=${action}`, {
        method: "PATCH",
      }),

    controllerReview: (paperId: number, action: "approve" | "reject") =>
      request<{ id: number; status: string }>(
        `/papers/${paperId}/controller-review?action=${action}`,
        { method: "PATCH" }
      ),

    download: async (paperId: number, title: string): Promise<void> => {
      const res = await fetch(`${BASE}/papers/${paperId}/download`, {
        headers: authHeaders(),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(body.detail ?? `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      const cd = res.headers.get("Content-Disposition") ?? ""
      const match = cd.match(/filename="([^"]+)"/)
      a.download = match?.[1] ?? `${title.replace(/\s+/g, "_")}_SECURE.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    },
  },
}
