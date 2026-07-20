import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"
import { useAuth } from "@/context/AuthContext"
import { LoginPage } from "@/pages/LoginPage"
import { SetterDashboard } from "@/pages/SetterDashboard"
import { ControllerDashboard } from "@/pages/ControllerDashboard"
import { PrinterDashboard } from "@/pages/PrinterDashboard"
import { type UserRole } from "@/lib/api"

const ROLE_HOME: Record<UserRole, string> = {
  setter: "/setter",
  controller: "/controller",
  printer: "/printer",
  admin: "/controller",
}

function RequireAuth({ children, allow }: { children: React.ReactNode; allow?: UserRole[] }) {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="min-h-dvh bg-background flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!user) return <Navigate to="/login" replace />

  if (allow && !allow.includes(user.role)) {
    return <Navigate to={ROLE_HOME[user.role]} replace />
  }

  return <>{children}</>
}

export function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/setter"
          element={
            <RequireAuth allow={["setter"]}>
              <SetterDashboard />
            </RequireAuth>
          }
        />
        <Route
          path="/controller"
          element={
            <RequireAuth allow={["controller", "admin"]}>
              <ControllerDashboard />
            </RequireAuth>
          }
        />
        <Route
          path="/printer"
          element={
            <RequireAuth allow={["printer"]}>
              <PrinterDashboard />
            </RequireAuth>
          }
        />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
