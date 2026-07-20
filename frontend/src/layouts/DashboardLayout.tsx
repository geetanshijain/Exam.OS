import { NavLink, useNavigate } from "react-router-dom"
import { LayoutDashboard, FileText, ShieldCheck, Printer, LogOut, ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { useAuth } from "@/context/AuthContext"

const NAV_ITEMS = [
  { to: "/setter",     icon: FileText,      label: "Paper Setter",  roles: ["setter"] },
  { to: "/controller", icon: ShieldCheck,   label: "Controller",    roles: ["controller", "admin"] },
  { to: "/printer",    icon: Printer,       label: "Print Station", roles: ["printer"] },
]

const ROLE_LABEL: Record<string, string> = {
  setter:     "Paper Setter",
  controller: "Controller",
  printer:    "Printer",
  admin:      "Administrator",
}

interface DashboardLayoutProps {
  children: React.ReactNode
  pageTitle: string
}

export function DashboardLayout({ children, pageTitle }: DashboardLayoutProps) {
  const navigate = useNavigate()
  const { user, logout } = useAuth()

  const handleLogout = () => {
    logout()
    navigate("/login", { replace: true })
  }

  const visibleNav = NAV_ITEMS.filter(
    (item) => !user || item.roles.includes(user.role)
  )

  return (
    <div className="grid-dashboard">
      {/* Topbar */}
      <header className="col-span-2 flex items-center justify-between px-5 border-b border-border bg-card/80 backdrop-blur-sm z-10">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded bg-primary flex items-center justify-center">
            <LayoutDashboard className="w-3.5 h-3.5 text-primary-foreground" />
          </div>
          <span className="font-semibold text-sm tracking-tight">ExamOS</span>
          <ChevronRight className="w-3 h-3 text-muted-foreground/50" />
          <span className="text-sm text-muted-foreground">{pageTitle}</span>
        </div>

        <div className="flex items-center gap-3">
          {user && (
            <div className="flex items-center gap-2 pr-3 border-r border-border">
              <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold text-primary">
                {user.full_name.charAt(0).toUpperCase()}
              </div>
              <div className="hidden sm:block">
                <p className="text-xs font-medium leading-none">{user.full_name}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{ROLE_LABEL[user.role]}</p>
              </div>
            </div>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="gap-1.5 text-muted-foreground h-7 px-2"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="text-xs">Sign out</span>
          </Button>
        </div>
      </header>

      {/* Sidebar */}
      <aside className="border-r border-border bg-sidebar flex flex-col pt-3 pb-6 px-2">
        <nav className="flex flex-col gap-0.5">
          {visibleNav.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to}>
              {({ isActive }) => (
                <span
                  className={cn(
                    "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/15 text-primary"
                      : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-foreground"
                  )}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  {label}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto px-2">
          <div className="rounded-md border border-border bg-muted/20 p-3">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Phase</p>
            <p className="text-sm font-bold text-foreground mt-0.5">2</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">Core workflows active</p>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="overflow-auto bg-background">{children}</main>
    </div>
  )
}
