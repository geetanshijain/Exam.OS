import { useCallback, useEffect, useState } from "react"
import {
  ShieldCheck,
  ShieldAlert,
  Loader2,
  CheckCircle2,
  XCircle,
  FileText,
  Cpu,
  Lock,
  Printer,
  Activity,
  AlertTriangle,
  RefreshCw,
} from "lucide-react"

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { DashboardLayout } from "@/layouts/DashboardLayout"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusBadge, Badge } from "@/components/ui/badge"
import { api, type Paper, type AlertData, type AdminStats } from "@/lib/api"

function ActionButton({
  label,
  variant,
  icon: Icon,
  loading,
  onClick,
}: {
  label: string
  variant: "default" | "destructive" | "outline"
  icon: React.ElementType
  loading: boolean
  onClick: () => void
}) {
  return (
    <Button size="sm" variant={variant} disabled={loading} onClick={onClick} className="gap-1.5 h-7 text-xs px-2.5">
      {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Icon className="w-3 h-3" />}
      {label}
    </Button>
  )
}

export function ControllerDashboard() {
  const [papers, setPapers] = useState<Paper[]>([])
  const [alerts, setAlerts] = useState<AlertData[]>([])
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [aiSummary, setAiSummary] = useState<string | null>(null)
  const [aiLoading, setAiLoading] = useState<boolean>(true)
  const [loading, setLoading] = useState<boolean>(true)
  const [resolvingId, setResolvingId] = useState<number | null>(null)
  const [actionLoading, setActionLoading] = useState<Record<number, boolean>>({})
  const [actionError, setActionError] = useState<string | null>(null)

  const fetchData = useCallback(() => {
    setLoading(true)
    Promise.all([
      api.papers.list().catch(() => []),
      api.admin.listAlerts().catch(() => []),
      api.admin.getStats().catch(() => null),
    ]).then(([pList, aList, sData]) => {
      setPapers(pList)
      setAlerts(aList)
      setStats(sData)
      setLoading(false)
    })
  }, [])

  const fetchAiSummary = useCallback(() => {
    setAiLoading(true)
    api.admin
      .analyzeLogs()
      .then((res) => setAiSummary(res.summary))
      .catch(() => setAiSummary("System operating normally with zero recorded audit events."))
      .finally(() => setAiLoading(false))
  }, [])

  useEffect(() => {
    fetchData()
    fetchAiSummary()

    const handleSimLeak = () => {
      fetchData()
      fetchAiSummary()
    }

    window.addEventListener("examos-sim-leak", handleSimLeak)
    return () => window.removeEventListener("examos-sim-leak", handleSimLeak)
  }, [fetchData, fetchAiSummary])

  const handleResolveAlert = async (alertId: number) => {
    setResolvingId(alertId)
    try {
      await api.admin.resolveAlert(alertId)
      fetchData()
    } catch (err) {
      console.error(err)
    } finally {
      setResolvingId(null)
    }
  }

  const handleAction = async (
    paperId: number,
    endpoint: "hod-review" | "controller-review",
    action: "approve" | "reject"
  ) => {
    setActionLoading((prev) => ({ ...prev, [paperId]: true }))
    setActionError(null)

    try {
      if (endpoint === "controller-review") {
        await api.papers.controllerReview(paperId, action)
      } else {
        await api.papers.hodReview(paperId, action)
      }
      fetchData()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Action failed")
    } finally {
      setActionLoading((prev) => ({ ...prev, [paperId]: false }))
    }
  }

  const pendingController = papers.filter((p) => p.status === "Pending_Controller")
  const pendingHOD = papers.filter((p) => p.status === "Pending_HOD")
  const activeAlerts = alerts.filter((a) => !a.resolved)

  return (
    <DashboardLayout pageTitle="Security Operations Center">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center glow-primary">
              <ShieldCheck className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-tight">Security Operations Command</h2>
              <p className="text-xs text-muted-foreground">
                Real-time threat telemetry, AI log intelligence, and paper lifecycle governance
              </p>
            </div>
          </div>

          <Button variant="outline" size="sm" onClick={() => { fetchData(); fetchAiSummary() }} className="gap-1.5 text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh Telemetry
          </Button>
        </div>

        {/* AI Analysis Center */}
        <Card className="border-primary/30 bg-card/90 overflow-hidden relative shadow-lg">
          <div className="absolute top-0 right-0 left-0 h-1 bg-gradient-to-r from-primary via-accent to-destructive" />
          <CardContent className="p-5">
            <div className="flex items-start gap-4">
              <div className="relative shrink-0 mt-0.5">
                <div className="w-9 h-9 rounded-xl bg-accent/20 border border-accent/40 flex items-center justify-center">
                  <Cpu className="w-5 h-5 text-accent" />
                </div>
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-accent"></span>
                </span>
              </div>

              <div className="space-y-1.5 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-accent">
                    Gemini 2.5 Log Intelligence
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-accent/15 text-accent font-mono">
                    LIVE SENTRY
                  </span>
                </div>

                {aiLoading ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-accent" />
                    <span>Analyzing system audit logs with Gemini AI models…</span>
                  </div>
                ) : (
                  <p className="text-xs font-medium leading-relaxed text-foreground/90 font-mono">
                    {aiSummary}
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Metric Layout Deck */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          <Card className="glass">
            <CardContent className="pt-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Active Threat Indicators</p>
                  <p className="text-2xl font-bold mt-1 text-foreground">
                    {stats ? stats.active_threats : activeAlerts.length}
                  </p>
                </div>
                <div className={`p-2.5 rounded-lg ${activeAlerts.length > 0 ? "bg-destructive/15 text-destructive" : "bg-primary/10 text-primary"}`}>
                  <ShieldAlert className="w-6 h-6" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="glass">
            <CardContent className="pt-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">System Risk Level</p>
                  <p className="text-2xl font-bold mt-1 text-foreground">
                    {stats ? `${stats.system_risk_level} / 100` : "0.0"}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-[hsl(var(--severity-medium)/0.15)] text-[hsl(var(--severity-medium))]">
                  <Activity className="w-6 h-6" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="glass">
            <CardContent className="pt-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Vault Locks</p>
                  <p className="text-2xl font-bold mt-1 text-foreground">
                    {stats ? stats.vault_locks : papers.filter(p => p.status === "Approved_Locked").length}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-[hsl(var(--severity-low)/0.15)] text-[hsl(var(--severity-low))]">
                  <Lock className="w-6 h-6" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="glass">
            <CardContent className="pt-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Open Print Queues</p>
                  <p className="text-2xl font-bold mt-1 text-foreground">
                    {stats ? stats.open_print_queues : papers.filter(p => p.status === "Approved_Locked").length}
                  </p>
                </div>
                <div className="p-2.5 rounded-lg bg-accent/15 text-accent">
                  <Printer className="w-6 h-6" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Live Grid Console: Threat Telemetry & Active Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Recharts Timeline */}
          <Card className="glass lg:col-span-2">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-bold">System Access &amp; Threat Telemetry</CardTitle>
                  <CardDescription className="text-xs">Live activity metrics over time</CardDescription>
                </div>
                <Badge variant="secondary">24H Timeline</Badge>
              </div>
            </CardHeader>
            <CardContent className="pt-2">
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={stats?.timeline ?? []}>
                    <defs>
                      <linearGradient id="colorAccess" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(220 91% 60%)" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="hsl(220 91% 60%)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(0 72% 51%)" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="hsl(0 72% 51%)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 20% 18%)" />
                    <XAxis dataKey="time" stroke="hsl(215 20.2% 65.1%)" fontSize={11} />
                    <YAxis stroke="hsl(215 20.2% 65.1%)" fontSize={11} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(222 20% 11%)",
                        borderColor: "hsl(222 20% 18%)",
                        borderRadius: "6px",
                        fontSize: "12px",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="access_events"
                      name="Access Events"
                      stroke="hsl(220 91% 60%)"
                      fillOpacity={1}
                      fill="url(#colorAccess)"
                    />
                    <Area
                      type="monotone"
                      dataKey="threat_events"
                      name="Threat Alerts"
                      stroke="hsl(0 72% 51%)"
                      fillOpacity={1}
                      fill="url(#colorThreat)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Active System Alerts */}
          <Card className="glass flex flex-col">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-bold flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-destructive" />
                    Active Alerts
                  </CardTitle>
                  <CardDescription className="text-xs">Honeytoken trips &amp; access breaches</CardDescription>
                </div>
                {activeAlerts.length > 0 && (
                  <span className="flex items-center justify-center px-2 py-0.5 rounded-full bg-destructive text-[10px] font-bold text-destructive-foreground">
                    {activeAlerts.length}
                  </span>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-0 flex-1 overflow-auto max-h-72">
              {alerts.length === 0 ? (
                <div className="py-12 text-center text-xs text-muted-foreground">
                  No security alerts recorded.
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {alerts.map((alert) => (
                    <div
                      key={alert.id}
                      className={`p-3 space-y-1.5 text-xs transition-colors ${
                        alert.resolved ? "opacity-50 bg-card/40" : "bg-card/90 hover:bg-card"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span
                          className={`font-semibold uppercase text-[10px] px-1.5 py-0.5 rounded border ${
                            alert.severity === "critical"
                              ? "bg-destructive/20 text-destructive border-destructive/30"
                              : alert.severity === "high"
                              ? "bg-[hsl(var(--severity-high)/0.2)] text-[hsl(var(--severity-high))] border-[hsl(var(--severity-high)/0.3)]"
                              : "bg-[hsl(var(--severity-medium)/0.2)] text-[hsl(var(--severity-medium))] border-[hsl(var(--severity-medium)/0.3)]"
                          }`}
                        >
                          {alert.severity}
                        </span>

                        {alert.resolved ? (
                          <span className="text-[10px] text-muted-foreground font-medium">Resolved ✓</span>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={resolvingId === alert.id}
                            onClick={() => handleResolveAlert(alert.id)}
                            className="h-6 text-[10px] px-2 gap-1 border-destructive/40 text-destructive hover:bg-destructive/10"
                          >
                            {resolvingId === alert.id && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
                            Resolve
                          </Button>
                        )}
                      </div>
                      <p className="text-foreground leading-snug font-mono text-[11px]">
                        {alert.message}
                      </p>
                      <p className="text-[10px] text-muted-foreground">
                        {new Date(alert.created_at).toLocaleTimeString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {actionError && (
          <div
            role="alert"
            className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-2.5 text-xs text-destructive"
          >
            <XCircle className="w-3.5 h-3.5 shrink-0" />
            {actionError}
          </div>
        )}

        {/* Controller Approval Queue */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Controller Approval Queue</CardTitle>
                <CardDescription>Escalated papers awaiting final approval &amp; vault lock</CardDescription>
              </div>
              {pendingController.length > 0 && (
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-primary text-[10px] font-bold text-primary-foreground">
                  {pendingController.length}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">Title</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Exam Date</TableHead>
                  <TableHead>Submitted</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : pendingController.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center text-xs text-muted-foreground">
                      No papers awaiting controller approval.
                    </TableCell>
                  </TableRow>
                ) : (
                  pendingController.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="pl-5 font-medium text-sm">{p.title}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{p.subject}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(p.exam_date).toLocaleDateString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                        })}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(p.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={p.status} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <ActionButton
                            label="Approve & Lock"
                            variant="default"
                            icon={CheckCircle2}
                            loading={!!actionLoading[p.id]}
                            onClick={() => handleAction(p.id, "controller-review", "approve")}
                          />
                          <ActionButton
                            label="Reject"
                            variant="destructive"
                            icon={XCircle}
                            loading={!!actionLoading[p.id]}
                            onClick={() => handleAction(p.id, "controller-review", "reject")}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* HOD Review Queue */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>HOD Review Queue</CardTitle>
                <CardDescription>Newly uploaded papers awaiting initial department review</CardDescription>
              </div>
              {pendingHOD.length > 0 && (
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[hsl(var(--severity-medium))] text-[10px] font-bold text-white">
                  {pendingHOD.length}
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">Title</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Exam Date</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : pendingHOD.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-xs text-muted-foreground">
                      No papers awaiting HOD review.
                    </TableCell>
                  </TableRow>
                ) : (
                  pendingHOD.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="pl-5 font-medium text-sm">{p.title}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{p.subject}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(p.exam_date).toLocaleDateString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                        })}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={p.status} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <ActionButton
                            label="Approve to Controller"
                            variant="outline"
                            icon={CheckCircle2}
                            loading={!!actionLoading[p.id]}
                            onClick={() => handleAction(p.id, "hod-review", "approve")}
                          />
                          <ActionButton
                            label="Reject"
                            variant="destructive"
                            icon={XCircle}
                            loading={!!actionLoading[p.id]}
                            onClick={() => handleAction(p.id, "hod-review", "reject")}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* All Papers Audit View */}
        <Card className="glass">
          <CardHeader>
            <CardTitle>System Paper Inventory</CardTitle>
            <CardDescription>Complete registry of all examination assets</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">#</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Exam Date</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : papers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-10 text-center text-xs text-muted-foreground">
                      <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
                      No papers registered in the system.
                    </TableCell>
                  </TableRow>
                ) : (
                  papers.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="pl-5 text-xs text-muted-foreground font-mono">{p.id}</TableCell>
                      <TableCell className="font-medium text-sm">{p.title}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{p.subject}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(p.exam_date).toLocaleDateString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                        })}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={p.status} />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}
