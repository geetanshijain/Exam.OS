import { useCallback, useEffect, useState } from "react"
import { ShieldCheck, Loader2, CheckCircle2, XCircle, Clock, FileText, Bell } from "lucide-react"
import { DashboardLayout } from "@/layouts/DashboardLayout"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusBadge } from "@/components/ui/badge"
import { api, type Paper } from "@/lib/api"

function usePapers() {
  const [papers, setPapers] = useState<Paper[]>([])
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(() => {
    setLoading(true)
    api.papers
      .list()
      .then(setPapers)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { refresh() }, [refresh])
  return { papers, loading, refresh }
}

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
  const { papers, loading, refresh } = usePapers()
  const [actionLoading, setActionLoading] = useState<Record<number, boolean>>({})
  const [actionError, setActionError] = useState<string | null>(null)

  const pendingController = papers.filter((p) => p.status === "Pending_Controller")
  const pendingHOD = papers.filter((p) => p.status === "Pending_HOD")
  const approved = papers.filter((p) => p.status === "Approved_Locked")
  const rejected = papers.filter((p) => p.status === "Rejected")

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
      refresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Action failed")
    } finally {
      setActionLoading((prev) => ({ ...prev, [paperId]: false }))
    }
  }

  return (
    <DashboardLayout pageTitle="Controller">
      <div className="p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent/15 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-accent" />
          </div>
          <div>
            <h2 className="text-base font-semibold">Controller Dashboard</h2>
            <p className="text-xs text-muted-foreground">
              Manage and approve question papers through the lifecycle pipeline
            </p>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          {[
            { label: "Awaiting HOD", value: pendingHOD.length, icon: Clock, color: "text-[hsl(var(--severity-medium))]" },
            { label: "Awaiting You", value: pendingController.length, icon: Bell, color: "text-primary" },
            { label: "Approved", value: approved.length, icon: CheckCircle2, color: "text-[hsl(var(--severity-low))]" },
            { label: "Rejected", value: rejected.length, icon: XCircle, color: "text-destructive" },
          ].map(({ label, value, icon: Icon, color }) => (
            <Card key={label} className="glass">
              <CardContent className="pt-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground">{label}</p>
                    <p className="text-2xl font-bold mt-1">{value}</p>
                  </div>
                  <Icon className={`w-8 h-8 opacity-60 ${color}`} />
                </div>
              </CardContent>
            </Card>
          ))}
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

        {/* Controller approval queue — papers in Pending_Controller */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Approval Queue</CardTitle>
                <CardDescription>Papers escalated to controller — awaiting your decision</CardDescription>
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
                    <TableCell colSpan={6} className="py-10 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : pendingController.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-10 text-center text-xs text-muted-foreground">
                      No papers awaiting controller approval.
                    </TableCell>
                  </TableRow>
                ) : (
                  pendingController.map((p) => (
                    <TableRow key={p.id} className="group">
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
                            label="Approve"
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

        {/* HOD queue — controller can also act as HOD */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>HOD Review Queue</CardTitle>
                <CardDescription>Newly uploaded papers awaiting HOD approval before escalation</CardDescription>
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

        {/* All papers audit view */}
        <Card className="glass">
          <CardHeader>
            <CardTitle>All Papers</CardTitle>
            <CardDescription>Complete view across all lifecycle states</CardDescription>
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
                      No papers in the system yet.
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
