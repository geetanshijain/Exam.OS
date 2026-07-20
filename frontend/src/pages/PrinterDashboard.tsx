import { useCallback, useEffect, useState } from "react"
import {
  Printer,
  CheckCircle2,
  FileText,
  Download,
  Loader2,
  Clock,
  ShieldAlert,
  Lock,
  Unlock,
} from "lucide-react"
import { DashboardLayout } from "@/layouts/DashboardLayout"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusBadge } from "@/components/ui/badge"
import { api, type Paper } from "@/lib/api"
import { useCountdown } from "@/hooks/useCountdown"

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

  useEffect(() => {
    refresh()
  }, [refresh])

  return { papers, loading, refresh }
}

function pad(n: number) {
  return String(n).padStart(2, "0")
}

function CountdownCell({ examDate }: { examDate: string }) {
  const { hours, minutes, seconds, expired } = useCountdown(examDate)

  if (expired) {
    return (
      <span className="flex items-center gap-1 text-[hsl(var(--severity-low))] font-mono text-xs font-semibold">
        <Unlock className="w-3 h-3" />
        Window open
      </span>
    )
  }

  return (
    <span className="flex items-center gap-1.5 font-mono text-xs text-[hsl(var(--severity-medium))]">
      <Clock className="w-3 h-3 shrink-0 animate-pulse" />
      {pad(hours)}:{pad(minutes)}:{pad(seconds)}
    </span>
  )
}

function DownloadCell({ paper }: { paper: Paper }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleDownload = async () => {
    setLoading(true)
    setError(null)
    try {
      await api.papers.download(paper.id, paper.title)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-1 items-start">
      <Button
        id={`download-btn-${paper.id}`}
        size="sm"
        variant="default"
        className="gap-1.5 h-7 text-xs px-2.5"
        disabled={loading}
        onClick={handleDownload}
      >
        {loading ? (
          <Loader2 className="w-3 h-3 animate-spin" />
        ) : (
          <Download className="w-3 h-3" />
        )}
        {loading ? "Fetching…" : "Download Secure Document"}
      </Button>
      {error && (
        <span className="text-[10px] text-destructive">{error}</span>
      )}
    </div>
  )
}

export function PrinterDashboard() {
  const { papers, loading } = usePapers()

  const approvedPapers = papers.filter((p) => p.status === "Approved_Locked")
  const otherPapers = papers.filter((p) => p.status !== "Approved_Locked")

  return (
    <DashboardLayout pageTitle="Print Station">
      <div className="p-6 space-y-5">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
            <Printer className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h2 className="text-base font-semibold">Print Station</h2>
            <p className="text-xs text-muted-foreground">
              Secure vault access — time-locked decryption enforced server-side
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          {[
            {
              label: "Approved Papers",
              value: approvedPapers.length,
              icon: CheckCircle2,
              color: "text-[hsl(var(--severity-low))]",
            },
            {
              label: "In Pipeline",
              value: otherPapers.length,
              icon: FileText,
              color: "text-[hsl(var(--severity-medium))]",
            },
            {
              label: "Vault Secured",
              value: papers.length,
              icon: Lock,
              color: "text-primary",
            },
            {
              label: "Total Papers",
              value: papers.length,
              icon: Printer,
              color: "text-accent",
            },
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

        <div className="rounded-md border border-[hsl(var(--severity-medium)/0.3)] bg-[hsl(var(--severity-medium)/0.05)] px-4 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-[hsl(var(--severity-medium))] mt-0.5 shrink-0" />
          <div>
            <p className="text-xs font-semibold text-[hsl(var(--severity-medium))]">
              Cryptographic Time Lock Active
            </p>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Downloads are enforced server-side. Accessing a paper before its 30-minute
              pre-exam window will trigger a honeytoken alert and risk score update against
              your account — regardless of UI state.
            </p>
          </div>
        </div>

        <Card className="glass">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Print Queue — Approved Papers</CardTitle>
                <CardDescription>
                  Countdown shows time until the 30-minute access window opens
                </CardDescription>
              </div>
              {approvedPapers.length > 0 && (
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[hsl(var(--severity-low))] text-[10px] font-bold text-white">
                  {approvedPapers.length}
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
                  <TableHead>Time Lock</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-10 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : approvedPapers.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="py-12 text-center text-xs text-muted-foreground"
                    >
                      <Lock className="w-8 h-8 mx-auto mb-2 opacity-20" />
                      No approved papers in the print queue yet.
                    </TableCell>
                  </TableRow>
                ) : (
                  approvedPapers.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="pl-5 font-medium text-sm">{p.title}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{p.subject}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(p.exam_date).toLocaleString("en-IN", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </TableCell>
                      <TableCell>
                        <CountdownCell examDate={p.exam_date} />
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={p.status} />
                      </TableCell>
                      <TableCell>
                        <DownloadCell paper={p} />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {otherPapers.length > 0 && (
          <Card className="glass">
            <CardHeader>
              <CardTitle>Pipeline Papers</CardTitle>
              <CardDescription>Papers still in the approval workflow — not yet accessible</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="pl-5">Title</TableHead>
                    <TableHead>Subject</TableHead>
                    <TableHead>Exam Date</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {otherPapers.map((p) => (
                    <TableRow key={p.id} className="opacity-60">
                      <TableCell className="pl-5 text-sm">{p.title}</TableCell>
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
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  )
}
