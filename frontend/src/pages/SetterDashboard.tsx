import { useCallback, useEffect, useRef, useState } from "react"
import { FileText, Plus, Clock, CheckCircle2, XCircle, Upload, X, Loader2 } from "lucide-react"
import { DashboardLayout } from "@/layouts/DashboardLayout"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
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

interface UploadForm {
  title: string
  subject: string
  exam_date: string
  description: string
  file: File | null
}

const EMPTY_FORM: UploadForm = { title: "", subject: "", exam_date: "", description: "", file: null }

export function SetterDashboard() {
  const { papers, loading, refresh } = usePapers()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [form, setForm] = useState<UploadForm>(EMPTY_FORM)
  const [dragOver, setDragOver] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const counts = {
    total: papers.length,
    pending: papers.filter((p) => p.status === "Pending_HOD" || p.status === "Pending_Controller").length,
    approved: papers.filter((p) => p.status === "Approved_Locked").length,
    rejected: papers.filter((p) => p.status === "Rejected").length,
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) setForm((f) => ({ ...f, file }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.file) return
    setSubmitting(true)
    setUploadError(null)

    try {
      const fd = new FormData()
      fd.append("title", form.title)
      fd.append("subject", form.subject)
      fd.append("exam_date", new Date(form.exam_date).toISOString())
      fd.append("description", form.description)
      fd.append("file", form.file)
      await api.papers.upload(fd)
      setDialogOpen(false)
      setForm(EMPTY_FORM)
      refresh()
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Upload failed")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <DashboardLayout pageTitle="Paper Setter">
      <div className="p-6 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold">My Question Papers</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Upload and track examination papers through the approval pipeline
            </p>
          </div>
          <Button id="upload-paper-btn" size="sm" className="gap-1.5" onClick={() => setDialogOpen(true)}>
            <Plus className="w-4 h-4" />
            Upload Paper
          </Button>
        </div>

        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          {[
            { label: "Total", value: counts.total, icon: FileText, color: "text-primary" },
            { label: "In Review", value: counts.pending, icon: Clock, color: "text-[hsl(var(--severity-medium))]" },
            { label: "Approved", value: counts.approved, icon: CheckCircle2, color: "text-[hsl(var(--severity-low))]" },
            { label: "Rejected", value: counts.rejected, icon: XCircle, color: "text-destructive" },
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

        <Card className="glass">
          <CardHeader>
            <CardTitle>Submitted Papers</CardTitle>
            <CardDescription>All papers across examination cycles — sorted newest first</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">Title</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Exam Date</TableHead>
                  <TableHead>Uploaded</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-10 text-center">
                      <Loader2 className="w-4 h-4 animate-spin mx-auto text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ) : papers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-12 text-center text-xs text-muted-foreground">
                      No papers yet — click{" "}
                      <strong className="text-foreground">Upload Paper</strong> to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  papers.map((p) => (
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
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Upload Question Paper</DialogTitle>
            <DialogDescription>
              File will be AES-256-GCM encrypted before storage. Submitted directly to HOD review.
            </DialogDescription>
          </DialogHeader>

          <form id="upload-paper-form" onSubmit={handleSubmit} className="space-y-4 mt-2">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Title
              </label>
              <input
                id="paper-title"
                required
                value={form.title}
                onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
                placeholder="e.g. Data Structures — End Semester"
                className="w-full h-9 rounded-md border border-input bg-transparent px-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Subject
                </label>
                <input
                  id="paper-subject"
                  required
                  value={form.subject}
                  onChange={(e) => setForm((f) => ({ ...f, subject: e.target.value }))}
                  placeholder="CS301"
                  className="w-full h-9 rounded-md border border-input bg-transparent px-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Exam Date
                </label>
                <input
                  id="paper-exam-date"
                  type="date"
                  required
                  value={form.exam_date}
                  onChange={(e) => setForm((f) => ({ ...f, exam_date: e.target.value }))}
                  className="w-full h-9 rounded-md border border-input bg-transparent px-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring [color-scheme:dark]"
                />
              </div>
            </div>

            <div
              id="file-drop-zone"
              onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`flex flex-col items-center justify-center gap-2 h-28 rounded-lg border-2 border-dashed cursor-pointer transition-colors ${
                dragOver
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-primary/50 hover:bg-muted/20"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) setForm((f) => ({ ...f, file }))
                }}
              />
              {form.file ? (
                <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                  <FileText className="w-4 h-4 text-primary shrink-0" />
                  <span className="truncate max-w-[220px]">{form.file.name}</span>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); setForm((f) => ({ ...f, file: null })) }}
                    className="text-muted-foreground hover:text-destructive transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <>
                  <Upload className="w-6 h-6 text-muted-foreground" />
                  <p className="text-xs text-muted-foreground text-center">
                    Drag &amp; drop or{" "}
                    <span className="text-primary underline underline-offset-2">browse</span>
                  </p>
                </>
              )}
            </div>

            {uploadError && (
              <p role="alert" className="text-xs text-destructive">{uploadError}</p>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => { setDialogOpen(false); setForm(EMPTY_FORM) }}
              >
                Cancel
              </Button>
              <Button
                id="submit-paper-btn"
                type="submit"
                size="sm"
                disabled={!form.file || submitting}
                className="gap-1.5"
              >
                {submitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {submitting ? "Encrypting…" : "Submit to HOD"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  )
}
