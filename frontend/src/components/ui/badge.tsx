import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border",
  {
    variants: {
      variant: {
        default: "bg-primary/15 text-primary border-primary/20",
        pending_hod: "bg-[hsl(var(--severity-medium)/0.15)] text-[hsl(var(--severity-medium))] border-[hsl(var(--severity-medium)/0.25)]",
        pending_controller: "bg-primary/15 text-primary border-primary/20",
        approved_locked: "bg-[hsl(var(--severity-low)/0.15)] text-[hsl(var(--severity-low))] border-[hsl(var(--severity-low)/0.25)]",
        rejected: "bg-destructive/15 text-destructive border-destructive/25",
        secondary: "bg-secondary text-secondary-foreground border-border",
      },
    },
    defaultVariants: { variant: "default" },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; variant: BadgeProps["variant"] }> = {
    Pending_HOD:         { label: "Pending HOD",         variant: "pending_hod" },
    Pending_Controller:  { label: "Pending Controller",  variant: "pending_controller" },
    Approved_Locked:     { label: "Approved ✓",          variant: "approved_locked" },
    Rejected:            { label: "Rejected",             variant: "rejected" },
  }
  const cfg = map[status] ?? { label: status, variant: "secondary" as const }
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>
}
