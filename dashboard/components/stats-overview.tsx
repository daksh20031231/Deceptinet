"use client"

import { ShieldAlert, ShieldCheck, Activity, Globe } from "lucide-react"
import { Card } from "@/components/ui/card"

const stats = [
  {
    label: "Threats Blocked",
    value: "2,847",
    change: "+12%",
    trend: "up",
    icon: ShieldCheck,
    color: "text-success",
  },
  {
    label: "Active Attacks",
    value: "23",
    change: "+5",
    trend: "up",
    icon: ShieldAlert,
    color: "text-destructive",
  },
  {
    label: "Events/sec",
    value: "1,284",
    change: "-3%",
    trend: "down",
    icon: Activity,
    color: "text-primary",
  },
  {
    label: "Monitored Assets",
    value: "486",
    change: "+8",
    trend: "up",
    icon: Globe,
    color: "text-warning",
  },
]

export function StatsOverview() {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat) => (
        <Card key={stat.label} className="bg-card border-border p-4">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">{stat.label}</p>
              <p className="text-2xl font-bold text-foreground mt-1">{stat.value}</p>
              <p className={`text-xs mt-1 ${stat.trend === "up" ? "text-success" : "text-muted-foreground"}`}>
                {stat.change} from last hour
              </p>
            </div>
            <stat.icon className={`h-5 w-5 ${stat.color}`} />
          </div>
        </Card>
      ))}
    </div>
  )
}
