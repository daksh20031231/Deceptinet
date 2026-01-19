"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { useEffect, useState } from "react"

interface Attack {
  id: string
  timestamp: string
  type: string
  source: string
  severity: "critical" | "high" | "medium" | "low"
  status: "blocked" | "detected" | "investigating"
}

const initialAttacks: Attack[] = [
  {
    id: "1",
    timestamp: "12:45:23",
    type: "SQL Injection",
    source: "192.168.1.105",
    severity: "critical",
    status: "blocked",
  },
  { id: "2", timestamp: "12:44:58", type: "XSS Attack", source: "10.0.0.45", severity: "high", status: "blocked" },
  {
    id: "3",
    timestamp: "12:44:31",
    type: "Brute Force",
    source: "203.0.113.42",
    severity: "medium",
    status: "investigating",
  },
  { id: "4", timestamp: "12:43:55", type: "DDoS", source: "198.51.100.23", severity: "critical", status: "blocked" },
  { id: "5", timestamp: "12:43:12", type: "Port Scan", source: "172.16.0.88", severity: "low", status: "detected" },
  { id: "6", timestamp: "12:42:47", type: "Malware", source: "10.255.255.1", severity: "high", status: "blocked" },
]

const attackTypes = ["SQL Injection", "XSS Attack", "Brute Force", "DDoS", "Port Scan", "Malware", "Phishing", "RCE"]
const severities: Attack["severity"][] = ["critical", "high", "medium", "low"]
const statuses: Attack["status"][] = ["blocked", "detected", "investigating"]

export function AttackFeed() {
  const [attacks, setAttacks] = useState<Attack[]>(initialAttacks)

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date()
      const newAttack: Attack = {
        id: Date.now().toString(),
        timestamp: now.toTimeString().slice(0, 8),
        type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
        source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        severity: severities[Math.floor(Math.random() * severities.length)],
        status: statuses[Math.floor(Math.random() * statuses.length)],
      }
      setAttacks((prev) => [newAttack, ...prev.slice(0, 9)])
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: Attack["severity"]) => {
    switch (severity) {
      case "critical":
        return "bg-destructive text-destructive-foreground"
      case "high":
        return "bg-orange-500 text-foreground"
      case "medium":
        return "bg-warning text-warning-foreground"
      case "low":
        return "bg-success text-success-foreground"
    }
  }

  const getStatusColor = (status: Attack["status"]) => {
    switch (status) {
      case "blocked":
        return "text-success"
      case "detected":
        return "text-warning"
      case "investigating":
        return "text-primary"
    }
  }

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
            Live Attack Feed
          </CardTitle>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-destructive opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-destructive"></span>
            </span>
            <span className="text-xs text-muted-foreground">Live</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[280px] pr-4">
          <div className="space-y-2">
            {attacks.map((attack, index) => (
              <div
                key={attack.id}
                className={`p-3 rounded-lg bg-secondary/50 border border-border transition-all duration-300 ${
                  index === 0 ? "animate-in fade-in slide-in-from-top-2" : ""
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm text-foreground truncate">{attack.type}</span>
                      <Badge className={`text-xs ${getSeverityColor(attack.severity)}`}>{attack.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 font-mono">{attack.source}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-xs text-muted-foreground font-mono">{attack.timestamp}</p>
                    <p className={`text-xs font-medium capitalize ${getStatusColor(attack.status)}`}>{attack.status}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  )
}
