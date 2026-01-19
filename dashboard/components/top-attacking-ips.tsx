"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Ban, MapPin } from "lucide-react"

const topIps = [
  { ip: "203.0.113.42", attacks: 1247, country: "CN", status: "active", blocked: false },
  { ip: "198.51.100.23", attacks: 892, country: "RU", status: "active", blocked: true },
  { ip: "192.0.2.156", attacks: 654, country: "KP", status: "active", blocked: true },
  { ip: "172.16.254.1", attacks: 421, country: "IR", status: "inactive", blocked: false },
  { ip: "10.255.255.1", attacks: 298, country: "US", status: "active", blocked: false },
]

export function TopAttackingIps() {
  const maxAttacks = Math.max(...topIps.map((ip) => ip.attacks))

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
          Top Attacking IPs
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {topIps.map((item, index) => (
            <div key={item.ip} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground w-4">{index + 1}.</span>
                  <span className="font-mono text-sm text-foreground">{item.ip}</span>
                  <Badge variant="outline" className="text-xs py-0 px-1.5 flex items-center gap-1">
                    <MapPin className="h-2.5 w-2.5" />
                    {item.country}
                  </Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">{item.attacks.toLocaleString()}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={`h-6 w-6 ${item.blocked ? "text-destructive" : "text-muted-foreground hover:text-destructive"}`}
                  >
                    <Ban className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <div className="ml-6 h-1.5 bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-destructive rounded-full transition-all duration-500"
                  style={{ width: `${(item.attacks / maxAttacks) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
