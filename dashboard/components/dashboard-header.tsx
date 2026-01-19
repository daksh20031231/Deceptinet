"use client"

import { Shield, Bell, Settings, Search, Wifi, WifiOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { useState } from "react"

export function DashboardHeader() {
  const [isConnected, setIsConnected] = useState(true)

  return (
    <header className="border-b border-border bg-card px-4 lg:px-6 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-lg font-semibold text-foreground">Deceptinet</h1>
              <p className="text-xs text-muted-foreground">SOC Dashboard</p>
            </div>
          </div>
        </div>

        <div className="hidden md:flex items-center gap-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search threats, IPs, events..." className="pl-9 bg-secondary border-border" />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" className="gap-2" onClick={() => setIsConnected(!isConnected)}>
            {isConnected ? (
              <>
                <Wifi className="h-4 w-4 text-success" />
                <span className="hidden sm:inline text-success text-xs">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-destructive" />
                <span className="hidden sm:inline text-destructive text-xs">Offline</span>
              </>
            )}
          </Button>

          <Button variant="ghost" size="icon" className="relative">
            <Bell className="h-5 w-5" />
            <Badge className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center bg-destructive text-destructive-foreground text-xs">
              7
            </Badge>
          </Button>

          <Button variant="ghost" size="icon">
            <Settings className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  )
}
