"use client"

import { Shield, Bell, Search, Wifi, WifiOff, LogOut, ChevronDown, User, Settings } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useState } from "react"
import { useRouter } from "next/navigation"

// Mock authenticated user data (simulating Firebase Google Auth)
const mockUser = {
  displayName: "John Doe",
  email: "john.doe@example.com",
  photoURL: "https://lh3.googleusercontent.com/a/default-user=s96-c",
}

export function DashboardHeader() {
  const [isConnected, setIsConnected] = useState(true)
  const router = useRouter()

  const handleLogout = () => {
    router.push("/login")
  }

  return (
    <header className="border-b border-border bg-card px-4 lg:px-6 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-lg font-semibold text-foreground">Deceptinet</h1>
              <p className="text-xs text-muted-foreground">SOC Platform</p>
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


          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="rounded-full">
                <User className="h-5 w-5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <div className="px-3 py-2">
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">User ID</p>
                <p className="text-sm font-mono text-foreground bg-secondary px-2 py-1 rounded">{mockUser.email}</p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive cursor-pointer">
                <LogOut className="mr-2 h-4 w-4" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
