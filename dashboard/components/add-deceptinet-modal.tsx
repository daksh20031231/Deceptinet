"use client"

import React from "react"

import { useState } from "react"
import { X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export interface DeceptionInstance {
  id: string
  name: string
  type: string
  status: "Active"
  createdAt: Date
}

interface AddDeceptiNetModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (instance: DeceptionInstance) => void
}

export function AddDeceptiNetModal({ isOpen, onClose, onSubmit }: AddDeceptiNetModalProps) {
  const [name, setName] = useState("")
  const [type, setType] = useState("")

  if (!isOpen) return null

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name || !type) return

    const newInstance: DeceptionInstance = {
      id: crypto.randomUUID(),
      name,
      type,
      status: "Active",
      createdAt: new Date(),
    }

    onSubmit(newInstance)
    setName("")
    setType("")
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-50 w-full max-w-md bg-card border border-border rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-foreground">Add DeceptiNet Instance</h2>
          <Button variant="ghost" size="icon" onClick={onClose} className="h-8 w-8">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="deception-name" className="text-foreground">
              Deception Name
            </Label>
            <Input
              id="deception-name"
              placeholder="Enter deception name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="bg-secondary border-border text-foreground placeholder:text-muted-foreground"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="deception-type" className="text-foreground">
              Deception Type
            </Label>
            <Select value={type} onValueChange={setType} required>
              <SelectTrigger className="bg-secondary border-border text-foreground">
                <SelectValue placeholder="Select type" />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="SSH Honeypot">SSH Honeypot</SelectItem>
                <SelectItem value="HTTP Honeypot">HTTP Honeypot</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex gap-3 pt-2">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1 border-border bg-transparent">
              Cancel
            </Button>
            <Button type="submit" className="flex-1 bg-primary text-primary-foreground hover:bg-primary/90">
              Create Instance
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
