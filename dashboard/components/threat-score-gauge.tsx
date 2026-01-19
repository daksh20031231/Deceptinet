"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEffect, useState } from "react"

export function ThreatScoreGauge() {
  const [score, setScore] = useState(72)
  const [animatedScore, setAnimatedScore] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(score)
    }, 100)
    return () => clearTimeout(timer)
  }, [score])

  useEffect(() => {
    const interval = setInterval(() => {
      setScore((prev) => {
        const change = Math.floor(Math.random() * 10) - 5
        return Math.max(0, Math.min(100, prev + change))
      })
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  const getScoreColor = (s: number) => {
    if (s < 30) return { color: "#22c55e", label: "Low", bg: "bg-success/20" }
    if (s < 60) return { color: "#eab308", label: "Medium", bg: "bg-warning/20" }
    if (s < 80) return { color: "#f97316", label: "High", bg: "bg-orange-500/20" }
    return { color: "#ef4444", label: "Critical", bg: "bg-destructive/20" }
  }

  const { color, label, bg } = getScoreColor(animatedScore)
  const rotation = (animatedScore / 100) * 180 - 90

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
          Threat Level
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center">
          <div className="relative w-48 h-24 overflow-hidden">
            <svg viewBox="0 0 200 100" className="w-full h-full">
              <defs>
                <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#22c55e" />
                  <stop offset="33%" stopColor="#eab308" />
                  <stop offset="66%" stopColor="#f97316" />
                  <stop offset="100%" stopColor="#ef4444" />
                </linearGradient>
              </defs>
              <path
                d="M 20 90 A 80 80 0 0 1 180 90"
                fill="none"
                stroke="url(#gaugeGradient)"
                strokeWidth="12"
                strokeLinecap="round"
                opacity="0.3"
              />
              <path
                d="M 20 90 A 80 80 0 0 1 180 90"
                fill="none"
                stroke="url(#gaugeGradient)"
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={`${(animatedScore / 100) * 251.2} 251.2`}
                style={{ transition: "stroke-dasharray 0.5s ease-out" }}
              />
              <g transform={`rotate(${rotation}, 100, 90)`} style={{ transition: "transform 0.5s ease-out" }}>
                <line x1="100" y1="90" x2="100" y2="30" stroke={color} strokeWidth="3" strokeLinecap="round" />
                <circle cx="100" cy="90" r="8" fill={color} />
              </g>
            </svg>
          </div>
          <div className="text-center mt-2">
            <span className="text-4xl font-bold text-foreground">{animatedScore}</span>
            <span className="text-lg text-muted-foreground">/100</span>
          </div>
          <div className={`mt-2 px-3 py-1 rounded-full ${bg}`}>
            <span className="text-sm font-medium" style={{ color }}>
              {label} Risk
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
