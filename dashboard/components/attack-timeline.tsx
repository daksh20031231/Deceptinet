"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEffect, useRef, useState } from "react"
import { Chart, LineElement, PointElement, LineController, CategoryScale, LinearScale, Tooltip, Filler } from "chart.js"

Chart.register(LineElement, PointElement, LineController, CategoryScale, LinearScale, Tooltip, Filler)

export function AttackTimeline() {
  const chartRef = useRef<HTMLCanvasElement>(null)
  const chartInstance = useRef<Chart | null>(null)
  const [timeRange, setTimeRange] = useState("12h")

  const generateData = () => {
    const points = 24
    const labels = Array.from({ length: points }, (_, i) => `${i}:00`)
    const blocked = Array.from({ length: points }, () => Math.floor(Math.random() * 150) + 50)
    const detected = Array.from({ length: points }, () => Math.floor(Math.random() * 80) + 20)
    return { labels, blocked, detected }
  }

  const [data] = useState(generateData)

  useEffect(() => {
    if (!chartRef.current) return

    if (chartInstance.current) {
      chartInstance.current.destroy()
    }

    const ctx = chartRef.current.getContext("2d")
    if (!ctx) return

    const gradient1 = ctx.createLinearGradient(0, 0, 0, 200)
    gradient1.addColorStop(0, "rgba(99, 102, 241, 0.3)")
    gradient1.addColorStop(1, "rgba(99, 102, 241, 0)")

    const gradient2 = ctx.createLinearGradient(0, 0, 0, 200)
    gradient2.addColorStop(0, "rgba(234, 179, 8, 0.3)")
    gradient2.addColorStop(1, "rgba(234, 179, 8, 0)")

    chartInstance.current = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.labels,
        datasets: [
          {
            label: "Blocked",
            data: data.blocked,
            borderColor: "#6366f1",
            backgroundColor: gradient1,
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4,
          },
          {
            label: "Detected",
            data: data.detected,
            borderColor: "#eab308",
            backgroundColor: gradient2,
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: "index",
        },
        scales: {
          x: {
            grid: {
              color: "rgba(255, 255, 255, 0.05)",
            },
            ticks: {
              color: "#6b7280",
              maxTicksLimit: 8,
            },
          },
          y: {
            grid: {
              color: "rgba(255, 255, 255, 0.05)",
            },
            ticks: {
              color: "#6b7280",
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            backgroundColor: "#1f2937",
            titleColor: "#f9fafb",
            bodyColor: "#d1d5db",
            borderColor: "#374151",
            borderWidth: 1,
            padding: 12,
          },
        },
      },
    })

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy()
      }
    }
  }, [data])

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
            Attack Timeline
          </CardTitle>
          <div className="flex items-center gap-1">
            {["1h", "6h", "12h", "24h"].map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  timeRange === range
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-4 mt-2">
          <div className="flex items-center gap-2">
            <div className="w-3 h-0.5 bg-primary rounded" />
            <span className="text-xs text-muted-foreground">Blocked</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-0.5 bg-warning rounded" />
            <span className="text-xs text-muted-foreground">Detected</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-[200px]">
          <canvas ref={chartRef} />
        </div>
      </CardContent>
    </Card>
  )
}
