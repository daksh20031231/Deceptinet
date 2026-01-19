"use client"

import { useState } from "react"
import { DashboardHeader } from "@/components/dashboard-header"
import { ThreatScoreGauge } from "@/components/threat-score-gauge"
import { AttackFeed } from "@/components/attack-feed"
import { TopAttackingIps } from "@/components/top-attacking-ips"
import { AttackTypeDistribution } from "@/components/attack-type-distribution"
import { AttackTimeline } from "@/components/attack-timeline"
import { StatsOverview } from "@/components/stats-overview"
import { AddDeceptiNetModal, type DeceptionInstance } from "@/components/add-deceptinet-modal"
import { DeceptionInstances } from "@/components/deception-instances"

const demoInstance: DeceptionInstance = {
  id: "demo-instance-001",
  name: "Production SSH Trap",
  type: "SSH Honeypot",
  status: "Active",
  createdAt: new Date("2025-01-15T10:30:00"),
}

export default function Dashboard() {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [instances, setInstances] = useState<DeceptionInstance[]>([demoInstance])
  const [selectedInstanceId, setSelectedInstanceId] = useState<string | null>(demoInstance.id)

  const handleAddInstance = (instance: DeceptionInstance) => {
    setInstances((prev) => [...prev, instance])
    setSelectedInstanceId(instance.id)
  }

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      <main className="p-4 lg:p-6 space-y-6">
        <DeceptionInstances
          instances={instances}
          selectedInstanceId={selectedInstanceId}
          onSelectInstance={setSelectedInstanceId}
          onAddDeceptiNet={() => setIsModalOpen(true)}
        />
        {selectedInstanceId && (
          <>
            <StatsOverview />
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-4 space-y-6">
                <ThreatScoreGauge />
                <TopAttackingIps />
              </div>
              <div className="lg:col-span-8 space-y-6">
                <AttackTimeline />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <AttackTypeDistribution />
                  <AttackFeed />
                </div>
              </div>
            </div>
          </>
        )}
      </main>
      <AddDeceptiNetModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleAddInstance}
      />
    </div>
  )
}
