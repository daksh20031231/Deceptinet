import { DashboardHeader } from "@/components/dashboard-header"
import { ThreatScoreGauge } from "@/components/threat-score-gauge"
import { AttackFeed } from "@/components/attack-feed"
import { TopAttackingIps } from "@/components/top-attacking-ips"
import { AttackTypeDistribution } from "@/components/attack-type-distribution"
import { AttackTimeline } from "@/components/attack-timeline"
import { StatsOverview } from "@/components/stats-overview"

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      <main className="p-4 lg:p-6 space-y-6">
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
      </main>
    </div>
  )
}
