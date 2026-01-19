"use client"

import { Server, Globe, Plus, Clock, Activity, Tag } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { DeceptionInstance } from "./add-deceptinet-modal"

interface DeceptionInstancesProps {
  instances: DeceptionInstance[]
  selectedInstanceId: string | null
  onSelectInstance: (id: string) => void
  onAddDeceptiNet: () => void
}

export function DeceptionInstances({
  instances,
  selectedInstanceId,
  onSelectInstance,
  onAddDeceptiNet,
}: DeceptionInstancesProps) {
  const selectedInstance = instances.find((i) => i.id === selectedInstanceId)

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
            <Server className="h-5 w-5 text-primary" />
            DeceptiNet Instances
          </CardTitle>
          <Button
            onClick={onAddDeceptiNet}
            className="bg-primary text-primary-foreground hover:bg-primary/90 gap-2"
            size="sm"
          >
            <Plus className="h-4 w-4" />
            <span className="hidden sm:inline">Add DeceptiNet</span>
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {instances.length === 0 ? (
          <div className="text-center py-8">
            <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-50" />
            <p className="text-muted-foreground text-sm">No DeceptiNet instances created yet</p>
            <p className="text-muted-foreground text-xs mt-1">
              Click the button above to create your first instance
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-3 px-2">
                      Name
                    </th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-3 px-2">
                      Type
                    </th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-3 px-2">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {instances.map((instance) => {
                    const isSelected = selectedInstanceId === instance.id
                    return (
                      <tr
                        key={instance.id}
                        onClick={() => {
                          onSelectInstance(instance.id)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            onSelectInstance(instance.id)
                          }
                        }}
                        tabIndex={0}
                        role="button"
                        className={`border-b border-border/50 last:border-0 cursor-pointer transition-colors ${
                          isSelected
                            ? "bg-primary/10 border-l-2 border-l-primary"
                            : "hover:bg-secondary/50"
                        }`}
                      >
                        <td className="py-3 px-2">
                          <span className="text-sm font-medium text-foreground">{instance.name}</span>
                        </td>
                        <td className="py-3 px-2">
                          <span className="text-sm text-muted-foreground">{instance.type}</span>
                        </td>
                        <td className="py-3 px-2">
                          <Badge
                            variant="outline"
                            className="bg-success/10 text-success border-success/30 text-xs"
                          >
                            {instance.status}
                          </Badge>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {selectedInstance && (
              <div className="mt-4 p-4 bg-secondary/50 rounded-lg border border-border">
                <h4 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-primary" />
                  Instance Details
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="flex items-start gap-2">
                    <Tag className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">Type</p>
                      <p className="text-sm font-medium text-foreground">{selectedInstance.type}</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Activity className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">Status</p>
                      <p className="text-sm font-medium text-success">{selectedInstance.status}</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="text-xs text-muted-foreground">Created</p>
                      <p className="text-sm font-medium text-foreground">{selectedInstance.createdAt.toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
