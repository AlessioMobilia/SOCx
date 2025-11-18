import React, { useMemo } from "react"
import {
  AdjustmentsHorizontalIcon,
  BoltIcon,
  DocumentTextIcon,
  MoonIcon,
  SunIcon,
  GlobeAltIcon,
  ExclamationTriangleIcon,
  ExclamationCircleIcon
} from "@heroicons/react/24/outline"

interface PopupUIProps {
  isDarkMode: boolean
  iocHistory: { type: string; text: string; timestamp: string }[]
  onBulkCheckClick: () => void
  onSubnetExtractorClick: () => void
  onSubnetCheckClick: () => void
  onOpenSidePanelClick: () => void
  onClearHistory: () => void
  onToggleTheme: () => void
  onOpenOptionsClick: () => void
}

const PopupUI: React.FC<PopupUIProps> = ({
  isDarkMode,
  iocHistory,
  onBulkCheckClick,
  onSubnetExtractorClick,
  onSubnetCheckClick,
  onOpenSidePanelClick,
  onClearHistory,
  onToggleTheme,
  onOpenOptionsClick
}) => {
  const recentHistory = useMemo(
    () =>
      [...iocHistory]
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 10),
    [iocHistory]
  )

  const actions = [
    {
      label: "Bulk IOC check",
      helper: "Launch the check tab",
      icon: ExclamationTriangleIcon,
      action: onBulkCheckClick
    },
    {
      label: "Subnet extractor",
      helper: "Derive CIDR blocks",
      icon: GlobeAltIcon,
      action: onSubnetExtractorClick
    },
    {
      label: "Subnet abuse check",
      helper: "AbuseIPDB drill-down",
      icon: ExclamationCircleIcon,
      action: onSubnetCheckClick
    },
    {
      label: "Field notes",
      helper: "Open analyst pad",
      icon: DocumentTextIcon,
      action: onOpenSidePanelClick
    },
    {
      label: "Options",
      helper: "Configure services & keys",
      icon: AdjustmentsHorizontalIcon,
      action: onOpenOptionsClick
    }
  ]

  return (
    <div className="min-w-[320px] max-w-[360px] bg-transparent p-2.5 font-inter text-socx-ink dark:text-white">
      <div className="space-y-2 rounded-socx-lg border border-socx-border-light bg-white/90 p-3 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80">
        <header className="flex items-start justify-between gap-2">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.35em] text-socx-muted dark:text-socx-muted-dark">
              SOCx
            </p>
            <p className="text-xs text-socx-muted dark:text-socx-muted-dark">Quick OSINT cockpit</p>
          </div>
          <button
            type="button"
            onClick={onToggleTheme}
            aria-label="Toggle color theme"
            className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-socx-border-light text-socx-muted transition hover:border-socx-accent hover:text-socx-ink focus-visible:outline-none focus-visible:shadow-socx-focus dark:border-socx-border-dark dark:text-socx-muted-dark">
            {isDarkMode ? <SunIcon className="h-5 w-5" /> : <MoonIcon className="h-5 w-5" />}
          </button>
        </header>

        <section className="space-y-1.5">
          {actions.map(({ label, helper, icon: Icon, action }) => (
            <button
              key={label}
              type="button"
              onClick={action}
              className="flex w-full items-center justify-between rounded-xl border border-socx-border-light bg-white/80 px-3 py-1.5 text-left text-sm transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:bg-socx-panel/50">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-transparent bg-socx-accent/15 text-socx-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <div>
                  <p className="font-semibold">{label}</p>
                  <p className="text-[11px] uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                    {helper}
                  </p>
                </div>
              </div>
              <BoltIcon className="h-4 w-4 text-socx-muted dark:text-socx-muted-dark" />
            </button>
          ))}
        </section>

        <section className="space-y-1.5">
          <div className="flex items-center justify-between">
            <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark">
              Latest activity
            </p>
            {recentHistory.length > 0 && (
              <button
                type="button"
                onClick={onClearHistory}
                className="text-xs font-semibold text-socx-muted underline-offset-2 hover:text-socx-accent">
                Clear
              </button>
            )}
          </div>
          <div className="socx-scroll socx-scroll-mini max-h-24 space-y-1 overflow-y-auto rounded-xl border border-socx-border-light bg-white/70 p-2 dark:border-socx-border-dark dark:bg-socx-panel/40">
            {recentHistory.length === 0 ? (
              <p className="py-4 text-center text-xs text-socx-muted dark:text-socx-muted-dark">No IOCs recorded yet.</p>
            ) : (
              recentHistory.map((entry, index) => (
                <div
                  key={`${entry.text}-${index}`}
                  className="flex items-center justify-between rounded-lg px-2 py-0.5 text-xs text-socx-ink dark:text-white">
                  <div className="mr-3 min-w-0">
                    <p className="truncate text-sm font-medium">{entry.text}</p>
                    <p className="text-[11px] uppercase tracking-[0.2em] text-socx-muted dark:text-socx-muted-dark">
                      {entry.type}
                    </p>
                  </div>
                  <span className="text-[11px] text-socx-muted dark:text-socx-muted-dark">
                    {new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

export default PopupUI
