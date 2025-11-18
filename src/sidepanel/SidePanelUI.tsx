import React from "react"
import {
  ArrowDownTrayIcon,
  ArrowsRightLeftIcon,
  BugAntIcon,
  TrashIcon
} from "@heroicons/react/24/outline"

interface SidePanelUIProps {
  note: string
  isDarkMode: boolean
  onTextChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  onSaveTxt: () => void
  onClearNote: () => void
  onRefang: () => void
  onDefang: () => void
}

const buttonClass =
  "flex flex-1 items-center justify-center gap-2 rounded-full border border-socx-border-light px-4 py-2 text-sm font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent focus-visible:outline-none focus-visible:shadow-socx-focus dark:border-socx-border-dark dark:text-white"

const SidePanelUI: React.FC<SidePanelUIProps> = ({
  note,
  isDarkMode,
  onTextChange,
  onSaveTxt,
  onClearNote,
  onRefang,
  onDefang
}) => {
  return (
    <div className="min-h-full bg-socx-cloud px-4 py-6 font-inter text-socx-ink dark:bg-socx-night dark:text-white">
      <div className="space-y-4 rounded-socx-lg border border-socx-border-light bg-white/80 p-5 dark:border-socx-border-dark dark:bg-socx-night-soft/70">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.4em] text-socx-muted dark:text-socx-muted-dark">
              SOCx
            </p>
            <h2 className="text-lg font-semibold">IOC Notepad</h2>
          </div>
          <span className="rounded-full border border-socx-border-light px-3 py-1 text-xs text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark">
            {isDarkMode ? "Dark" : "Light"} mode
          </span>
        </div>

        <textarea
          value={note}
          onChange={onTextChange}
          rows={16}
          placeholder="Document quick findings, snippets or ad-hoc lists…"
          className="socx-scroll w-full rounded-2xl border border-socx-border-light bg-white/90 px-4 py-3 text-sm text-socx-ink shadow-sm outline-none transition focus:border-socx-accent focus:ring-2 focus:ring-socx-accent/40 dark:border-socx-border-dark dark:bg-socx-panel/60 dark:text-white"
          aria-label="IOC notebook text area"
        />

        <div className="flex flex-col gap-2 md:flex-row">
          <button type="button" onClick={onRefang} className={buttonClass}>
            <ArrowsRightLeftIcon className="h-4 w-4" /> Refang
          </button>
          <button type="button" onClick={onDefang} className={buttonClass}>
            <BugAntIcon className="h-4 w-4" /> Defang
          </button>
        </div>

        <div className="flex flex-col gap-2 md:flex-row">
          <button
            type="button"
            onClick={onSaveTxt}
            className="flex flex-1 items-center justify-center gap-2 rounded-full bg-socx-accent px-4 py-2 text-sm font-semibold text-socx-ink transition hover:bg-socx-accent-strong focus-visible:outline-none focus-visible:shadow-socx-focus">
            <ArrowDownTrayIcon className="h-4 w-4" />
            Save as TXT
          </button>
          <button type="button" onClick={onClearNote} className={`${buttonClass} text-socx-danger`}>
            <TrashIcon className="h-4 w-4" />
            Clear all
          </button>
        </div>
      </div>
    </div>
  )
}

export default SidePanelUI
