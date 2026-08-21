import { CommandLineIcon } from "@heroicons/react/24/outline"
import React, { useEffect, useState } from "react"

import { openShortcutManager, SHORTCUT_COMMANDS } from "../utility/shortcuts"

const cardClass =
  "rounded-socx-lg border border-socx-border-light bg-white/90 p-6 shadow-sm dark:border-socx-border-dark dark:bg-socx-night-soft/80"
const labelClass =
  "text-xs font-semibold uppercase tracking-[0.3em] text-socx-muted dark:text-socx-muted-dark"
const buttonClass =
  "inline-flex items-center justify-center gap-2 rounded-full border border-socx-border-light px-3 py-1.5 text-xs font-semibold text-socx-ink transition hover:border-socx-accent hover:text-socx-accent dark:border-socx-border-dark dark:text-white"

/**
 * Keyboard shortcuts are owned by the browser: an extension may declare a
 * command and suggest a combination, but only the analyst can assign or change
 * one, from the browser's own shortcuts page. So this section reports what is
 * currently bound and routes there. Workspace commands ship unbound to avoid
 * shadowing shortcuts of the console in use.
 */
const ShortcutSettings: React.FC = () => {
  const [bindings, setBindings] = useState<Record<string, string>>({})
  const [error, setError] = useState("")

  const readBindings = () => {
    try {
      chrome.commands.getAll((commands) => {
        const readError = chrome.runtime.lastError
        if (readError) {
          setError(readError.message ?? "Unable to read keyboard shortcuts.")
          return
        }
        const next: Record<string, string> = {}
        for (const command of commands) {
          if (command.name) next[command.name] = command.shortcut ?? ""
        }
        setBindings(next)
      })
    } catch (readError) {
      console.error("Unable to read the keyboard shortcuts:", readError)
    }
  }

  useEffect(() => {
    readBindings()
    window.addEventListener("focus", readBindings)
    document.addEventListener("visibilitychange", readBindings)
    return () => {
      window.removeEventListener("focus", readBindings)
      document.removeEventListener("visibilitychange", readBindings)
    }
  }, [])

  const openShortcutSettings = async () => {
    const manifest = chrome.runtime.getManifest() as chrome.runtime.Manifest & {
      browser_specific_settings?: { gecko?: unknown }
    }
    const firefoxCommands = chrome.commands as typeof chrome.commands & {
      openShortcutSettings?: (callback: () => void) => void
    }
    setError("")
    try {
      await openShortcutManager(
        {
          openFirefoxSettings: firefoxCommands.openShortcutSettings
            ? (callback) =>
                firefoxCommands.openShortcutSettings?.call(
                  firefoxCommands,
                  callback
                )
            : undefined,
          openTab: (url, callback) => {
            chrome.tabs.create({ url }, () => callback())
          },
          readLastError: () => chrome.runtime.lastError
        },
        Boolean(manifest.browser_specific_settings?.gecko),
        navigator.userAgent
      )
    } catch (openError) {
      setError(
        openError instanceof Error
          ? openError.message
          : "Unable to open the browser shortcut manager."
      )
    }
  }

  return (
    <section className={`${cardClass} space-y-4`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className={labelClass}>Keyboard shortcuts</p>
          <p className="mt-1 max-w-3xl text-sm text-socx-muted dark:text-socx-muted-dark">
            In-page actions include defaults for the query palette and smart
            formatting. Workspace commands start disabled. Every combination can
            be reassigned from the browser shortcut manager.
          </p>
        </div>
        <button
          type="button"
          className={buttonClass}
          onClick={openShortcutSettings}>
          <CommandLineIcon className="h-4 w-4" />
          Customize shortcuts
        </button>
      </div>

      <div className="grid gap-2 md:grid-cols-2">
        {SHORTCUT_COMMANDS.map((command) => {
          const shortcut = bindings[command.id]
          return (
            <div
              key={command.id}
              className="flex items-center justify-between gap-3 rounded-xl border border-socx-border-light bg-white/80 px-4 py-3 dark:border-socx-border-dark dark:bg-socx-panel/50">
              <div className="min-w-0">
                <p className="text-sm font-semibold">{command.label}</p>
                <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
                  {command.helper}
                </p>
              </div>
              {shortcut ? (
                <kbd className="shrink-0 rounded-lg border border-socx-accent bg-socx-accent/15 px-2 py-1 font-mono text-xs font-semibold">
                  {shortcut}
                </kbd>
              ) : (
                <span className="shrink-0 rounded-lg border border-dashed border-socx-border-light px-2 py-1 text-[11px] font-semibold text-socx-muted dark:border-socx-border-dark dark:text-socx-muted-dark">
                  Disabled
                </span>
              )}
            </div>
          )
        })}
      </div>

      <p className="text-xs text-socx-muted dark:text-socx-muted-dark">
        Shortcut assignment stays in the browser's native extension editor.
        Firefox opens its dedicated Manage Extension Shortcuts view; Chromium
        opens the extensions shortcut page.
      </p>
      {error && <p className="text-xs text-socx-danger">{error}</p>}
    </section>
  )
}

export default ShortcutSettings
