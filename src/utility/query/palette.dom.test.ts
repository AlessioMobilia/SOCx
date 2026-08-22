import { beforeEach, describe, expect, it, vi } from "vitest"

import { buildGroupTree } from "./groups"
import { validateQueryPack, type QueryPack } from "./packSchema"
import {
  closePalette,
  entriesFromTree,
  isPaletteOpen,
  mountQueryView,
  openPalette
} from "./palette"
import { entrySourceKey } from "./paletteFilters"
import { bundledDialectMap } from "./render"

const knownDialects = new Set(bundledDialectMap().keys())

const makePack = (overrides: Record<string, unknown> = {}): QueryPack => {
  const result = validateQueryPack(
    {
      schema: "socx.querypack/v1",
      id: "defender-pack",
      kind: "ioc",
      name: "Defender",
      dialect: "kql",
      groups: [{ id: "network", label: "Network" }],
      templates: [
        {
          id: "connections",
          name: "Network connections",
          description: "Outbound sessions",
          group: "network",
          byType: { IP: { field: "RemoteIP", op: "in~" } },
          body: "DeviceNetworkEvents | where {{field}} {{op}} ({{iocs}})"
        },
        {
          id: "logons",
          name: "Failed logons",
          group: "network",
          byType: { IP: { field: "IPAddress", op: "in~" } },
          body: "IdentityLogonEvents | where {{field}} {{op}} ({{iocs}})"
        }
      ],
      ...overrides
    },
    { knownDialects }
  )
  if (!result.ok) {
    throw new Error(result.errors.map((error) => error.message).join("; "))
  }
  return result.value
}

const splunkPack = makePack({
  id: "splunk-pack",
  name: "Splunk",
  dialect: "spl",
  facets: [{ id: "customer", label: "Customer" }],
  templates: [
    {
      id: "proxy",
      name: "Proxy hits",
      group: "network",
      labels: { customer: "ACME" },
      byType: { IP: { field: "src_ip", op: "IN" } },
      body: "index=proxy src_ip IN ({{iocs}})"
    },
    {
      id: "vpn",
      name: "VPN sessions",
      group: "network",
      labels: { customer: "Globex" },
      byType: { IP: { field: "src_ip", op: "IN" } },
      body: "index=vpn src_ip IN ({{iocs}})"
    }
  ]
})

const entries = entriesFromTree(
  buildGroupTree([
    { ...makePack(), sourceId: "a", sourceLabel: "Defender catalogue" },
    { ...splunkPack, sourceId: "b", sourceLabel: "Security team queries" }
  ])
)

const rows = () =>
  Array.from(document.querySelectorAll('[role="option"]')).map(
    (node) => node.textContent ?? ""
  )

const searchField = () =>
  document.querySelector(
    'input[aria-label="Search queries"]'
  ) as HTMLInputElement

const chip = (label: string) =>
  Array.from(document.querySelectorAll("button")).find((button) =>
    (button.textContent ?? "").startsWith(label)
  )

const indicatorField = () =>
  document.querySelector(
    'textarea[aria-label="Indicators used by the query"]'
  ) as HTMLTextAreaElement

const open = (overrides: Record<string, unknown> = {}) =>
  openPalette({
    entries,
    onRender: (
      _entry: unknown,
      input: { indicatorText: string; mergeTypes: boolean }
    ) => [
      {
        text: `rendered with [${input.indicatorText}] merge=${input.mergeTypes}`
      }
    ],
    ...overrides
  } as never)

describe("query palette", () => {
  beforeEach(() => {
    closePalette()
    document.documentElement.classList.remove("dark", "dark-mode")
    document.body.classList.remove("dark", "dark-mode")
    document.body.innerHTML = ""
  })

  it("asks only for the variables the selected template uses", () => {
    // The pack declares four variables, shared by every template in it; the
    // selected query substitutes two of them.
    const variablePack = makePack({
      id: "splunk-variables",
      name: "Splunk variables",
      dialect: "spl",
      variables: [
        { id: "index", label: "Index", default: "main" },
        { id: "time-span", label: "Time span", default: "1h" },
        { id: "pre-filter", label: "Pre-filter" },
        { id: "dest-domain", label: "Destination domain" }
      ],
      templates: [
        {
          id: "log-volume-trend",
          name: "General log volume trend",
          group: "network",
          requiresIocs: false,
          body: "index={{var:index}}\n| timechart span={{var:time-span}} count"
        }
      ],
      kind: "standard"
    })
    openPalette({
      entries: entriesFromTree(
        buildGroupTree([{ ...variablePack, sourceId: "v" }])
      ),
      onRender: () => [{ text: "rendered" }]
    } as never)

    const labels = Array.from(document.querySelectorAll("label")).map(
      (node) => node.textContent ?? ""
    )
    expect(labels.some((text) => text.includes("Index"))).toBe(true)
    expect(labels.some((text) => text.includes("Time span"))).toBe(true)
    expect(labels.some((text) => text.includes("Destination domain"))).toBe(
      false
    )
    expect(labels.some((text) => text.includes("Pre-filter"))).toBe(false)
  })

  it("renders checkbox variables and emits boolean strings", () => {
    const checkboxPack = makePack({
      id: "splunk-tstats",
      name: "Splunk tstats",
      dialect: "spl",
      kind: "standard",
      variables: [
        {
          id: "summariesonly",
          label: "tstats: summaries only",
          type: "checkbox",
          default: "true"
        }
      ],
      templates: [
        {
          id: "accelerated-traffic",
          name: "Accelerated traffic",
          group: "network",
          requiresIocs: false,
          body: "| tstats summariesonly={{var:summariesonly}} count"
        }
      ]
    })
    const values: string[] = []

    openPalette({
      entries: entriesFromTree(
        buildGroupTree([{ ...checkboxPack, sourceId: "checkbox" }])
      ),
      onRender: (
        _entry: unknown,
        input: { variables: Record<string, string> }
      ) => {
        if (input.variables.summariesonly) {
          values.push(input.variables.summariesonly)
        }
        return [{ text: "rendered" }]
      }
    } as never)

    const checkbox = document.querySelector(
      'input[aria-label="tstats: summaries only"]'
    ) as HTMLInputElement
    expect(checkbox.type).toBe("checkbox")
    expect(checkbox.checked).toBe(true)

    const label = checkbox
      .closest("label")
      ?.querySelector("span") as HTMLElement
    expect(label.textContent).toBe("tstats: summaries only")
    expect(label.style.whiteSpace).toBe("normal")
    expect(label.style.textOverflow).toBe("clip")
    expect(label.style.overflow).toBe("visible")

    checkbox.click()
    expect(values.at(-1)).toBe("false")
  })

  it("opens with every template and closes on demand", () => {
    open()
    expect(isPaletteOpen()).toBe(true)
    expect(rows()).toHaveLength(entries.length)
    const closeButton = document.querySelector(
      'button[aria-label="Close query palette"]'
    ) as HTMLButtonElement
    expect(closeButton).toBeTruthy()
    closeButton.click()
    expect(isPaletteOpen()).toBe(false)

    open()
    closePalette()
    expect(isPaletteOpen()).toBe(false)
  })

  it("mounts the same browser as an embedded workspace", () => {
    const host = document.createElement("div")
    document.body.appendChild(host)
    const onIndicatorTextChange = vi.fn()
    const cleanup = mountQueryView(
      {
        entries,
        dialects: bundledDialectMap(),
        indicatorHint: ["8.8.8.8"],
        onIndicatorTextChange,
        onRender: () => [{ text: "embedded query" }]
      },
      { mode: "workspace", host }
    )

    expect(isPaletteOpen()).toBe(false)
    expect(host.querySelector('[role="region"]')).toBeTruthy()
    expect(
      host.querySelector('button[aria-label="Close query palette"]')
    ).toBeNull()
    expect(rows()).toHaveLength(entries.length)
    expect(host.textContent).toContain("embedded query")
    expect(
      [...host.querySelectorAll("button")].some(
        (button) => button.textContent === "Copy query"
      )
    ).toBe(true)
    expect(host.querySelector("details")?.open).toBe(false)
    expect(
      [...host.querySelectorAll("[data-socx-query-section]")].map((section) =>
        section.getAttribute("data-socx-query-section")
      )
    ).toEqual(["templates", "indicators", "preview"])

    const workspaceGuide = host.querySelector(
      'details[data-socx-language-guide="true"]'
    ) as HTMLDetailsElement
    const workspaceGuideDialect = workspaceGuide.querySelector(
      'select[aria-label="Filter guide by language and product"]'
    ) as HTMLSelectElement
    expect(workspaceGuideDialect.value).toBe("all")
    workspaceGuide.open = true
    workspaceGuide.dispatchEvent(new Event("toggle"))
    const workspaceGuideContent = workspaceGuide.querySelector(
      '[data-socx-language-guide-content="true"]'
    ) as HTMLElement
    expect(workspaceGuideContent.style.position).toBe("static")
    expect(workspaceGuideContent.style.overflowY).toBe("visible")
    expect(
      host.querySelector('[data-socx-query-section="templates"]')?.parentElement
        ?.style.display
    ).toBe("grid")

    const field = indicatorField()
    expect(field.classList.contains("socx-query-scroll")).toBe(true)
    expect(field.style.overflowY).toBe("auto")
    expect(field.style.resize).toBe("none")
    field.value = "1.1.1.1"
    field.dispatchEvent(new Event("input", { bubbles: true }))
    expect(onIndicatorTextChange).toHaveBeenCalledWith("1.1.1.1")

    cleanup()
    expect(host.childElementCount).toBe(0)
  })

  it("uses the workspace theme stored on the body", () => {
    document.body.classList.add("dark-mode")
    const host = document.createElement("div")
    document.body.appendChild(host)

    const cleanup = mountQueryView(
      {
        entries,
        dialects: bundledDialectMap(),
        onRender: () => [{ text: "dark query" }]
      },
      { mode: "workspace", host }
    )

    const search = host.querySelector(
      'input[aria-label="Search queries"]'
    ) as HTMLInputElement
    const indicators = host.querySelector(
      'textarea[aria-label="Indicators used by the query"]'
    ) as HTMLTextAreaElement

    expect(search.style.color).toBe("#ffffff")
    expect(indicators.style.color).toBe("#ffffff")
    expect(indicators.style.backgroundColor).toBe("rgba(22, 31, 50, 0.60)")

    cleanup()
  })

  it("narrows the list from a value that only appears inside the query", () => {
    open()
    const field = searchField()
    field.value = "IdentityLogonEvents"
    field.dispatchEvent(new Event("input", { bubbles: true }))
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toContain("Failed logons")
  })

  it("keeps every filter on screen whatever is selected", () => {
    open()
    chip("SPL")!.click()
    // The other language, the category filter and the custom facet are all
    // still there after narrowing the list.
    expect(chip("KQL")).toBeTruthy()
    expect(
      document.querySelector('select[aria-label="Filter by category"]')
    ).toBeTruthy()
    expect(
      document.querySelector('select[aria-label="Filter by Customer"]')
    ).toBeTruthy()
  })

  it("filters by language from the chip row", () => {
    open()
    chip("SPL")!.click()
    expect(rows()).toHaveLength(2)
    expect(rows().join(" ")).toContain("Proxy hits")
    expect(rows().join(" ")).not.toContain("Failed logons")
  })

  it("exposes a filter for a dimension the repository declared", () => {
    open()
    const select = document.querySelector(
      'select[aria-label="Filter by Customer"]'
    ) as HTMLSelectElement
    expect(select).toBeTruthy()
    select.value = "ACME"
    select.dispatchEvent(new Event("change", { bubbles: true }))
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toContain("Proxy hits")
  })

  it("starts from the source and language recognized for the platform", () => {
    const splunkEntry = entries.find((entry) => entry.pack.name === "Splunk")!
    open({
      initialSourceKey: entrySourceKey(splunkEntry),
      initialDialect: "spl"
    })

    const select = document.querySelector(
      'select[aria-label="Filter by query source"]'
    ) as HTMLSelectElement
    expect(select.value).toBe(entrySourceKey(splunkEntry))
    expect(rows()).toHaveLength(2)
    expect(rows().every((row) => /Proxy hits|VPN sessions/.test(row))).toBe(
      true
    )
  })

  it("keeps the language guide inside the shared palette", async () => {
    open({ dialects: bundledDialectMap() })
    const guide = document.querySelector(
      'details[data-socx-language-guide="true"]'
    ) as HTMLDetailsElement
    expect(guide).toBeTruthy()
    expect(guide.closest('[role="dialog"]')).toBeTruthy()
    expect(guide.open).toBe(false)
    expect(
      (
        guide.querySelector(
          'select[aria-label="Filter guide by language and product"]'
        ) as HTMLSelectElement
      ).value
    ).toBe("all")

    guide.open = true
    guide.dispatchEvent(new Event("toggle"))
    await Promise.resolve()

    const guideContent = guide.querySelector(
      '[data-socx-language-guide-content="true"]'
    ) as HTMLElement
    expect(guide.style.flex).toBe("1 1 0%")
    expect(guide.style.minHeight).toBe("0")
    expect(
      (guide.closest('[role="dialog"]') as HTMLElement).style.height
    ).toBe("720px")
    expect(guideContent.style.position).toBe("absolute")
    expect(guideContent.style.bottom).toBe("0px")
    expect(guideContent.style.overflowY).toBe("auto")
    expect(
      guide.querySelector('input[aria-label="Search query language guides"]')
    ).toBeTruthy()
    expect(guide.textContent).toContain("Main fields")
    expect(guide.textContent).toContain("Commands and operators")
    const officialLink = guide.querySelector(
      'a[target="_blank"]'
    ) as HTMLAnchorElement
    expect(officialLink?.rel).toContain("noreferrer")
  })

  it("filters the palette guide for a recognised console only", () => {
    open({
      dialects: bundledDialectMap(),
      initialDialect: "spl",
      platformLabel: "Splunk"
    })

    const guideDialect = document.querySelector(
      'select[aria-label="Filter guide by language and product"]'
    ) as HTMLSelectElement
    expect(guideDialect.value).toBe("spl")
  })

  it("stars a query, reports it, and lists it first", () => {
    const onToggleFavorite = vi.fn()
    open({ onToggleFavorite })

    const target = entries.find((entry) => entry.template.id === "proxy")!
    const index = rows().findIndex((row) => row.includes("Proxy hits"))
    const star = document
      .querySelectorAll('[role="option"]')
      [index].querySelector("button") as HTMLButtonElement
    star.click()

    expect(onToggleFavorite).toHaveBeenCalledWith(target.key, [target.key])
    expect(rows()[0]).toContain("Proxy hits")
    expect(document.body.textContent).toContain("Favorites")
  })

  it("shows the indicators it was given and lets them be edited", () => {
    const describeIndicators = vi.fn(
      (text: string) => `${text.split(/\s+/).filter(Boolean).length} values`
    )
    open({ indicatorHint: ["8.8.8.8", "1.1.1.1"], describeIndicators })

    const field = indicatorField()
    expect(field.value).toBe(["8.8.8.8", "1.1.1.1"].join("\n"))
    expect(document.body.textContent).toContain("2 values")
    // What the field holds is what gets rendered into the query.
    expect(document.body.textContent).toContain("rendered with [8.8.8.8")

    field.value = "9.9.9.9"
    field.dispatchEvent(new Event("input", { bubbles: true }))
    expect(document.body.textContent).toContain("rendered with [9.9.9.9]")
    expect(document.body.textContent).toContain("1 values")
  })

  it("merges the types by default and can be switched to one query per type", () => {
    const onMergeTypesChange = vi.fn()
    open({ indicatorHint: ["8.8.8.8"], onMergeTypesChange })
    expect(document.body.textContent).toContain("merge=true")

    const toggle = chip("Single query")!
    toggle.click()
    expect(onMergeTypesChange).toHaveBeenCalledWith(false)
    expect(document.body.textContent).toContain("merge=false")
    expect(chip("One per type")).toBeTruthy()
  })

  it("hides the indicator list for a query that reads no indicator", () => {
    const hunting = makePack({
      id: "hunting-pack",
      kind: "standard",
      name: "Hunting",
      templates: [
        {
          id: "encoded",
          name: "Encoded PowerShell",
          group: "network",
          requiresIocs: false,
          body: "DeviceProcessEvents | where ProcessCommandLine has '-enc'"
        }
      ]
    })
    const huntingEntries = entriesFromTree(
      buildGroupTree([{ ...hunting, sourceId: "h" }])
    )
    openPalette({
      entries: huntingEntries,
      indicatorHint: ["8.8.8.8"],
      onRender: () => [{ text: "hunting query" }]
    } as never)

    expect((indicatorField().parentElement as HTMLElement).style.display).toBe(
      "none"
    )

    // ...while an indicator template keeps it.
    open()
    expect(
      (indicatorField().parentElement as HTMLElement).style.display
    ).not.toBe("none")
  })

  it("lets Enter add a line in the indicator field instead of inserting", () => {
    open()
    // Dispatched from the field, the way a real keystroke reaches the capture
    // phase listener the palette installs on the document.
    indicatorField().dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true })
    )
    expect(isPaletteOpen()).toBe(true)
  })

  it("opens on the template the caller asked for", () => {
    const favorite = entries.find((entry) => entry.template.id === "proxy")!
    const requested = entries.find((entry) => entry.template.id === "logons")!
    open({ favorites: [favorite.key], initialKey: requested.key })
    const selected = document.querySelector(
      '[role="option"][aria-selected="true"]'
    )
    expect(selected?.textContent).toContain("Failed logons")
  })
})
