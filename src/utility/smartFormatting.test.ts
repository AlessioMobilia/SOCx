import { describe, expect, it } from "vitest"

import {
  captureSmartSelection,
  formatSmartContainer,
  formatSmartSelection,
  formatSmartSelectionSnapshot
} from "./smartFormatting"

const fromHtml = (html: string): HTMLElement => {
  const container = document.createElement("div")
  container.innerHTML = html
  return container
}

const setRect = (
  element: HTMLElement,
  left: number,
  top: number,
  width: number,
  height: number = 18
) => {
  element.getBoundingClientRect = () =>
    ({
      x: left,
      y: top,
      left,
      top,
      right: left + width,
      bottom: top + height,
      width,
      height,
      toJSON: () => ({})
    }) as DOMRect
}

const selectContents = (element: Element): Selection => {
  const range = document.createRange()
  range.selectNodeContents(element)
  const selection = window.getSelection()!
  selection.removeAllRanges()
  selection.addRange(range)
  return selection
}

describe("smart formatting", () => {
  it("preserves meaningful whitespace inside JSON string values", () => {
    const result = formatSmartContainer(
      fromHtml('<pre>{"message":"keep   these spaces","score":7}</pre>')
    )

    expect(result?.kind).toBe("json")
    expect(result?.text).toContain('"message": "keep   these spaces"')
  })

  it("recovers a partial JSON object with encoded indentation and missing braces", () => {
    const source = document.createElement("pre")
    source.textContent = [
      '&#x20; "ip": "73.115.85.232",',
      '&#x20; "geo": {',
      '&#x20;   "city": "Houston",',
      '&#x20;   "region": "Texas",',
      '&#x20;   "region\\_code": "TX",',
      '&#x20;   "latitude": 29.76328,'
    ].join("\n")

    const result = formatSmartContainer(source)

    expect(result?.kind).toBe("partial-json")
    expect(result?.text).toBe(
      [
        "```json",
        "{",
        '  "ip": "73.115.85.232",',
        '  "geo": {',
        '    "city": "Houston",',
        '    "region": "Texas",',
        '    "region_code": "TX",',
        '    "latitude": 29.76328',
        "  }",
        "}",
        "```"
      ].join("\n")
    )
  })

  it("normalizes padded partial JSON fields and copied comma markers", () => {
    const result = formatSmartContainer(
      fromHtml(`<pre>
        " ip ": " 73.115.85.232 " *,*
        " geo ": {
        " city ": " Houston " *,*
        " country_code ": " US " *,*
        " pattern ": " a*,*b " *,*
        " latitude ": 29.76328 ,
      </pre>`)
    )

    expect(result?.kind).toBe("partial-json")
    expect(result?.text).toContain('"ip": "73.115.85.232"')
    expect(result?.text).toContain('"city": "Houston"')
    expect(result?.text).toContain('"country_code": "US"')
    expect(result?.text).toContain('"pattern": "a*,*b"')
    expect(result?.text).toContain('"latitude": 29.76328')
  })

  it("closes an unfinished array inside a partial object", () => {
    const result = formatSmartContainer(
      fromHtml('<pre>"host": "edge-01",\n"ports": [80, 443,</pre>')
    )

    expect(result?.kind).toBe("partial-json")
    expect(result?.text).toContain('"ports": [\n    80,\n    443\n  ]')
  })

  it("does not classify property-like prose as partial JSON", () => {
    const result = formatSmartContainer(
      fromHtml('<pre>Analyst note\n"message": not actually JSON</pre>')
    )

    expect(result?.kind).not.toBe("partial-json")
  })

  it("formats explicit EDR key/value rows without splitting URLs, IPv6 or timestamps", () => {
    const result = formatSmartContainer(
      fromHtml(
        "Device name: WS-FIN-023<br>Process: WINWORD.EXE<br>URL: https://example.test/a:b<br>IPv6: 2001:db8::1<br>Time: 12:45:20"
      )
    )

    expect(result?.kind).toBe("text-key-value")
    expect(result?.text).toContain("Device name: WS-FIN-023")
    expect(result?.text).toContain("URL:         https://example.test/a:b")
    expect(result?.text).toContain("IPv6:        2001:db8::1")
    expect(result?.text).toContain("Time:        12:45:20")
  })

  it("parses alternating key and value lines copied without punctuation", () => {
    const result = formatSmartContainer(
      fromHtml(`<pre>Network
23.34.4.0/22
Autonomous System Number
20940
Autonomous System Label
Akamai International B.V.
Regional Internet Registry
ARIN
Country
US
Continent
NA</pre>`)
    )

    expect(result?.kind).toBe("text-key-value")
    expect(result?.text).toContain("Network:                    23.34.4.0/22")
    expect(result?.text).toContain(
      "Autonomous System Label:    Akamai International B.V."
    )
    expect(result?.text).toContain("Continent:                  NA")
  })

  it("does not alternate ordinary heading and paragraph prose", () => {
    const result = formatSmartContainer(
      fromHtml(`<article>First finding
The analyst reviewed the original alert.
Next action
The team isolated the affected device.
Final note
The investigation remains open.</article>`)
    )

    expect(result).toBeNull()
  })

  it("uses contextual headers for a grid selection whose header was clipped", () => {
    const result = formatSmartContainer(
      fromHtml(`
        <div role="grid">
          <div role="row">
            <span role="gridcell" aria-colindex="1">WS-FIN-023</span>
            <span role="gridcell" aria-colindex="2">WINWORD.EXE</span>
            <span role="gridcell" aria-colindex="3">8f12a40c</span>
            <span role="gridcell" aria-colindex="4">High</span>
          </div>
        </div>
      `),
      ["Device", "Process", "SHA256", "Severity"]
    )

    expect(result?.kind).toBe("semantic-table")
    expect(result?.text).toBe(
      [
        "| Device | Process | SHA256 | Severity |",
        "| --- | --- | --- | --- |",
        "| WS-FIN-023 | WINWORD.EXE | 8f12a40c | High |"
      ].join("\n")
    )
  })

  it("keeps empty cells aligned and uses honest generic headers", () => {
    const result = formatSmartContainer(
      fromHtml(`
        <table>
          <tr><td>host-1</td><td></td><td>High</td></tr>
          <tr><td>host-2</td><td>powershell.exe</td><td>Medium</td></tr>
        </table>
      `)
    )

    expect(result?.text).toContain("| Column 1 | Column 2 | Column 3 |")
    expect(result?.text).toContain("| host-1 |  | High |")
  })

  it("recognizes clipped row fragments even without their table wrapper", () => {
    const result = formatSmartContainer(
      fromHtml(
        '<div role="row"><span role="gridcell">host-23</span><span role="gridcell">WINWORD.EXE</span><span role="gridcell">High</span></div>'
      ),
      ["Device", "Process", "Severity"]
    )

    expect(result?.kind).toBe("semantic-table")
    expect(result?.text).toContain("| Device | Process | Severity |")
    expect(result?.text).toContain("| host-23 | WINWORD.EXE | High |")
  })

  it("parses quoted logfmt values", () => {
    const result = formatSmartContainer(
      fromHtml(
        '<pre>src=10.0.0.5 dst=203.0.113.20 user=jdoe msg="PowerShell execution blocked"</pre>'
      )
    )

    expect(result?.kind).toBe("logfmt")
    expect(result?.text).toContain("src:  10.0.0.5")
    expect(result?.text).toContain("msg:  PowerShell execution blocked")
  })

  it("detects TSV tables without discarding delimiters", () => {
    const result = formatSmartContainer(
      fromHtml(
        "<pre>Device\tProcess\tSeverity\nhost-23\tWINWORD.EXE\tHigh</pre>"
      )
    )

    expect(result?.kind).toBe("delimited-table")
    expect(result?.text).toContain("| Device | Process | Severity |")
    expect(result?.text).toContain("| host-23 | WINWORD.EXE | High |")
  })

  it("parses CEF headers and extension fields", () => {
    const result = formatSmartContainer(
      fromHtml(
        "<code>CEF:0|Example|EDR|1.0|42|Suspicious execution|8|src=10.0.0.5 action=blocked</code>"
      )
    )

    expect(result?.kind).toBe("cef")
    expect(result?.text).toContain("Vendor:       Example")
    expect(result?.text).toContain("Severity:     8")
    expect(result?.text).toContain("action:       blocked")
  })

  it("supports escaped CEF pipes and unquoted extension values with spaces", () => {
    const result = formatSmartContainer(
      fromHtml(
        "<code>CEF:0|Example|EDR|1.0|42|Suspicious \\| execution|8|src=10.0.0.5 msg=PowerShell execution blocked action=blocked</code>"
      )
    )

    expect(result?.text).toContain("Event:        Suspicious | execution")
    expect(result?.text).toContain("msg:          PowerShell execution blocked")
  })

  it("reads headers from the original table when only data cells are selected", () => {
    document.body.innerHTML = `
      <table>
        <thead><tr><th>Device</th><th>Severity</th></tr></thead>
        <tbody><tr><td id="start">host-23</td><td id="end">High</td></tr></tbody>
      </table>
    `
    const range = document.createRange()
    range.setStart(document.getElementById("start")!.firstChild!, 0)
    range.setEnd(document.getElementById("end")!.firstChild!, 4)
    const selection = window.getSelection()!
    selection.removeAllRanges()
    selection.addRange(range)

    const result = formatSmartSelection(selection)
    expect(result?.text).toContain("| Device | Severity |")
    expect(result?.text).toContain("| host-23 | High |")
  })

  it("formats stacked visual fields from an immutable snapshot", () => {
    document.body.innerHTML = `
      <div id="visual-root">
        <div id="host-label" class="field-label">Host</div>
        <div id="host-value">pc-01</div>
        <div id="user-label" class="field-label">User</div>
        <div id="user-value">alice</div>
      </div>
    `
    setRect(document.getElementById("host-label")!, 100, 100, 70)
    setRect(document.getElementById("host-value")!, 100, 124, 90)
    setRect(document.getElementById("user-label")!, 100, 165, 70)
    setRect(document.getElementById("user-value")!, 100, 189, 90)
    const root = document.getElementById("visual-root")!
    const snapshot = captureSmartSelection(selectContents(root))!

    document.getElementById("host-value")!.textContent = "mutated-host"
    root.insertAdjacentHTML(
      "beforeend",
      '<div role="tooltip">Late tooltip</div>'
    )

    const result = formatSmartSelectionSnapshot(snapshot)
    expect(result?.kind).toBe("visual-key-value")
    expect(result?.text).toBe("Host: pc-01\nUser: alice")
  })

  it("does not prefer internal raw state over rendered selected fields", () => {
    document.body.innerHTML = `
      <div id="raw-root" data-raw='{"origin":"widget","html":"<div class=tooltip>Help</div>"}'>
        <strong id="raw-label">Host</strong>
        <span id="raw-value">pc-01</span>
      </div>
    `
    setRect(document.getElementById("raw-label")!, 100, 100, 60)
    setRect(document.getElementById("raw-value")!, 240, 100, 80)
    const snapshot = captureSmartSelection(
      selectContents(document.getElementById("raw-root")!)
    )!

    const result = formatSmartSelectionSnapshot(snapshot)
    expect(result?.kind).toBe("visual-key-value")
    expect(result?.text).toBe("Host: pc-01")
    expect(result?.text).not.toContain("origin")
    expect(result?.text).not.toContain("tooltip")
  })

  it("uses an explicit label above a value selected on its own", () => {
    document.body.innerHTML = `
      <div>
        <div class="field-label">Host</div>
        <div id="only-value">pc-01</div>
      </div>
    `
    setRect(document.querySelector(".field-label")!, 100, 100, 70)
    setRect(document.getElementById("only-value")!, 100, 126, 90)

    const result = formatSmartSelection(
      selectContents(document.getElementById("only-value")!)
    )
    expect(result?.kind).toBe("visual-key-value")
    expect(result?.text).toBe("Host: pc-01")
  })

  it("uses aria-labelledby without copying the surrounding widget", () => {
    document.body.innerHTML = `
      <div>
        <span id="host-name">Host</span>
        <div id="aria-value" aria-labelledby="host-name">pc-01</div>
        <div role="tooltip">Internal help</div>
      </div>
    `
    setRect(document.getElementById("aria-value")!, 100, 126, 90)

    const result = formatSmartSelection(
      selectContents(document.getElementById("aria-value")!)
    )
    expect(result?.text).toBe("Host: pc-01")
    expect(result?.text).not.toContain("Internal help")
  })

  it("does not use an unrelated preceding heading as contextual metadata", () => {
    document.body.innerHTML = `
      <article>
        <strong>Investigation summary</strong>
        <p id="summary-value">The user opened a suspicious attachment.</p>
      </article>
    `
    setRect(document.getElementById("summary-value")!, 100, 126, 420)

    const result = formatSmartSelection(
      selectContents(document.getElementById("summary-value")!)
    )
    expect(result).toBeNull()
  })

  it("excludes CSS-hidden tooltip text from selected table cells", () => {
    document.head.innerHTML = "<style>.css-hidden { display: none; }</style>"
    document.body.innerHTML = `
      <table>
        <thead><tr><th>Field</th><th>Value</th></tr></thead>
        <tbody><tr><td id="field">Host</td><td id="value">pc-01<span class="css-hidden">Internal help</span></td></tr></tbody>
      </table>
    `
    const range = document.createRange()
    range.setStart(document.getElementById("field")!.firstChild!, 0)
    range.setEnd(document.getElementById("value")!.firstChild!, 5)
    const selection = window.getSelection()!
    selection.removeAllRanges()
    selection.addRange(range)

    const result = formatSmartSelection(selection)
    expect(result?.text).toContain("pc-01")
    expect(result?.text).not.toContain("Internal help")
  })
})
