import { describe, expect, it } from "vitest"

import { formatSmartContainer, formatSmartSelection } from "./smartFormatting"

const fromHtml = (html: string): HTMLElement => {
  const container = document.createElement("div")
  container.innerHTML = html
  return container
}

describe("smart formatting", () => {
  it("preserves meaningful whitespace inside JSON string values", () => {
    const result = formatSmartContainer(
      fromHtml('<pre>{"message":"keep   these spaces","score":7}</pre>')
    )

    expect(result?.kind).toBe("json")
    expect(result?.text).toContain('"message": "keep   these spaces"')
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
      fromHtml("<pre>Device\tProcess\tSeverity\nhost-23\tWINWORD.EXE\tHigh</pre>")
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
})
