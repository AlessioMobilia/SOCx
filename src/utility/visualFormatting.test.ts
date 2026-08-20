import { beforeEach, describe, expect, it } from "vitest"

import {
  buildVisualCandidate,
  captureVisualSelection,
  readRenderedElementText
} from "./visualFormatting"

const makeRect = (
  left: number,
  top: number,
  width: number,
  height: number = 18
): DOMRect =>
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

const mount = (html: string): HTMLElement => {
  document.body.innerHTML = html
  const root = document.getElementById("root")!
  root.querySelectorAll<HTMLElement>("[data-rect]").forEach((element) => {
    const [left, top, width, height = 18] = element.dataset
      .rect!.split(",")
      .map(Number)
    element.getBoundingClientRect = () => makeRect(left, top, width, height)
  })
  return root
}

const select = (element: Element): Selection => {
  const range = document.createRange()
  range.selectNodeContents(element)
  const selection = window.getSelection()!
  selection.removeAllRanges()
  selection.addRange(range)
  return selection
}

const format = (root: HTMLElement) => {
  const snapshot = captureVisualSelection(select(root))
  expect(snapshot).not.toBeNull()
  return buildVisualCandidate(snapshot!)
}

describe("visual structural formatting", () => {
  beforeEach(() => {
    document.head.innerHTML = ""
    document.body.innerHTML = ""
  })

  it("pairs keys and values placed on the same visual row", () => {
    const result = format(
      mount(`
        <div id="root">
          <div><strong data-rect="100,100,50">Host</strong><span data-rect="260,100,70">pc-01</span></div>
          <div><strong data-rect="100,130,50">User</strong><span data-rect="260,130,70">alice</span></div>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([
      ["Host", "pc-01"],
      ["User", "alice"]
    ])
    expect(result?.coverage).toBe(1)
  })

  it("keeps nested label fragments as one logical key", () => {
    const result = format(
      mount(`
        <div id="root">
          <label><span data-rect="100,100,55">Device</span> <span data-rect="158,100,45">name</span></label>
          <span data-rect="260,100,95">WS-FIN-023</span>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([["Device name", "WS-FIN-023"]])
  })

  it("pairs labelled fields placed above their values", () => {
    const result = format(
      mount(`
        <div id="root">
          <div class="field-label" data-rect="100,100,60">Host</div>
          <div data-rect="100,124,80">pc-01</div>
          <div class="field-label" data-rect="100,165,60">User</div>
          <div data-rect="100,189,80">alice</div>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([
      ["Host", "pc-01"],
      ["User", "alice"]
    ])
  })

  it("infers a repeated unmarked vertical key/value pattern", () => {
    const result = format(
      mount(`
        <div id="root">
          <div data-rect="100,100,60">Host</div>
          <div data-rect="100,124,80">pc-01</div>
          <div data-rect="100,165,60">User</div>
          <div data-rect="100,189,80">alice</div>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([
      ["Host", "pc-01"],
      ["User", "alice"]
    ])
  })

  it("matches a row of labels to the values directly below each column", () => {
    const result = format(
      mount(`
        <div id="root">
          <span data-rect="100,100,70">Host</span>
          <span data-rect="300,100,70">Severity</span>
          <span data-rect="100,126,90">pc-01</span>
          <span data-rect="300,126,90">High</span>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([
      ["Host", "pc-01"],
      ["Severity", "High"]
    ])
  })

  it("keeps multiline values together until the next strong label", () => {
    const result = format(
      mount(`
        <div id="root">
          <div class="field-label" data-rect="100,100,100">Description</div>
          <div data-rect="100,124,240">PowerShell execution detected</div>
          <div data-rect="100,146,220">on workstation FIN-023</div>
          <div class="field-label" data-rect="100,185,100">Severity</div>
          <div data-rect="100,209,80">High</div>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([
      ["Description", "PowerShell execution detected on workstation FIN-023"],
      ["Severity", "High"]
    ])
  })

  it("does not reinterpret a lone emphasized heading and paragraph", () => {
    const result = format(
      mount(`
        <article id="root">
          <strong data-rect="100,100,180">Investigation summary</strong>
          <p data-rect="100,126,420">The user opened a suspicious attachment during the morning.</p>
        </article>
      `)
    )

    expect(result).toBeNull()
  })

  it("accepts a single vertical pair when the label is explicit", () => {
    const result = format(
      mount(`
        <div id="root">
          <label data-rect="100,100,80">Host</label>
          <div data-rect="100,126,100">pc-01</div>
        </div>
      `)
    )

    expect(result?.pairs).toEqual([["Host", "pc-01"]])
  })

  it("ignores tooltip text and hidden descendants", () => {
    document.head.innerHTML = "<style>.css-hidden { display: none; }</style>"
    const root = mount(`
      <div id="root">
        <strong data-rect="100,100,50">Host</strong>
        <span data-rect="260,100,70">pc-01</span>
        <div role="tooltip" data-rect="260,122,140">Internal help</div>
        <div class="css-hidden" data-rect="260,144,140">Hidden metadata</div>
      </div>
    `)
    const snapshot = captureVisualSelection(select(root))!

    expect(snapshot.tokens.map((token) => token.text)).toEqual([
      "Host",
      "pc-01"
    ])
    expect(buildVisualCandidate(snapshot)?.pairs).toEqual([["Host", "pc-01"]])
  })

  it("never treats raw attributes as selected values", () => {
    const root = mount(`
      <div id="root" data-raw='{"origin":"widget","html":"<div>Help</div>"}'>
        <strong data-rect="100,100,50">Host</strong>
        <span data-rect="260,100,70">pc-01</span>
      </div>
    `)
    const snapshot = captureVisualSelection(select(root))!

    expect(snapshot.tokens.map((token) => token.text)).toEqual([
      "Host",
      "pc-01"
    ])
    expect(buildVisualCandidate(snapshot)?.pairs).toEqual([["Host", "pc-01"]])
  })

  it("reads rendered element text without controls or semantic tooltips", () => {
    const root = mount(`
      <div id="root">
        <span>pc-01</span>
        <button data-testid="copyValueButton">Copy</button>
        <div role="tooltip">Internal help</div>
        <span hidden>Hidden metadata</span>
        <span style="position:absolute;overflow:hidden;width:1px;height:1px">Screen reader duplicate</span>
      </div>
    `)

    expect(readRenderedElementText(root)).toBe("pc-01")
  })
})
