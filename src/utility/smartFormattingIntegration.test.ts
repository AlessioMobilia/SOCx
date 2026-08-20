import { describe, expect, it } from "vitest"

import { captureSmartSelection } from "./smartFormatting"
import { formatSelectedText } from "./utils"

const rect = (left: number, top: number, width: number): DOMRect =>
  ({
    x: left,
    y: top,
    left,
    top,
    right: left + width,
    bottom: top + 18,
    width,
    height: 18,
    toJSON: () => ({})
  }) as DOMRect

const selectRoot = (
  html: string
): { root: HTMLElement; selection: Selection } => {
  document.body.innerHTML = html
  const root = document.getElementById("root")!
  root.querySelectorAll<HTMLElement>("[data-rect]").forEach((element) => {
    const [left, top, width] = element.dataset.rect!.split(",").map(Number)
    element.getBoundingClientRect = () => rect(left, top, width)
  })
  const range = document.createRange()
  range.selectNodeContents(root)
  const selection = window.getSelection()!
  selection.removeAllRanges()
  selection.addRange(range)
  return { root, selection }
}

describe("smart formatting public selection flow", () => {
  it("copies visual fields without internal raw state", () => {
    const { selection } = selectRoot(`
      <div id="root" data-raw='{"origin":"widget","html":"<div>Help</div>"}'>
        <strong data-rect="100,100,60">Host</strong>
        <span data-rect="240,100,90">pc-01</span>
      </div>
    `)
    const snapshot = captureSmartSelection(selection)!

    expect(formatSelectedText(selection, snapshot)).toBe("Host: pc-01")
  })

  it("uses the frozen rendered text when no structured interpretation is safe", () => {
    const { root, selection } = selectRoot(`
      <article id="root">
        <strong data-rect="100,100,180">Investigation summary</strong>
        <p data-rect="100,126,420">The user opened a suspicious attachment.</p>
        <div role="tooltip" data-rect="100,150,180">Internal tooltip</div>
      </article>
    `)
    const snapshot = captureSmartSelection(selection)!
    root.textContent = "Page mutated after selection"

    expect(formatSelectedText(selection, snapshot)).toBe(
      "Investigation summary\nThe user opened a suspicious attachment."
    )
  })
})
