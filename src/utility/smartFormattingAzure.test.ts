import { describe, expect, it } from "vitest"

import {
  captureSmartSelection,
  formatSmartContainer,
  formatSmartSelectionSnapshot
} from "./smartFormatting"

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

const setRect = (
  element: Element | null,
  left: number,
  top: number,
  width: number
) => {
  if (element instanceof HTMLElement) {
    element.getBoundingClientRect = () => rect(left, top, width)
  }
}

const selectContents = (element: Element): Selection => {
  const range = document.createRange()
  range.selectNodeContents(element)
  const selection = window.getSelection()!
  selection.removeAllRanges()
  selection.addRange(range)
  return selection
}

const positionRows = (root: Element) => {
  root
    .querySelectorAll<HTMLElement>("[data-field-row]")
    .forEach((row, index) => {
      const top = 100 + index * 28
      setRect(row.querySelector("label"), 100, top, 260)
      setRect(row.querySelector("[data-field-value]"), 400, top, 360)
      setRect(row.querySelector("button"), 400, top, 100)
    })
}

describe("Azure identity smart formatting", () => {
  it("formats a rendered Entra ID identity group with empty fields", () => {
    document.body.innerHTML = `
      <section id="entra-identity">
        <h3>Identità <button aria-label="Edit identity">Modifica</button></h3>
        <div data-field-row><label for="display-name">Nome visualizzato</label><div id="display-name"><span data-field-value>account-01</span></div></div>
        <div data-field-row><label for="principal-name">Nome dell'entità utente</label><div id="principal-name"><span data-field-value>identity-01@example.test</span><button aria-label="Copy principal name">Copia</button></div></div>
        <div data-field-row><label for="object-id">ID oggetto</label><div id="object-id"><span data-field-value>00000000-0000-4000-8000-000000000001</span></div></div>
        <div data-field-row><label for="created-at">Data e ora di creazione</label><div id="created-at"><span data-field-value>6 apr 2026, 20:56</span></div></div>
        <div data-field-row><label for="sign-in-identifiers">Identificatori di accesso</label><div id="sign-in-identifiers"></div></div>
        <div data-field-row><label for="creation-type">Tipo di creazione</label><div id="creation-type"></div></div>
        <div data-field-row><label for="assigned-licenses">Licenze assegnate</label><div id="assigned-licenses"><button>Visualizza</button></div></div>
        <div data-field-row><label for="preferred-language">Lingua preferita</label><div id="preferred-language"></div></div>
        <div data-field-row><label for="invitation-state">Stato invito</label><div id="invitation-state"></div></div>
        <div data-field-row><label for="authorization-info">Informazioni autorizzazione</label><div id="authorization-info"><button>Visualizza</button></div></div>
      </section>
    `
    const root = document.getElementById("entra-identity")!
    setRect(root.querySelector("h3"), 100, 60, 160)
    positionRows(root)

    const snapshot = captureSmartSelection(selectContents(root))!
    const result = formatSmartSelectionSnapshot(snapshot)

    expect(snapshot.visual?.geometryAvailable).toBe(true)
    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toBe(
      [
        "Nome visualizzato:       account-01",
        "Nome dell'entità utente: identity-01@example.test",
        "ID oggetto:              00000000-0000-4000-8000-000000000001",
        "Data e ora di creazione: 6 apr 2026, 20:56"
      ].join("\n")
    )
    expect(result?.text).not.toContain("Visualizza")
    expect(result?.text).not.toContain("Tipo di creazione")
  })

  it("formats rendered Sentinel user information with sparse values", () => {
    const fields = [
      ["Data", ""],
      ["ID richiesta", "00000000-0000-4000-8000-000000000002"],
      ["ID correlazione", ""],
      ["Requisito per l'autenticazione", ""],
      ["Stato", "Operazione riuscita"],
      ["Codice errore di accesso", ""],
      ["Motivo dell'errore", ""],
      ["Utente", "identity-01@example.test"],
      ["ID utente", ""],
      ["ID sessione", ""],
      ["Tipo di utente", ""],
      ["Agente utente", ""]
    ]
    document.body.innerHTML = `
      <section id="sentinel-user-info" role="tabpanel">
        <h3>Info di base</h3>
        ${fields
          .map(
            ([label, value], index) => `
              <div data-field-row data-formelement="pcControl">
                <div class="form-label-container">
                  <label for="field-${index}-anchor">${label}</label>
                  <div id="field-${index}-anchor" role="button" aria-label="${label}"></div>
                </div>
                <div class="form-value-container">${
                  value ? `<div data-field-value>${value}</div>` : ""
                }</div>
              </div>`
          )
          .join("")}
      </section>
    `
    const root = document.getElementById("sentinel-user-info")!
    setRect(root.querySelector("h3"), 100, 60, 160)
    positionRows(root)

    const result = formatSmartSelectionSnapshot(
      captureSmartSelection(selectContents(root))!
    )

    expect(result?.kind).toBe("semantic-key-value")
    expect(result?.text).toBe(
      [
        "ID richiesta: 00000000-0000-4000-8000-000000000002",
        "Stato:        Operazione riuscita",
        "Utente:       identity-01@example.test"
      ].join("\n")
    )
    expect(result?.text).not.toContain("ID correlazione")
    expect(result?.text).not.toContain("Agente utente")
  })

  it("does not interpret a clock colon as a key/value separator", () => {
    const root = document.createElement("pre")
    root.textContent = "Creazione completata il 6 apr 2026, 20:56"

    expect(formatSmartContainer(root)).toBeNull()
  })
})
