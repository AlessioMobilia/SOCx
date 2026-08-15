import type { ResolvedServicePage } from "./servicePageAdapters"
import {
  normalizeServiceText,
  parseServicePage,
  type ServiceIntelField
} from "./servicePageParsers"

export type { ServiceIntelField } from "./servicePageParsers"
export { normalizeServiceText } from "./servicePageParsers"

const INTERSTITIAL_SELECTORS = [
  "script[src*='/cdn-cgi/challenge-platform/']",
  "iframe[src*='challenges.cloudflare.com']",
  "#challenge-running",
  "#challenge-stage",
  ".cf-turnstile",
  "[name='cf-turnstile-response']"
].join(",")

const INTERSTITIAL_PATTERN =
  /(?:just a moment|checking your browser|verify you are human|confirm that you are not a robot|security verification|security check|esecuzione della verifica di sicurezza|servizio di sicurezza|protezione dai bot|vérification de sécurité|überprüfung der sicherheit|comprobación de seguridad|verificação de segurança)/i

export const isServicePageReady = (
  rootDocument: Document = document
): boolean => {
  if (rootDocument.querySelector(INTERSTITIAL_SELECTORS)) return false
  const bodyText =
    rootDocument.body?.innerText || rootDocument.body?.textContent || ""
  const pageSignal = `${rootDocument.title}\n${bodyText.slice(0, 1_500)}`
  return !INTERSTITIAL_PATTERN.test(pageSignal)
}

export const extractServicePageFields = (
  page: ResolvedServicePage,
  rootDocument: Document = document
): ServiceIntelField[] =>
  isServicePageReady(rootDocument) ? parseServicePage(page, rootDocument) : []

export const formatServicePageReport = ({
  page,
  fields
}: {
  page: ResolvedServicePage
  fields: ServiceIntelField[]
}): string => {
  const hasIoc = fields.some(({ label }) => /^(?:ioc|ip)$/i.test(label))
  const reportFields = hasIoc
    ? fields
    : [{ label: "IOC", value: page.ioc }, ...fields]
  const labels = reportFields.map(({ label }) => `${label}:`)
  const width = Math.max(0, ...labels.map((label) => label.length))

  return [
    page.adapter.label,
    ...reportFields.map(
      ({ value }, index) => `- ${labels[index].padEnd(width, " ")} ${value}`
    )
  ].join("\n")
}
