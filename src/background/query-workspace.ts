export const QUERY_WORKSPACE_PATH = "tabs/query-workspace.html"

export const buildQueryWorkspaceUrl = (
  baseUrl: string,
  indicators: string[] = [],
  templateKey?: string
): string => {
  const params = new URLSearchParams()
  if (indicators.length > 0) params.set("iocs", indicators.join("\n"))
  if (templateKey) params.set("template", templateKey)
  const hash = params.toString()
  return hash ? `${baseUrl}#${hash}` : baseUrl
}

export const openQueryWorkspace = (
  indicators: string[] = [],
  templateKey?: string
): Promise<chrome.tabs.Tab> =>
  chrome.tabs.create({
    url: buildQueryWorkspaceUrl(
      chrome.runtime.getURL(QUERY_WORKSPACE_PATH),
      indicators,
      templateKey
    )
  })
