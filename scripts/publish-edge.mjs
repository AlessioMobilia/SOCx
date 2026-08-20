import { readFile } from "node:fs/promises"
import { pathToFileURL } from "node:url"

const EDGE_API = "https://api.addons.microsoftedge.microsoft.com"
const RETRYABLE_STATUS_CODES = new Set([409, 423, 429, 500, 502, 503, 504])

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds))

const readResponse = async (response) => {
  const text = await response.text()
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    return { message: text }
  }
}

const errorMessage = (action, response, body) => {
  const detail = body?.message || body?.errorCode || response.statusText
  return `${action} failed (${response.status})${detail ? `: ${detail}` : ""}`
}

const retryDelay = (response, fallbackMilliseconds) => {
  const retryAfter = Number(response.headers.get("retry-after"))
  return Number.isFinite(retryAfter) && retryAfter > 0
    ? retryAfter * 1000
    : fallbackMilliseconds
}

const operationUrl = (endpoint, location) => {
  if (/^https?:\/\//i.test(location)) return location
  if (location.startsWith("/")) return new URL(location, EDGE_API).href
  return `${endpoint}/operations/${encodeURIComponent(location)}`
}

const waitForOperation = async ({
  endpoint,
  operationId,
  headers,
  fetchImpl,
  sleepImpl,
  pollMilliseconds,
  deadline,
  action
}) => {
  const url = operationUrl(endpoint, operationId)

  while (Date.now() < deadline) {
    const response = await fetchImpl(url, { headers })
    const body = await readResponse(response)
    if (!response.ok && response.status !== 202) {
      throw new Error(errorMessage(`${action} status`, response, body))
    }

    const status = String(body.status ?? "").toLowerCase()
    if (status === "succeeded") return body
    if (status === "failed") {
      throw new Error(
        `${action} failed: ${body.message || body.errorCode || "unknown Edge error"}`
      )
    }
    if (status && status !== "inprogress") {
      throw new Error(`${action} returned unexpected status: ${body.status}`)
    }

    await sleepImpl(retryDelay(response, pollMilliseconds))
  }

  throw new Error(`${action} did not complete before the workflow deadline`)
}

/**
 * Edge reports "a submission is already in progress" in two places: as a 409 on
 * the request, which postWithRetry waits out, and as a *failed operation* after
 * the same request was accepted with 202. The second form is the one that comes
 * back while an earlier version is still in certification, and it means exactly
 * the same thing — wait, then submit the draft again — so it must not end the
 * job. Without this the long wait the workflow is configured for never engages.
 */
const SUBMISSION_IN_PROGRESS =
  /submission is in progress|already in progress|try again later/i

const postWithRetry = async ({
  url,
  headers,
  body,
  fetchImpl,
  sleepImpl,
  retryMilliseconds,
  deadline,
  action,
  log
}) => {
  while (Date.now() < deadline) {
    const response = await fetchImpl(url, { method: "POST", headers, body })
    if (response.status === 202) return response

    const responseBody = await readResponse(response)
    if (!RETRYABLE_STATUS_CODES.has(response.status)) {
      throw new Error(errorMessage(action, response, responseBody))
    }

    log(
      `::notice::${action} is waiting for the current Edge submission (${response.status}); the latest package will replace the draft when available.`
    )
    await sleepImpl(retryDelay(response, retryMilliseconds))
  }

  throw new Error(`${action} could not start before the workflow deadline`)
}

export const publishEdgeExtension = async ({
  credentials,
  filePath,
  notes = "",
  fetchImpl = fetch,
  sleepImpl = sleep,
  retryMilliseconds = 30_000,
  pollMilliseconds = 5_000,
  maxWaitMilliseconds = 330 * 60_000,
  log = console.log
}) => {
  const { productId, clientId, apiKey } = credentials ?? {}
  if (!productId || !clientId || !apiKey) {
    throw new Error(
      "SUBMIT_KEYS.edge must contain productId, clientId, and apiKey"
    )
  }

  const archive = await readFile(filePath)
  const productEndpoint = `${EDGE_API}/v1/products/${encodeURIComponent(productId)}`
  const submissionEndpoint = `${productEndpoint}/submissions`
  const uploadEndpoint = `${submissionEndpoint}/draft/package`
  const authHeaders = {
    Authorization: `ApiKey ${apiKey}`,
    "X-ClientID": clientId
  }
  const deadline = Date.now() + maxWaitMilliseconds

  log("Uploading Edge package; an existing draft package will be replaced.")
  const uploadResponse = await postWithRetry({
    url: uploadEndpoint,
    headers: { ...authHeaders, "Content-Type": "application/zip" },
    body: archive,
    fetchImpl,
    sleepImpl,
    retryMilliseconds,
    deadline,
    action: "Edge upload",
    log
  })
  const uploadOperation = uploadResponse.headers.get("location")
  if (!uploadOperation) throw new Error("Edge upload returned no operation ID")

  await waitForOperation({
    endpoint: uploadEndpoint,
    operationId: uploadOperation,
    headers: authHeaders,
    fetchImpl,
    sleepImpl,
    pollMilliseconds,
    deadline,
    action: "Edge upload"
  })

  log("Submitting the latest Edge draft for certification.")
  for (;;) {
    const publishResponse = await postWithRetry({
      url: submissionEndpoint,
      headers: { ...authHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ notes }),
      fetchImpl,
      sleepImpl,
      retryMilliseconds,
      deadline,
      action: "Edge publication",
      log
    })
    const publishOperation = publishResponse.headers.get("location")
    if (!publishOperation)
      throw new Error("Edge publication returned no operation ID")

    try {
      await waitForOperation({
        endpoint: submissionEndpoint,
        operationId: publishOperation,
        headers: authHeaders,
        fetchImpl,
        sleepImpl,
        pollMilliseconds,
        deadline,
        action: "Edge publication"
      })
      break
    } catch (error) {
      if (
        !SUBMISSION_IN_PROGRESS.test(error?.message ?? "") ||
        Date.now() >= deadline
      ) {
        throw error
      }
      log(
        "::notice::Edge is still certifying an earlier submission; the draft will be submitted again shortly."
      )
      await sleepImpl(retryMilliseconds)
    }
  }

  log("Edge accepted the latest package for certification.")
}

const isCli =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href

if (isCli) {
  const submitKeys = JSON.parse(process.env.SUBMIT_KEYS || "{}")
  await publishEdgeExtension({
    credentials: submitKeys.edge,
    filePath: process.env.EDGE_ZIP || "build/edge-mv3-prod.zip",
    notes: process.env.EDGE_NOTES || "",
    retryMilliseconds: Number(process.env.EDGE_RETRY_SECONDS || 30) * 1000,
    maxWaitMilliseconds:
      Number(process.env.EDGE_MAX_WAIT_MINUTES || 330) * 60_000
  })
}
