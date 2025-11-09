import React, { useCallback, useEffect, useMemo, useState } from "react"
import { Storage } from "@plasmohq/storage"
import { sendToBackground } from "@plasmohq/messaging"
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Container,
  Form,
  Row,
  Spinner,
  Table
} from "react-bootstrap"
import "bootstrap/dist/css/bootstrap.min.css"
import "./bulk-check.css"
import {
  NormalizedSubnet,
  SubnetCheckSummaryRow,
  estimateSubnetHostCount,
  exportSubnetCheckToExcel,
  extractSubnetsFromText,
  formatHostCount,
  formatSubnetCheckClipboard,
  isPrivateIP
} from "../utility/utils"
import { ensureIsDarkMode, persistIsDarkMode } from "../utility/theme"

type SubnetCheckResult = {
  reportedCount?: number
  data?: any
  error?: string
  isPrivate?: boolean
  ipDetails?: any
}

const storage = new Storage({ area: "local" })

const PREFILL_KEY = "subnetCheckPrefill"
const INPUT_KEY = "subnetCheckInput"
const LOOKBACK_DAYS = 30

const clampConfidenceInput = (value: number): number => {
  if (!Number.isFinite(value)) {
    return 0
  }
  const rounded = Math.round(value)
  return Math.min(Math.max(rounded, 0), 100)
}

const getTodayDateString = (): string => new Date().toISOString().split("T")[0]
const getAbuseDailyKey = (): string => `Abuse_${getTodayDateString()}`

const hasClipboardAccess = (): boolean =>
  typeof navigator !== "undefined" && Boolean(navigator.clipboard?.writeText)

const applyDocumentTheme = (isDarkMode: boolean): void => {
  if (typeof document === "undefined") {
    return
  }
  document.body.className = isDarkMode ? "dark-mode" : "light-mode"
}

const readAbuseCounter = async (): Promise<number> => {
  if (typeof chrome === "undefined" || !chrome.storage?.local?.get) {
    return 0
  }

  const key = getAbuseDailyKey()
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (items) => {
      const rawValue = items?.[key]
      resolve(typeof rawValue === "number" ? rawValue : 0)
    })
  })
}

const STATUS_BADGE_MAP: Record<SubnetCheckSummaryRow["statusKind"], { bg: string; text?: "dark" | "light" }> = {
  flagged: { bg: "warning", text: "dark" },
  error: { bg: "danger" },
  private: { bg: "secondary" },
  clean: { bg: "success" },
  pending: { bg: "secondary" }
}

const getStatusBadgeProps = (entry: SubnetCheckSummaryRow) =>
  STATUS_BADGE_MAP[entry.statusKind] ?? STATUS_BADGE_MAP.pending

const resolveStatusDescriptor = (
  payload: SubnetCheckResult | undefined,
  isPrivateSubnet: boolean,
  reportedCount: number,
  isLoading: boolean
): Pick<SubnetCheckSummaryRow, "statusKind" | "statusText"> => {
  if (isPrivateSubnet) {
    return {
      statusKind: "private",
      statusText: payload?.error ?? "Private subnet - not checked"
    }
  }

  if (payload?.error) {
    return {
      statusKind: "error",
      statusText: payload.error
    }
  }

  if (reportedCount > 0) {
    return {
      statusKind: "flagged",
      statusText: reportedCount === 1 ? "1 IP reported" : `${reportedCount} IPs reported`
    }
  }

  if (payload) {
    return {
      statusKind: "clean",
      statusText: "No reports"
    }
  }

  return {
    statusKind: "pending",
    statusText: isLoading ? "Pending check..." : "Awaiting check"
  }
}

const SubnetCheck = () => {
  const [textareaValue, setTextareaValue] = useState("")
  const [subnets, setSubnets] = useState<NormalizedSubnet[]>([])
  const [results, setResults] = useState<Record<string, SubnetCheckResult>>({})
  const [isLoading, setIsLoading] = useState(false)
  const [message, setMessage] = useState<string>("")
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [themeLoaded, setThemeLoaded] = useState(false)
  const [confidenceMinimum, setConfidenceMinimum] = useState(0)
  const [abuseDailyCount, setAbuseDailyCount] = useState(0)

  const refreshAbuseCounter = useCallback(async () => {
    const nextCount = await readAbuseCounter()
    setAbuseDailyCount(nextCount)
  }, [])

  useEffect(() => {
    const loadInitialState = async () => {
      try {
        const [savedInput, prefill, savedConfidence, savedTheme] = await Promise.all([
          storage.get<string>(INPUT_KEY),
          storage.get<string[]>(PREFILL_KEY),
          storage.get<number>("subnetCheckConfidence"),
          ensureIsDarkMode()
        ])

        const initialList = Array.isArray(prefill) && prefill.length > 0
          ? prefill.join("\n")
          : typeof savedInput === "string"
            ? savedInput
            : ""

        if (initialList) {
          setTextareaValue(initialList)
        }

        if (Array.isArray(prefill) && prefill.length > 0) {
          await storage.remove(PREFILL_KEY)
        }

        if (typeof savedConfidence === "number") {
          setConfidenceMinimum(clampConfidenceInput(savedConfidence))
        }

        setIsDarkMode(savedTheme)
      } catch (error) {
        console.error("Failed to load initial subnet-check state:", error)
      } finally {
        setThemeLoaded(true)
      }
    }

    loadInitialState()
  }, [])

  useEffect(() => {
    storage.set(INPUT_KEY, textareaValue)
  }, [textareaValue])

  useEffect(() => {
    storage.set("subnetCheckConfidence", confidenceMinimum)
  }, [confidenceMinimum])

  useEffect(() => {
    if (!themeLoaded) {
      return
    }
    persistIsDarkMode(isDarkMode)
    applyDocumentTheme(isDarkMode)
  }, [isDarkMode, themeLoaded])

  useEffect(() => {
    refreshAbuseCounter()
  }, [refreshAbuseCounter])

  useEffect(() => {
    if (typeof chrome === "undefined" || !chrome.storage?.onChanged) {
      return
    }

    const listener: Parameters<typeof chrome.storage.onChanged.addListener>[0] = (changes, area) => {
      if (area !== "local") {
        return
      }

      if (Object.prototype.hasOwnProperty.call(changes, "isDarkMode")) {
        const next = changes.isDarkMode?.newValue
        if (typeof next === "boolean") {
          setIsDarkMode(next)
        }
      }

      const abuseKey = getAbuseDailyKey()
      if (Object.prototype.hasOwnProperty.call(changes, abuseKey)) {
        const nextCount = changes[abuseKey]?.newValue
        if (typeof nextCount === "number") {
          setAbuseDailyCount(nextCount)
        }
      }
    }

    chrome.storage.onChanged.addListener(listener)
    return () => chrome.storage.onChanged.removeListener(listener)
  }, [])

  const handleTextAreaChange = useCallback((event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setTextareaValue(event.target.value)
  }, [])

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    const reader = new FileReader()
    reader.onload = (loadEvent) => {
      const content = typeof loadEvent.target?.result === "string" ? loadEvent.target.result : ""
      if (!content) {
        setMessage("The selected file was empty.")
      }
      setTextareaValue(content)
    }
    reader.onerror = () => {
      setMessage("Unable to read the selected file.")
    }
    reader.readAsText(file)
    event.target.value = ""
  }, [])

  const handleClear = useCallback(() => {
    setTextareaValue("")
    setSubnets([])
    setResults({})
    setMessage("")
  }, [])

  const handleConfidenceChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setConfidenceMinimum(clampConfidenceInput(Number(event.target.value)))
  }, [])

  const handleCheck = useCallback(async () => {
    const parsed = extractSubnetsFromText(textareaValue)
    if (parsed.length === 0) {
      setSubnets([])
      setResults({})
      setMessage("Add at least one valid subnet in the text area before running the check.")
      return
    }

    setSubnets(parsed)
    setResults({})
    setIsLoading(true)
    setMessage("Checking subnets on AbuseIPDB...")

    try {
      const body = {
        subnets: parsed.map((entry) => entry.subnet),
        maxAgeInDays: LOOKBACK_DAYS,
        confidenceMinimum: confidenceMinimum > 0 ? confidenceMinimum : undefined
      }

      const response = await sendToBackground<{ results?: Record<string, SubnetCheckResult> }>({
        name: "check-subnet-abuse",
        body
      })

      setResults(response?.results ?? {})
      setMessage("Check completed.")
      await refreshAbuseCounter()
    } catch (error) {
      console.error("Subnet check failed:", error)
      setMessage("Unable to complete the check. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }, [confidenceMinimum, refreshAbuseCounter, textareaValue])

  const summarizedResults = useMemo<SubnetCheckSummaryRow[]>(
    () =>
      subnets.map((entry) => {
        const payload = results[entry.subnet]
        const hostCount = formatHostCount(estimateSubnetHostCount(entry.version, entry.prefix))
        const subnetData = payload?.data?.data
        const reports = Array.isArray(subnetData?.reportedAddress) ? subnetData.reportedAddress : null
        const firstReport = reports?.[0] ?? null
        const ipFallback = payload?.ipDetails?.data
        const minAddress = subnetData?.minAddress
        const maxAddress = subnetData?.maxAddress
        const reportedCount = payload?.reportedCount ?? (reports?.length ?? 0)
        const baseAddress = entry.subnet.split("/")[0] ?? ""
        const isPrivateSubnet = payload?.isPrivate ?? isPrivateIP(baseAddress)
        const { statusKind, statusText } = resolveStatusDescriptor(payload, isPrivateSubnet, reportedCount, isLoading)

        const isp = firstReport?.isp ?? subnetData?.isp ?? ipFallback?.isp ?? null
        const country = firstReport?.countryCode ?? subnetData?.countryCode ?? ipFallback?.countryCode ?? null
        const usageType = firstReport?.usageType ?? subnetData?.usageType ?? ipFallback?.usageType ?? null
        const domain = subnetData?.domain ?? firstReport?.domain ?? ipFallback?.domain ?? null

        const hostnames = Array.isArray(subnetData?.hostnames) && subnetData.hostnames.length > 0
          ? subnetData.hostnames
          : Array.isArray(firstReport?.hostnames) && firstReport.hostnames.length > 0
            ? firstReport.hostnames
            : Array.isArray(ipFallback?.hostnames) && ipFallback.hostnames.length > 0
              ? ipFallback.hostnames
              : null

        return {
          subnet: entry.subnet,
          version: entry.version,
          prefix: entry.prefix,
          hostCount,
          mostRecent: getMostRecentReport(payload?.data),
          minAddress,
          maxAddress,
          reportedCount,
          distinctIpCount: reports?.length ?? null,
          isPrivate: isPrivateSubnet,
          statusText,
          statusKind,
          error: payload?.error ?? null,
          isp,
          country,
          usageType,
          domain,
          hostnames
        }
      }),
    [isLoading, results, subnets]
  )

  const flaggedTotal = useMemo(
    () => summarizedResults.filter((entry) => entry.statusKind === "flagged").length,
    [summarizedResults]
  )

  const totalIpv4 = useMemo(() => subnets.filter((entry) => entry.version === 4).length, [subnets])
  const totalIpv6 = useMemo(() => subnets.filter((entry) => entry.version === 6).length, [subnets])

  const handleCopyResults = useCallback(async () => {
    if (summarizedResults.length === 0) {
      setMessage("There are no results to copy yet.")
      return
    }

    if (!hasClipboardAccess()) {
      setMessage("Clipboard access is not available in this context.")
      return
    }

    try {
      const payload = formatSubnetCheckClipboard(summarizedResults)
      if (!payload) {
        setMessage("There are no results to copy yet.")
        return
      }
      await navigator.clipboard.writeText(payload)
      setMessage("Subnet report copied to clipboard.")
    } catch (error) {
      console.error("Copy failed:", error)
      setMessage("Unable to copy the subnet report.")
    }
  }, [summarizedResults])

  const handleExportResults = useCallback(() => {
    if (summarizedResults.length === 0) {
      setMessage("There are no results to export yet.")
      return
    }

    try {
      exportSubnetCheckToExcel(summarizedResults)
      setMessage("Subnet report exported to Excel.")
    } catch (error) {
      console.error("Export failed:", error)
      setMessage("Unable to export the subnet report.")
    }
  }, [summarizedResults])

  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"
  const secondaryTextClass = isDarkMode ? "text-white-50" : "text-muted"

  return (
    <Container fluid className={`p-4 min-vh-100 ${themeClass}`}>
      <h1 className="mb-4">🛰️ Subnet Abuse Check</h1>
      <Row className="g-4">
        <Col md={6}>
          <Form.Group>
            <Form.Label>📋 Enter IPv4/IPv6 Subnets</Form.Label>
            <Form.Control
              as="textarea"
              rows={16}
              value={textareaValue}
              className={themeClass}
              onChange={handleTextAreaChange}
              placeholder={"Example: 192.168.10.0/24\n2001:db8::/48"}
            />
          </Form.Group>

          <Card className={`mt-4 ${themeClass}`}>
            <Card.Body>
              <h5>📊 Summary</h5>
              <div className="d-flex flex-wrap gap-2">
                <Badge bg="primary">Total: {subnets.length}</Badge>
                <Badge bg="success">IPv4: {totalIpv4}</Badge>
                <Badge bg="info">IPv6: {totalIpv6}</Badge>
                <Badge bg="warning" text="dark">
                  Flagged Subnets: {flaggedTotal}
                </Badge>
                <Badge bg="danger">AbuseIPDB Today: {abuseDailyCount}</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col md={6}>
          <Form.Group>
            <Form.Label>📁 Upload .txt File</Form.Label>
            <Form.Control type="file" accept=".txt" onChange={handleFileUpload} className={themeClass} />
          </Form.Group>

          <Row className="mt-3">
            <Col md={12}>
              <Form.Label>Confidence minimum</Form.Label>
              <Form.Control
                type="number"
                min={0}
                max={100}
                value={confidenceMinimum}
                className={themeClass}
                onChange={handleConfidenceChange}
                inputMode="numeric"
              />
            </Col>
          </Row>
          <p className={`${secondaryTextClass} small mt-2`}>
            Reports are limited to the last {LOOKBACK_DAYS} days.
          </p>

          <div className="d-grid gap-2 mt-4">
            <Button variant="success" onClick={handleCheck} disabled={isLoading}>
              {isLoading ? (
                <>
                  <Spinner as="span" size="sm" animation="border" role="status" aria-hidden="true" />
                  <span className="ms-2">Checking...</span>
                </>
              ) : (
                "🔍 Run AbuseIPDB Check"
              )}
            </Button>
            <Button variant="outline-danger" onClick={handleClear} disabled={isLoading}>
              🗑️ Clear Subnets
            </Button>
            <Button
              variant={isDarkMode ? "outline-light" : "outline-secondary"}
              onClick={handleCopyResults}
              disabled={summarizedResults.length === 0}
            >
              Copy Report
            </Button>
            <Button
              variant={isDarkMode ? "outline-light" : "outline-secondary"}
              onClick={handleExportResults}
              disabled={summarizedResults.length === 0}
            >
              Export XLSX
            </Button>
          </div>

          {message && (
            <Alert variant="info" className="mt-3">
              {message}
            </Alert>
          )}
        </Col>
      </Row>

      <Card className={`mt-4 ${themeClass}`}>
        <Card.Header>AbuseIPDB Results</Card.Header>
        <Card.Body className="table-responsive">
          {subnets.length === 0 ? (
            <p className={`${secondaryTextClass} mb-0`}>
              Enter at least one subnet to start the analysis.
            </p>
          ) : (
            <Table bordered hover variant={isDarkMode ? "dark" : undefined} className="mb-0">
              <thead>
                <tr>
                  <th>Subnet</th>
                  <th>Version</th>
                  <th>Hosts</th>
                  <th>Reported IPs</th>
                  <th>Most Recent Report</th>
                  <th>Details</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {summarizedResults.map((entry) => {
                  const badge = getStatusBadgeProps(entry)
                  const hasDistinctIps = typeof entry.distinctIpCount === "number" && entry.distinctIpCount > 0
                  const hasOtherIntel = Boolean(
                    entry.country || entry.isp || entry.usageType || entry.domain || (entry.hostnames && entry.hostnames.length)
                  )
                  const hasIntel = hasDistinctIps || hasOtherIntel

                  return (
                    <tr key={entry.subnet}>
                      <td>
                        <div className="fw-semibold">{entry.subnet}</div>
                        <small className={secondaryTextClass}>
                          {entry.minAddress && entry.maxAddress
                            ? `${entry.minAddress} → ${entry.maxAddress}`
                            : entry.version === 4
                              ? "IPv4 block"
                              : "IPv6 block"}
                        </small>
                      </td>
                      <td>IPv{entry.version}</td>
                      <td>{entry.hostCount}</td>
                      <td>
                        <Badge bg={entry.reportedCount > 0 ? "danger" : "secondary"}>{entry.reportedCount}</Badge>
                      </td>
                      <td>{entry.mostRecent ?? "—"}</td>
                      <td>
                        <div className={`small ${secondaryTextClass}`}>
                          {hasDistinctIps && (
                            <div>Distinct IPs: {entry.distinctIpCount}</div>
                          )}
                          {entry.country && <div>Country: {entry.country}</div>}
                          {entry.isp && <div>ISP: {entry.isp}</div>}
                          {entry.usageType && <div>Usage: {entry.usageType}</div>}
                          {entry.domain && <div>Domain: {entry.domain}</div>}
                          {Array.isArray(entry.hostnames) && entry.hostnames.length > 0 && (
                            <div>Hostnames: {entry.hostnames.join(", ")}</div>
                          )}
                          {!hasIntel && <div>No extra intel</div>}
                        </div>
                      </td>
                      <td>
                        <Badge bg={badge.bg} text={badge.text} className="d-inline-block">
                          {entry.statusText}
                        </Badge>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </Table>
          )}
        </Card.Body>
      </Card>
    </Container>
  )
}

const getMostRecentReport = (payload: any): string | null => {
  const entries = payload?.data?.reportedAddress
  if (!Array.isArray(entries) || entries.length === 0) {
    return null
  }
  const timestamps = entries
    .map((entry) => entry?.mostRecentReport)
    .filter((value): value is string => Boolean(value))
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))

  if (timestamps.length === 0) {
    return null
  }

  const latest = timestamps.sort((a, b) => b.getTime() - a.getTime())[0]
  return latest.toISOString().split("T")[0]
}

export default SubnetCheck
