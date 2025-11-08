import React, { useEffect, useMemo, useState } from "react"
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Container,
  Form,
  ListGroup,
  Row,
  Spinner
} from "react-bootstrap"
import { Storage } from "@plasmohq/storage"
import "bootstrap/dist/css/bootstrap.min.css"
import "./subnet-extractor.css"
import {
  ExtractedIPMap,
  computeIPv4Subnet,
  computeIPv6Subnet,
  extractIPAddresses,
  isPrivateIP
} from "../utility/utils"

type SubnetSummary = {
  subnet: string
  version: 4 | 6
  ips: string[]
  isPrivate: boolean
}

type StatusVariant = "success" | "danger" | "info" | "warning"

const storage = new Storage({ area: "local" })
const DEFAULT_IPV4_PREFIX = 24
const DEFAULT_IPV6_PREFIX = 64

const summarizeSubnets = (
  ips: ExtractedIPMap,
  ipv4Prefix: number,
  ipv6Prefix: number
): SubnetSummary[] => {
  const map = new Map<
    string,
    { subnet: string; version: 4 | 6; ips: Set<string>; isPrivate: boolean }
  >()

  ips.ipv4.forEach((ip) => {
    const subnet = computeIPv4Subnet(ip, ipv4Prefix)
    if (!subnet) {
      return
    }
    const key = `4-${subnet}`
    if (!map.has(key)) {
      map.set(key, {
        subnet,
        version: 4,
        ips: new Set(),
        isPrivate: isPrivateIP(subnet.split("/")[0] ?? "")
      })
    }
    map.get(key)!.ips.add(ip)
  })

  ips.ipv6.forEach((ip) => {
    const subnet = computeIPv6Subnet(ip, ipv6Prefix)
    if (!subnet) {
      return
    }
    const key = `6-${subnet}`
    if (!map.has(key)) {
      map.set(key, {
        subnet,
        version: 6,
        ips: new Set(),
        isPrivate: isPrivateIP(subnet.split("/")[0] ?? "")
      })
    }
    map.get(key)!.ips.add(ip)
  })

  return Array.from(map.values())
    .map((entry) => ({
      subnet: entry.subnet,
      version: entry.version,
      ips: Array.from(entry.ips).sort(),
      isPrivate: entry.isPrivate
    }))
    .sort((a, b) => {
      if (a.version !== b.version) {
        return a.version - b.version
      }
      return a.subnet.localeCompare(b.subnet, undefined, {
        numeric: true,
        sensitivity: "base"
      })
    })
}

const SubnetExtractor = () => {
  const [inputText, setInputText] = useState("")
  const [ipv4Prefix, setIpv4Prefix] = useState(DEFAULT_IPV4_PREFIX)
  const [ipv6Prefix, setIpv6Prefix] = useState(DEFAULT_IPV6_PREFIX)
  const [isDarkMode, setIsDarkMode] = useState(true)
  const [isProcessing, setIsProcessing] = useState(false)
  const [summary, setSummary] = useState<SubnetSummary[]>([])
  const [status, setStatus] = useState<{ variant: StatusVariant; message: string } | null>(null)
  const [totals, setTotals] = useState({ ipv4: 0, ipv6: 0 })
  const [privateTotals, setPrivateTotals] = useState({ ipv4: 0, ipv6: 0 })

  const ipv4Subnets = useMemo(
    () => summary.filter((entry) => entry.version === 4).map((entry) => entry.subnet),
    [summary]
  )
  const ipv6Subnets = useMemo(
    () => summary.filter((entry) => entry.version === 6).map((entry) => entry.subnet),
    [summary]
  )

  const ipv4SubnetIpCount = useMemo(
    () => summary.filter((entry) => entry.version === 4).reduce((acc, entry) => acc + entry.ips.length, 0),
    [summary]
  )
  const ipv6SubnetIpCount = useMemo(
    () => summary.filter((entry) => entry.version === 6).reduce((acc, entry) => acc + entry.ips.length, 0),
    [summary]
  )

  const subnetExportPayload = useMemo(() => {
    const sections: string[] = []
    if (ipv4Subnets.length > 0) {
      sections.push(`== Subnet IPv4 /${ipv4Prefix} ==\n\n${ipv4Subnets.join("\n")}`)
    }
    if (ipv6Subnets.length > 0) {
      sections.push(`== Subnet IPv6 /${ipv6Prefix} ==\n\n${ipv6Subnets.join("\n")}`)
    }
    return sections.join("\n\n").trim()
  }, [ipv4Subnets, ipv6Subnets, ipv4Prefix, ipv6Prefix])

  const hasExportableSubnets = subnetExportPayload.length > 0

  useEffect(() => {
    const loadPreferences = async () => {
      const savedInput = await storage.get<string>("subnetExtractorInput")
      const savedIpv4 = await storage.get<number>("subnetExtractorIpv4")
      const savedIpv6 = await storage.get<number>("subnetExtractorIpv6")
      const savedTheme = await storage.get<boolean>("isDarkMode")

      if (typeof savedInput === "string") {
        setInputText(savedInput)
      }
      if (typeof savedIpv4 === "number") {
        setIpv4Prefix(savedIpv4)
      }
      if (typeof savedIpv6 === "number") {
        setIpv6Prefix(savedIpv6)
      }
      if (typeof savedTheme === "boolean") {
        setIsDarkMode(savedTheme)
      }
    }

    loadPreferences()
  }, [])

  useEffect(() => {
    storage.set("subnetExtractorInput", inputText)
  }, [inputText])

  useEffect(() => {
    storage.set("subnetExtractorIpv4", ipv4Prefix)
  }, [ipv4Prefix])

  useEffect(() => {
    storage.set("subnetExtractorIpv6", ipv6Prefix)
  }, [ipv6Prefix])

  useEffect(() => {
    storage.set("isDarkMode", isDarkMode)
    if (typeof document !== "undefined") {
      document.body.className = isDarkMode ? "dark-mode" : "light-mode"
    }
  }, [isDarkMode])

  useEffect(() => {
    const trimmed = inputText.trim()
    if (!trimmed) {
      setIsProcessing(false)
      setSummary([])
      setTotals({ ipv4: 0, ipv6: 0 })
      setPrivateTotals({ ipv4: 0, ipv6: 0 })
      setStatus(null)
      return
    }

    setIsProcessing(true)
    setStatus({ variant: "info", message: "Extracting subnets..." })

    let cancelled = false
    const timer = setTimeout(() => {
      if (cancelled) {
        return
      }

      try {
        const ips = extractIPAddresses(trimmed)
        if (cancelled) {
          return
        }

        setTotals({ ipv4: ips.ipv4.length, ipv6: ips.ipv6.length })
        setPrivateTotals({
          ipv4: ips.ipv4.filter((ip) => isPrivateIP(ip)).length,
          ipv6: ips.ipv6.filter((ip) => isPrivateIP(ip)).length
        })

        if (ips.ipv4.length === 0 && ips.ipv6.length === 0) {
          setSummary([])
          setStatus({
            variant: "warning",
            message: "No valid IPv4 or IPv6 addresses were detected."
          })
        } else {
          const computed = summarizeSubnets(ips, ipv4Prefix, ipv6Prefix)
          setSummary(computed)
          setStatus({
            variant: "success",
            message: `Extracted ${computed.length} subnet${computed.length === 1 ? "" : "s"}.`
          })
        }
      } catch (error) {
        console.error("Subnet extraction failed:", error)
        if (!cancelled) {
          setSummary([])
          setTotals({ ipv4: 0, ipv6: 0 })
          setPrivateTotals({ ipv4: 0, ipv6: 0 })
          setStatus({
            variant: "danger",
            message: "Failed to extract subnets. Please try again."
          })
        }
      } finally {
        if (!cancelled) {
          setIsProcessing(false)
        }
      }
    }, 250)

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [inputText, ipv4Prefix, ipv6Prefix])

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    const reader = new FileReader()
    reader.onload = (loadEvent) => {
      const content = String(loadEvent.target?.result ?? "")
      setInputText(content)
    }
    reader.readAsText(file)
    event.target.value = ""
  }

  const handleClearInput = () => {
    setInputText("")
    setSummary([])
    setTotals({ ipv4: 0, ipv6: 0 })
    setStatus(null)
  }

  const handleIpv4PrefixChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.target.value)
    const nextValue = Number.isFinite(value) ? Math.min(32, Math.max(0, value)) : DEFAULT_IPV4_PREFIX
    setIpv4Prefix(nextValue)
  }

  const handleIpv6PrefixChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(event.target.value)
    const nextValue = Number.isFinite(value) ? Math.min(128, Math.max(0, value)) : DEFAULT_IPV6_PREFIX
    setIpv6Prefix(nextValue)
  }

  const handleCopyAll = async () => {
    if (!hasExportableSubnets) {
      setStatus({
        variant: "warning",
        message: "There are no subnets to copy yet."
      })
      return
    }

    try {
      await navigator.clipboard.writeText(subnetExportPayload)
      setStatus({
        variant: "success",
        message: "Subnet list copied to clipboard."
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the subnet list."
      })
    }
  }

  const handleExportTxt = () => {
    if (!hasExportableSubnets) {
      setStatus({
        variant: "warning",
        message: "There are no subnets to export yet."
      })
      return
    }

    try {
      const blob = new Blob([subnetExportPayload], {
        type: "text/plain;charset=utf-8"
      })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement("a")
      anchor.href = url
      anchor.download = "subnets.txt"
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setStatus({
        variant: "success",
        message: "Subnet list exported to subnets.txt."
      })
    } catch (error) {
      console.error("Export failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to export the subnet list."
      })
    }
  }

  const handleCopySingle = async (entry: SubnetSummary) => {
    try {
      const payload = `${entry.subnet} (IPv${entry.version})\n${entry.ips.join("\n")}`
      await navigator.clipboard.writeText(payload)
      setStatus({
        variant: "success",
        message: `${entry.subnet} copied to clipboard.`
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the selected subnet."
      })
    }
  }

  const handleCopySubnetGroup = async (family: "ipv4" | "ipv6") => {
    const list = family === "ipv4" ? ipv4Subnets : ipv6Subnets
    if (list.length === 0) {
      setStatus({
        variant: "warning",
        message: `No IPv${family === "ipv4" ? 4 : 6} subnets to copy.`
      })
      return
    }

    try {
      await navigator.clipboard.writeText(list.join("\n"))
      setStatus({
        variant: "success",
        message: `IPv${family === "ipv4" ? 4 : 6} subnet list copied.`
      })
    } catch (error) {
      console.error("Copy failed:", error)
      setStatus({
        variant: "danger",
        message: "Unable to copy the subnet list."
      })
    }
  }

  const isSubnetPrivate = (entry: SubnetSummary): boolean => {
    const base = entry.subnet.split("/")[0] ?? ""
    return isPrivateIP(base)
  }

  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"

  return (
    <Container fluid className={`p-4 min-vh-100 ${themeClass}`}>
      <h1 className="mb-4">🧭 Subnet Extractor</h1>
      <Row className="g-4">
        <Col md={6}>
          <Form.Group>
            <Form.Label>Paste IP Addresses</Form.Label>
            <Form.Control
              as="textarea"
              rows={16}
              placeholder="Paste IPv4/IPv6 addresses, defanged entries, or raw text..."
              value={inputText}
              className={themeClass}
              onChange={(event) => setInputText(event.target.value)}
            />
          </Form.Group>

          <Card className={`mt-3 ${themeClass}`}>
            <Card.Header>Subnet Lists</Card.Header>
            <Card.Body>
              <Form.Group className="mb-3">
                <Form.Label className="d-flex justify-content-between align-items-center gap-2">
                  <span>IPv4 Subnets ({ipv4Subnets.length} networks / {ipv4SubnetIpCount} IPs)</span>
                  <Button
                    size="sm"
                    variant={isDarkMode ? "outline-light" : "outline-secondary"}
                    onClick={() => handleCopySubnetGroup("ipv4")}
                  >
                    Copy
                  </Button>
                </Form.Label>
                <Form.Control
                  as="textarea"
                  rows={4}
                  readOnly
                  className={`subnet-export-box ${themeClass}`}
                  value={ipv4Subnets.join("\n")}
                  placeholder="No IPv4 subnets yet."
                />
              </Form.Group>
              <Form.Group>
                <Form.Label className="d-flex justify-content-between align-items-center gap-2">
                  <span>IPv6 Subnets ({ipv6Subnets.length} networks / {ipv6SubnetIpCount} IPs)</span>
                  <Button
                    size="sm"
                    variant={isDarkMode ? "outline-light" : "outline-secondary"}
                    onClick={() => handleCopySubnetGroup("ipv6")}
                  >
                    Copy
                  </Button>
                </Form.Label>
                <Form.Control
                  as="textarea"
                  rows={4}
                  readOnly
                  className={`subnet-export-box ${themeClass}`}
                  value={ipv6Subnets.join("\n")}
                  placeholder="No IPv6 subnets yet."
                />
              </Form.Group>
            </Card.Body>
          </Card>
        </Col>

        <Col md={6}>
          <Form.Group className="mb-3">
            <Form.Label>Upload .txt File</Form.Label>
            <Form.Control
              type="file"
              accept=".txt"
              className={themeClass}
              onChange={handleFileUpload}
            />
          </Form.Group>

          <Row className="mb-3">
            <Col md={6}>
              <Form.Label>IPv4 Subnet</Form.Label>
              <Form.Control
                type="number"
                min={0}
                max={32}
                value={ipv4Prefix}
                className={themeClass}
                onChange={handleIpv4PrefixChange}
              />
            </Col>
            <Col md={6}>
              <Form.Label>IPv6 Subnet</Form.Label>
              <Form.Control
                type="number"
                min={0}
                max={128}
                value={ipv6Prefix}
                className={themeClass}
                onChange={handleIpv6PrefixChange}
              />
            </Col>
          </Row>

          <div className="d-grid gap-2">
            <Button variant="outline-danger" onClick={handleClearInput} disabled={isProcessing}>
              Clear Input
            </Button>
            <Button
              variant="outline-primary"
              onClick={handleCopyAll}
              disabled={!hasExportableSubnets || isProcessing}
            >
              Copy Subnet List
            </Button>
            <Button
              variant="outline-success"
              onClick={handleExportTxt}
              disabled={!hasExportableSubnets || isProcessing}
            >
              Export TXT
            </Button>
          </div>

          {status && (
            <Alert
              variant={status.variant}
              className="mt-3 d-flex align-items-center gap-2"
            >
              {isProcessing && status.variant === "info" && (
                <Spinner animation="border" size="sm" role="status" />
              )}
              <span>{status.message}</span>
            </Alert>
          )}

          <Card className={`mt-3 ${themeClass}`}>
            <Card.Header>Overview</Card.Header>
            <Card.Body>
              <div className="subnet-stats mb-3">
                <Badge bg="primary">IPv4 IPs: {totals.ipv4}</Badge>
                <Badge bg="secondary">IPv6 IPs: {totals.ipv6}</Badge>
                <Badge bg="info">Detected Subnets: {summary.length}</Badge>
              </div>
              <div className="subnet-stats">
                <Badge bg="primary">IPv4 Subnets: {ipv4Subnets.length}</Badge>
                <Badge bg="secondary">IPv6 Subnets: {ipv6Subnets.length}</Badge>
                <Badge bg="danger">IPv4 Private IPs: {privateTotals.ipv4}</Badge>
                <Badge bg="danger">IPv6 Private IPs: {privateTotals.ipv6}</Badge>
              </div>
            </Card.Body>
          </Card>

          <Card className={`mt-3 ${themeClass}`}>
            <Card.Header>Detected Subnets</Card.Header>
            <Card.Body>
              {summary.length === 0 ? (
                <p className="text-muted mb-0">
                  No subnets yet. Paste IPs or upload a file to generate the subnet list automatically.
                </p>
              ) : (
                <ListGroup variant="flush">
                  {summary.map((entry) => {
                    const isPrivate = isSubnetPrivate(entry)
                    const versionBadge =
                      isPrivate ? "danger" : entry.version === 4 ? "primary" : "secondary"
                    const ipBadge = isPrivate ? "danger" : "dark"

                    return (
                      <ListGroup.Item
                        key={`${entry.version}-${entry.subnet}`}
                        className={`${themeClass} border rounded-2 mb-3 ${
                          isPrivate ? "subnet-private" : "border-secondary-subtle"
                        }`}
                      >
                        <div className="d-flex justify-content-between align-items-start gap-3">
                          <div>
                            <div className="d-flex align-items-center gap-2">
                              <strong>{entry.subnet}</strong>
                              <Badge bg={versionBadge}>IPv{entry.version}</Badge>
                              <Badge bg={ipBadge}>{entry.ips.length} IPs</Badge>
                              <Badge bg={isPrivate ? "danger" : "success"}>
                                {isPrivate ? "Private" : "Public"}
                              </Badge>
                            </div>
                            <details className="subnet-details mt-2">
                              <summary>Show member IPs</summary>
                              <code className="subnet-ip-list d-block mt-2">
                                {entry.ips.join("\n")}
                              </code>
                            </details>
                          </div>
                          <Button
                            variant={isDarkMode ? "outline-light" : "outline-secondary"}
                            size="sm"
                            onClick={() => handleCopySingle(entry)}
                          >
                            Copy
                          </Button>
                        </div>
                      </ListGroup.Item>
                    )
                  })}
                </ListGroup>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  )
}

export default SubnetExtractor
