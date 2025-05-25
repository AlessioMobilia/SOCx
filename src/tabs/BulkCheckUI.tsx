import React, { useEffect, useState } from "react"
import {
  Container,
  Button,
  Form,
  Card,
  Spinner,
  Badge,
  Row,
  Col,
  Alert
} from "react-bootstrap"
import { parseAndFormatResults } from "../utility/utils"
import "bootstrap/dist/css/bootstrap.min.css"

interface BulkCheckUIProps {
  textareaValue: string
  onTextAreaChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void
  selectedServices: string[]
  onServiceToggle: (service: string, checked: boolean) => void
  onCheckBulk: () => void
  onClearList: () => void
  isLoading: boolean
  message: string
  results: { [key: string]: any }
  isDarkMode: boolean
  onExport: (format: "csv" | "xlsx") => void
}

const BulkCheckUI: React.FC<BulkCheckUIProps> = ({
  textareaValue,
  onTextAreaChange,
  onFileUpload,
  selectedServices,
  onServiceToggle,
  onCheckBulk,
  onClearList,
  isLoading,
  message,
  results,
  isDarkMode,
  onExport 
}) => {
  const [vtCount, setVtCount] = useState<number>(0)
  const [abuseCount, setAbuseCount] = useState<number>(0)

  useEffect(() => {
    const loadCounters = async () => {
      const today = new Date().toISOString().split("T")[0]
      const keys = await chrome.storage.local.get([
        `VT_${today}`,
        `Abuse_${today}`
      ])
      setVtCount(keys[`VT_${today}`] || 0)
      setAbuseCount(keys[`Abuse_${today}`] || 0)
    }
    loadCounters()
  }, [])

  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"

const getRiskLevel = (result: any): "low" | "medium" | "high" => {
  const vt = result?.VirusTotal;
  const abuse = result?.AbuseIPDB;

  let vtLevel: "low" | "medium" | "high" = "low";
  let abuseLevel: "low" | "medium" | "high" = "low";

  // Controllo VirusTotal con soglie abbassate e bonus harmless
  if (vt) {
    const stats = vt?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats?.malicious || 0;
    const suspicious = stats?.suspicious || 0;
    const harmless = stats?.harmless || 0;

    // Calcola bonus harmless limitato a massimo 5 punti
    const harmlessBonus = Math.min(harmless * 0.2, 5);
    const vtScore = (malicious * 3) + suspicious - harmlessBonus;

    if (vtScore >= 20) vtLevel = "high";
    else if (vtScore >= 5) vtLevel = "medium";
  }

  // Controllo AbuseIPDB con soglie abbassate
  if (abuse) {
    const abuseScore = abuse?.data?.abuseConfidenceScore || 0;

    if (abuseScore >= 50) abuseLevel = "high";
    else if (abuseScore >= 20) abuseLevel = "medium";
  }

  // Confronta i livelli e ritorna il più grave
  const levels = ["low", "medium", "high"];
  return levels[Math.max(levels.indexOf(vtLevel), levels.indexOf(abuseLevel))] as "low" | "medium" | "high";
};



  const getRiskClass = (risk: "low" | "medium" | "high") => {
    switch (risk) {
      case "low":
        return "border-success bg-success-subtle text-dark";
      case "medium":
        return "border-warning bg-warning-subtle text-dark";
      case "high":
        return "border-danger bg-danger-subtle text-dark";
      default:
        return "";
    }
  };

  return (
    <Container fluid className={`p-4 min-vh-100 ${themeClass}`}>
      <h1 className="mb-4">🔍 Bulk IOC Check</h1>

      <Row className="mb-3">
        <Col md={6}>
          <Form.Group>
            <Form.Label>📋 Enter IOCs</Form.Label>
            <Form.Control
              as="textarea"
              rows={15}
              placeholder="Paste IPs, domains, hashes, emails, URLs..."
              value={textareaValue}
              onChange={onTextAreaChange}
              className={themeClass}
            />
          </Form.Group>
        </Col>
        <Col md={6}>
          <Form.Group>
            <Form.Label>📁 Upload .txt File</Form.Label>
            <Form.Control
              type="file"
              accept=".txt"
              onChange={onFileUpload}
              className={themeClass}
            />
          </Form.Group>

          <Form.Group className="mt-4">
            <Form.Label>🛠️ Select Services</Form.Label>
            <div className="d-flex gap-3">
              {["VirusTotal", "AbuseIPDB"].map((service) => (
                <Form.Check
                  key={service}
                  type="checkbox"
                  label={service}
                  checked={selectedServices.includes(service)}
                  onChange={(e) =>
                    onServiceToggle(service, e.target.checked)
                  }
                  className={isDarkMode ? "text-white" : "text-dark"}
                />
              ))}
            </div>
          </Form.Group>

          <div className="mt-4 d-grid gap-2">
            <Button
              variant="success"
              onClick={onCheckBulk}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Spinner
                    as="span"
                    size="sm"
                    animation="border"
                    role="status"
                    aria-hidden="true"
                  />
                  <span className="ms-2">Analysis in progress...</span>
                </>
              ) : (
                "🔍 Start Check"
              )}
            </Button>
            <Button variant="outline-danger" onClick={onClearList}>
              🗑️ Clear List
            </Button>
            <Button
              variant="outline-primary"
              onClick={() => onExport("csv")}
              disabled={Object.keys(results).length === 0}
            >
              📤 Export CSV
            </Button>
            <Button
              variant="outline-success"
              onClick={() => onExport("xlsx")}
              disabled={Object.keys(results).length === 0}
            >
              📘 Export Excel (.xlsx)
            </Button>

            <Button
              variant="outline-secondary"
              onClick={() => {
                const formatted = Object.entries(results)
                  .filter(([_, result]) => {
                    const content = parseAndFormatResults(result).trim()
                    return content && content !== "-"
                  })
                  .map(([ioc, result]) => {
                    const content = parseAndFormatResults(result).trim()
                    return `=== ${ioc} ===\n\n${content}\n-------------------\n\n`
                  })
                  .join("\n\n");

                if (formatted) {
                  navigator.clipboard
                    .writeText(formatted)
                    .then(() => alert("Formatted IOCs copied to clipboard!"))
                    .catch(() => alert("Error copying to clipboard."));
                } else {
                  alert("No formatted results available to copy.");
                }
              }}
              disabled={Object.keys(results).length === 0}
            >
              📋 Copy Formatted IOCs
            </Button>
          </div>
        </Col>
      </Row>

      {message && (
        <Alert
          variant={isLoading ? "info" : "success"}
          className="text-center"
        >
          {message}
        </Alert>
      )}

      <Row className="mb-4">
        <Col>
          <Card className={themeClass}>
            <Card.Body>
              <h5>📊 Daily Counters</h5>
              <p>
                VirusTotal: <Badge bg="info">{vtCount}</Badge>
              </p>
              <p>
                AbuseIPDB: <Badge bg="danger">{abuseCount}</Badge>
              </p>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {results && Object.keys(results).length > 0 && (
        <>
          <h2>📦 Results</h2>
          <Row>
            {Object.entries(results).map(([ioc, result]) => {
              const riskLevel = getRiskLevel(result);
              const riskClass = getRiskClass(riskLevel);

              return (
                <Col md={6} key={ioc}>
                  <Card className={`mb-3 shadow-sm border ${riskClass}`}>
                    <Card.Header>
                      <strong>{ioc}</strong>{" "}
                      <Badge
                        bg={
                          riskLevel === "high"
                            ? "danger"
                            : riskLevel === "medium"
                            ? "warning"
                            : "success"
                        }
                        className="ms-2"
                      >
                        {riskLevel.toUpperCase()}
                      </Badge>
                    </Card.Header>
                    <Card.Body>
                      <pre className="small">
                        {parseAndFormatResults(result)}
                      </pre>
                    </Card.Body>
                  </Card>
                </Col>
              );
            })}
          </Row>
        </>
      )}
    </Container>
  )
}

export default BulkCheckUI
