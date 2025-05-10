import React, { useState } from "react"
import { Card, Table, Form, Button, InputGroup } from "react-bootstrap"
import { MdDarkMode, MdLightMode, MdVisibility, MdVisibilityOff } from "react-icons/md"
import { servicesConfig } from "../utility/servicesConfig"
import "bootstrap/dist/css/bootstrap.min.css"

interface OptionsUIProps {
  isDarkMode: boolean
  virusTotalApiKey: string
  abuseIPDBApiKey: string
  selectedServices: { [key: string]: string[] }
  onDarkModeToggle: () => void
  onServiceChange: (type: string, service: string) => void
  onVirusTotalApiKeyChange: (val: string) => void
  onAbuseIPDBApiKeyChange: (val: string) => void
  onTestKeys: () => void
}

const OptionsUI: React.FC<OptionsUIProps> = ({
  isDarkMode,
  virusTotalApiKey,
  abuseIPDBApiKey,
  selectedServices,
  onDarkModeToggle,
  onServiceChange,
  onVirusTotalApiKeyChange,
  onAbuseIPDBApiKeyChange,
  onTestKeys
}) => {
  const [showKeys, setShowKeys] = useState(false)
  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"
  const tableVariant = isDarkMode ? "dark" : "light"
  const inputType = showKeys ? "text" : "password"

  return (
    <Card className={`p-4 ${themeClass}`}>
      <Card.Body>
        {/* Header */}
        <div className="d-flex justify-content-between align-items-center mb-4">
          <Card.Title className="mb-0">⚙️ Impostazioni Estensione</Card.Title>
          <Button
            variant={isDarkMode ? "light" : "dark"}
            size="sm"
            onClick={onDarkModeToggle}
            title="Cambia Tema"
          >
            {isDarkMode ? <MdLightMode /> : <MdDarkMode />}
          </Button>
        </div>

        {/* Sezione API Key */}
        <Card.Title>🔑 Chiavi API</Card.Title>
        <Form>
          <Form.Group className="mb-3">
            <Form.Label>VirusTotal</Form.Label>
            <InputGroup>
              <Form.Control
                type={inputType}
                value={virusTotalApiKey}
                onChange={(e) => onVirusTotalApiKeyChange(e.target.value)}
                placeholder="Inserisci la chiave API di VirusTotal"
                className={themeClass}
              />
              <Button
                variant={isDarkMode ? "outline-light" : "outline-secondary"}
                onClick={() => setShowKeys((prev) => !prev)}
              >
                {showKeys ? <MdVisibilityOff /> : <MdVisibility />}
              </Button>
            </InputGroup>
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>AbuseIPDB</Form.Label>
            <InputGroup>
              <Form.Control
                type={inputType}
                value={abuseIPDBApiKey}
                onChange={(e) => onAbuseIPDBApiKeyChange(e.target.value)}
                placeholder="Inserisci la chiave API di AbuseIPDB"
                className={themeClass}
              />
              <Button
                variant={isDarkMode ? "outline-light" : "outline-secondary"}
                onClick={() => setShowKeys((prev) => !prev)}
              >
                {showKeys ? <MdVisibilityOff /> : <MdVisibility />}
              </Button>
            </InputGroup>
          </Form.Group>

          <Button variant="outline-primary" onClick={onTestKeys}>
            🧪 Testa Chiavi API
          </Button>
        </Form>

        {/* Sezione Servizi */}
        <hr />
        <Card.Title>🔍 Servizi abilitati per "MAGIC IOC"</Card.Title>
        <Table striped bordered hover responsive variant={tableVariant}>
          <thead>
            <tr>
              <th>Tipo IOC</th>
              <th>Motori di Ricerca</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(servicesConfig.availableServices).map(([type, services]) => (
              <tr key={type}>
                <td>{type}</td>
                <td>
                  {services.map((service) => (
                    <Form.Check
                      key={`${type}-${service}`}
                      type="checkbox"
                      label={service}
                      id={`${type}-${service}`}
                      checked={selectedServices[type]?.includes(service) || false}
                      onChange={() => onServiceChange(type, service)}
                      className="mb-1"
                    />
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card.Body>
    </Card>
  )
}

export default OptionsUI
