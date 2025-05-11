import React, { useState } from "react"
import {
  Card,
  Table,
  Form,
  Button,
  InputGroup
} from "react-bootstrap"
import {
  MdDarkMode,
  MdLightMode,
  MdVisibility,
  MdVisibilityOff
} from "react-icons/md"
import { servicesConfig } from "../utility/servicesConfig"
import { supportedIOCTypes, type IOCType, type CustomService } from "../utility/iocTypes"
import "bootstrap/dist/css/bootstrap.min.css"

interface OptionsUIProps {
  isDarkMode: boolean
  virusTotalApiKey: string
  abuseIPDBApiKey: string
  selectedServices: { [key: string]: string[] }
  customServices: CustomService[]
  onDarkModeToggle: () => void
  onServiceChange: (type: string, service: string) => void
  onVirusTotalApiKeyChange: (val: string) => void
  onAbuseIPDBApiKeyChange: (val: string) => void
  onTestKeys: () => void
  onAddCustomService: (s: CustomService) => void
  onRemoveCustomService: (index: number) => void
}

const OptionsUI: React.FC<OptionsUIProps> = ({
  isDarkMode,
  virusTotalApiKey,
  abuseIPDBApiKey,
  selectedServices,
  customServices,
  onDarkModeToggle,
  onServiceChange,
  onVirusTotalApiKeyChange,
  onAbuseIPDBApiKeyChange,
  onTestKeys,
  onAddCustomService,
  onRemoveCustomService
}) => {
  const [showKeys, setShowKeys] = useState(false)
  const [newType, setNewType] = useState<IOCType>("IP")
  const [newName, setNewName] = useState("")
  const [newURL, setNewURL] = useState("")

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

        {/* API Key */}
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

        {/* Servizi Standard */}
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

        {/* Aggiungi Servizi Personalizzati */}
        <hr />
        <Card.Title>➕ Aggiungi servizio personalizzato</Card.Title>
        <Form className="mb-3">
          <Form.Group className="mb-2">
            <Form.Label>Tipo IOC</Form.Label>
            <Form.Select value={newType} onChange={(e) => setNewType(e.target.value as IOCType)}>
              {supportedIOCTypes.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </Form.Select>
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label>Nome servizio</Form.Label>
            <Form.Control
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Es: Shodan"
            />
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label>URL con <code>{'{ioc}'}</code></Form.Label>
            <Form.Control
              type="text"
              value={newURL}
              onChange={(e) => setNewURL(e.target.value)}
              placeholder="https://example.com/lookup/{ioc}"
            />
          </Form.Group>

          <Button
            variant="success"
            onClick={() => {
              if (newName && newURL.includes("{ioc}")) {
                onAddCustomService({ type: newType, name: newName, url: newURL })
                setNewName("")
                setNewURL("")
              } else {
                alert("Inserisci un nome valido e un URL che contenga {ioc}")
              }
            }}
          >
            ➕ Aggiungi servizio
          </Button>
        </Form>

        {/* Lista Servizi Personalizzati */}
        <Card.Title>⚙️ Servizi personalizzati configurati</Card.Title>
        <Table striped bordered hover responsive variant={tableVariant}>
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Nome</th>
              <th>URL</th>
              <th>Azioni</th>
            </tr>
          </thead>
          <tbody>
            {customServices.map((service, index) => (
              <tr key={index}>
                <td>{service.type}</td>
                <td>{service.name}</td>
                <td style={{ wordBreak: "break-word" }}>{service.url}</td>
                <td>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => onRemoveCustomService(index)}
                  >
                    Rimuovi
                  </Button>
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
