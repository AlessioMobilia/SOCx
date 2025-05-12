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
          <Card.Title className="mb-0">⚙️ Extension Settings</Card.Title>
          <Button
            variant={isDarkMode ? "light" : "dark"}
            size="sm"
            onClick={onDarkModeToggle}
            title="Toggle Theme"
          >
            {isDarkMode ? <MdLightMode /> : <MdDarkMode />}
          </Button>
        </div>

        {/* API Keys */}
        <Card.Title>🔑 API Keys</Card.Title>
        <Form>
          <Form.Group className="mb-3">
            <Form.Label>VirusTotal</Form.Label>
            <InputGroup>
              <Form.Control
                type={inputType}
                value={virusTotalApiKey}
                onChange={(e) => onVirusTotalApiKeyChange(e.target.value)}
                placeholder="Enter your VirusTotal API key"
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
                placeholder="Enter your AbuseIPDB API key"
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
            🧪 Test API Keys
          </Button>
        </Form>

        {/* Standard Services */}
        <hr />
        <Card.Title>🔍 Enabled Services for "MAGIC IOC"</Card.Title>
        <Table striped bordered hover responsive variant={tableVariant}>
          <thead>
            <tr>
              <th>IOC Type</th>
              <th>Search Engines</th>
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

        {/* Add Custom Service */}
        <hr />
        <Card.Title>➕ Add Custom Service</Card.Title>
        <Form className="mb-3">
          <Form.Group className="mb-2">
            <Form.Label>IOC Type</Form.Label>
            <Form.Select value={newType} onChange={(e) => setNewType(e.target.value as IOCType)}>
              {supportedIOCTypes.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </Form.Select>
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label>Service Name</Form.Label>
            <Form.Control
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="e.g., Shodan"
            />
          </Form.Group>

          <Form.Group className="mb-2">
            <Form.Label>URL with <code>{'{ioc}'}</code></Form.Label>
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
                alert("Enter a valid name and a URL containing {ioc}")
              }
            }}
          >
            ➕ Add Service
          </Button>
        </Form>

        {/* Custom Service List */}
        <Card.Title>⚙️ Configured Custom Services</Card.Title>
        <Table striped bordered hover responsive variant={tableVariant}>
          <thead>
            <tr>
              <th>Type</th>
              <th>Name</th>
              <th>URL</th>
              <th>Actions</th>
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
                    Remove
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
