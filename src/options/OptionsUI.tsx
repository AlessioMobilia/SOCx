// src/options/OptionsUI.tsx
import React from "react";
import { Card, Table, Form } from "react-bootstrap";
import { servicesConfig } from "../utility/servicesConfig"; // Importa servicesConfig
import { MdDarkMode, MdLightMode } from "react-icons/md"; // Importa le icone di Material Design da React Icons
import "bootstrap/dist/css/bootstrap.min.css";

interface OptionsUIProps {
  isDarkMode: boolean;
  virusTotalApiKey: string;
  abuseIPDBApiKey: string;
  selectedServices: { [key: string]: string[] };
  onDarkModeToggle: () => void;
  onServiceChange: (type: string, service: string) => void;
  onVirusTotalApiKeyChange: (value: string) => void;
  onAbuseIPDBApiKeyChange: (value: string) => void;
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
}) => {
  // Usa availableServices da servicesConfig
  const { availableServices } = servicesConfig;

  return (
    <Card className={`p-3 ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}`}>
      <Card.Body>
        <div className="d-flex justify-content-between align-items-start mb-3">
          <Card.Title>Impostazioni Estensione</Card.Title>
          <div onClick={onDarkModeToggle} style={{ cursor: "pointer" }}>
            {isDarkMode ? <MdLightMode size={24} /> : <MdDarkMode size={24} />}
          </div>
        </div>

        <Card.Title>Preferenze Motori di Ricerca per il tasto "MAGIC IOC"</Card.Title>
        <Table striped bordered hover variant={isDarkMode ? "dark" : "light"}>
          <thead>
            <tr>
              <th>Tipo IOC</th>
              <th>Motori di Ricerca</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(availableServices).map(([type, services]) => (
              <tr key={type}>
                <td>{type}</td>
                <td>
                  {services.map((service) => (
                    <Form.Check
                      key={service}
                      type="checkbox"
                      id={`${type}-${service}`}
                      label={service}
                      checked={selectedServices[type].includes(service)}
                      onChange={() => onServiceChange(type, service)}
                    />
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>

        <Card.Title>Chiavi API</Card.Title>
        <Form>
          <Form.Group className="mb-3">
            <Form.Label>VirusTotal API Key</Form.Label>
            <Form.Control
              type="text"
              value={virusTotalApiKey}
              onChange={(e) => onVirusTotalApiKeyChange(e.target.value)}
              placeholder="Inserisci la tua chiave API di VirusTotal"
              className={isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}
            />
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label>AbuseIPDB API Key</Form.Label>
            <Form.Control
              type="text"
              value={abuseIPDBApiKey}
              onChange={(e) => onAbuseIPDBApiKeyChange(e.target.value)}
              placeholder="Inserisci la tua chiave API di AbuseIPDB"
              className={isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}
            />
          </Form.Group>
        </Form>
      </Card.Body>
    </Card>
  );
};

export default OptionsUI;

