import React, { useEffect, useState } from "react";
import { Container, Button, Form, Card, Spinner, Badge } from "react-bootstrap";
import { parseAndFormatResults } from "../utility/utils";
import "bootstrap/dist/css/bootstrap.min.css";

interface BulkCheckUIProps {
  textareaValue: string;
  onTextAreaChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
  selectedServices: string[];
  onServiceToggle: (service: string, checked: boolean) => void;
  onCheckBulk: () => void;
  onClearList: () => void;
  isLoading: boolean;
  message: string;
  results: { [key: string]: any };
  isDarkMode: boolean;
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
}) => {
  const [vtCount, setVtCount] = useState<number>(0);
  const [abuseCount, setAbuseCount] = useState<number>(0);

  // Funzione per ottenere la data corrente in formato YYYY-MM-DD
  const getTodayDate = (): string => {
    const today = new Date();
    return today.toISOString().split("T")[0];
  };

  // Carica i contatori giornalieri
  useEffect(() => {
    const loadCounters = async () => {
      const today = getTodayDate();
      const vtKey = `VT_${today}`;
      const abuseKey = `Abuse_${today}`;
      const counters = await chrome.storage.local.get([vtKey, abuseKey]);
      setVtCount(counters[vtKey] || 0);
      setAbuseCount(counters[abuseKey] || 0);
    };
    loadCounters();
  }, []);

  return (
    <Container fluid className={`p-3 container ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}`}>
      <h1>Controllo Bulk IOC</h1>

      {/* Area di testo per gli IOC */}
      <Form.Group className="mb-3">
        <Form.Control
          as="textarea"
          rows={5}
          placeholder="Incolla gli IOC qui (separati da righe o virgole)..."
          value={textareaValue}
          onChange={onTextAreaChange}
          className={isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}
        />
      </Form.Group>

      {/* Input per caricare file */}
      <Form.Group className="mb-3">
        <Form.Label>Carica file (.txt)</Form.Label>
        <Form.Control
          type="file"
          accept=".txt"
          onChange={onFileUpload}
          className={isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}
        />
      </Form.Group>

      {/* Checkbox per i servizi */}
      <Form.Group className="mb-3">
        <h3>Servizi selezionati</h3>
        <Form.Check
          type="checkbox"
          label="VirusTotal"
          checked={selectedServices.includes("VirusTotal")}
          onChange={(e) => onServiceToggle("VirusTotal", e.target.checked)}
          className={isDarkMode ? "text-white" : "text-dark"}
        />
        <Form.Check
          type="checkbox"
          label="AbuseIPDB"
          checked={selectedServices.includes("AbuseIPDB")}
          onChange={(e) => onServiceToggle("AbuseIPDB", e.target.checked)}
          className={isDarkMode ? "text-white" : "text-dark"}
        />
      </Form.Group>

      {/* Pulsanti per avviare il controllo e cancellare la lista */}
      <div className="d-grid gap-2 mb-4">
        <Button
          variant="primary"
          onClick={onCheckBulk}
          disabled={isLoading}
        >
          {isLoading ? (
            <>
              <Spinner as="span" size="sm" animation="border" role="status" aria-hidden="true" />
              <span className="ms-2">Controllo in corso...</span>
            </>
          ) : (
            "Avvia Controllo"
          )}
        </Button>
        <Button variant="outline-danger" onClick={onClearList}>
          Cancella Lista
        </Button>
      </div>

      {/* Messaggio di stato */}
      {message && <p className={`text-center ${isLoading ? "text-muted" : ""}`}>{message}</p>}

      {/* Contatori giornalieri */}
      <Card className={`mb-4 ${isDarkMode ? "bg-secondary text-white" : "bg-light text-dark"}`}>
        <Card.Body>
          <h2>Contatori Giornalieri</h2>
          <p>Chiamate VirusTotal oggi: <Badge bg="info">{vtCount}</Badge></p>
          <p>Chiamate AbuseIPDB oggi: <Badge bg="danger">{abuseCount}</Badge></p>
        </Card.Body>
      </Card>

      {/* Risultati */}
      <h2>Risultati</h2>
      {results &&
        Object.entries(results).map(([ioc, result]) => (
          <Card key={ioc} className={`mb-3 ${isDarkMode ? "bg-secondary text-white" : "bg-light text-dark"}`}>
            <Card.Body>
              <Card.Title>{ioc}</Card.Title>
              <pre>{parseAndFormatResults(result)}</pre>
            </Card.Body>
          </Card>
        ))}
    </Container>
  );
};

export default BulkCheckUI;