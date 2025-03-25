// src/popup/PopupUI.tsx
import "bootstrap/dist/css/bootstrap.min.css";
import { Container, Button, ListGroup } from "react-bootstrap";
import React from "react";

interface PopupUIProps {
  isDarkMode: boolean;
  iocHistory: { type: string; text: string; timestamp: string }[];
  onBulkCheckClick: () => void;
  onOpenSidePanelClick: () => void;
  onClearHistory: () => void;
}

const PopupUI: React.FC<PopupUIProps> = ({
  isDarkMode,
  iocHistory,
  onBulkCheckClick,
  onOpenSidePanelClick,
  onClearHistory,
}) => (
  <Container
    fluid
    className={`p-3 ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}`}
  >
    <h1 className="h3 mb-3 text-center">Estensione IOC</h1>

    <div className="d-grid gap-2 mb-3">
      <Button variant="primary btn-sm" onClick={onBulkCheckClick}>
        Controllo Bulk IOC
      </Button>
      <Button variant="secondary btn-sm" onClick={onOpenSidePanelClick}>
        Apri Blocco Note
      </Button>
    </div>

    <h2 className="h4 mb-3 text-center">Storico IOC</h2>

    {iocHistory.length === 0 ? (
      <p className="text-muted text-center">Nessun IOC trovato.</p>
    ) : (
      <ListGroup>
        {iocHistory.map((entry, index) => (
          <ListGroup.Item
            key={index}
            className={`${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"} border-secondary`}
          >
            <div className="d-flex justify-content-between align-items-center">
              <span className="fw-bold">{entry.text}</span>
              <small className="text-muted">
                {entry.type} • {new Date(entry.timestamp).toLocaleString()}
              </small>
            </div>
          </ListGroup.Item>
        ))}
      </ListGroup>
    )}

    {iocHistory.length > 0 && (
      <div className="d-grid gap-2 mt-3">
        <Button variant="danger" onClick={onClearHistory}>
          Cancella Cronologia IOC
        </Button>
      </div>
    )}
  </Container>
);

export default PopupUI;