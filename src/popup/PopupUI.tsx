import "bootstrap/dist/css/bootstrap.min.css"
import { Container, Button, ListGroup } from "react-bootstrap"
import React from "react"

interface PopupUIProps {
  isDarkMode: boolean
  iocHistory: { type: string; text: string; timestamp: string }[]
  onBulkCheckClick: () => void
  onOpenSidePanelClick: () => void
  onClearHistory: () => void
}

const PopupUI: React.FC<PopupUIProps> = ({
  isDarkMode,
  iocHistory,
  onBulkCheckClick,
  onOpenSidePanelClick,
  onClearHistory
}) => {
  // Ordina per data decrescente e prendi solo i 10 più recenti
  const recentHistory = [...iocHistory]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 10)

  return (
    <Container
      fluid
      className={`p-3 ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}`}
    >
      <h1 className="h4 mb-3 text-center">Estensione IOC</h1>

      <div className="d-grid gap-2 mb-3">
        <Button variant="primary btn-sm" onClick={onBulkCheckClick}>
          Controllo Bulk IOC
        </Button>
        <Button variant="secondary btn-sm" onClick={onOpenSidePanelClick}>
          Apri Blocco Note
        </Button>
      </div>

      <h2 className="h6 mb-2 text-center">Ultimi 10 IOC</h2>

      {recentHistory.length === 0 ? (
        <p className="text-muted text-center small">Nessun IOC trovato.</p>
      ) : (
        <ListGroup variant="flush" style={{ maxHeight: "240px", overflowY: "auto" }}>
          {recentHistory.map((entry, index) => (
            <ListGroup.Item
              key={index}
              className={`py-1 px-2 small ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"} border-0`}
            >
              <span className="text-truncate d-block">{entry.text}</span>
            </ListGroup.Item>
          ))}
        </ListGroup>
      )}

      {recentHistory.length > 0 && (
        <div className="d-grid gap-2 mt-3">
          <Button variant="danger btn-sm" onClick={onClearHistory}>
            Cancella Cronologia IOC
          </Button>
        </div>
      )}
    </Container>
  )
}

export default PopupUI
