import "bootstrap/dist/css/bootstrap.min.css"
import React from "react"
import { Container, Button, ListGroup } from "react-bootstrap"
import { MdPlaylistAddCheck, MdNote, MdDelete } from "react-icons/md"

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
  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"
  const recentHistory = [...iocHistory]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 10)

  return (
    <Container fluid className={`p-3 ${themeClass}`}>
      <h5 className="text-center mb-3">🛡️ IOC Extension</h5>

      <div className="d-grid gap-2 mb-3">
        <Button variant="success" size="sm" onClick={onBulkCheckClick}>
          <MdPlaylistAddCheck className="me-1" /> Bulk Check
        </Button>
        <Button variant="secondary" size="sm" onClick={onOpenSidePanelClick}>
          <MdNote className="me-1" /> Open Notepad
        </Button>
      </div>

      <h6 className="text-center mb-2">📋 Latest 10 IOCs</h6>

      {recentHistory.length === 0 ? (
        <p className="text-muted text-center small">No IOCs recorded.</p>
      ) : (
        <ListGroup variant="flush" className="small" style={{ maxHeight: 200, overflowY: "auto" }}>
          {recentHistory.map((entry, idx) => (
            <ListGroup.Item
              key={idx}
              className={`py-1 px-2 border-0 ${themeClass}`}
            >
              <span className="text-truncate d-block">{entry.text}</span>
            </ListGroup.Item>
          ))}
        </ListGroup>
      )}

      {recentHistory.length > 0 && (
        <div className="d-grid gap-2 mt-3">
          <Button variant="outline-danger" size="sm" onClick={onClearHistory}>
            <MdDelete className="me-1" /> Clear History
          </Button>
        </div>
      )}
    </Container>
  )
}

export default PopupUI
