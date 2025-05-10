import React from "react"
import "bootstrap/dist/css/bootstrap.min.css"
import { Container, Button, Form } from "react-bootstrap"
import { MdDownload, MdDelete, MdBuild, MdBugReport } from "react-icons/md"

interface SidePanelUIProps {
  note: string
  isDarkMode: boolean
  onTextChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void
  onSaveTxt: () => void
  onClearNote: () => void
  onRefang: () => void
  onDefang: () => void
}

const SidePanelUI: React.FC<SidePanelUIProps> = ({
  note,
  isDarkMode,
  onTextChange,
  onSaveTxt,
  onClearNote,
  onRefang,
  onDefang
}) => {
  const themeClass = isDarkMode ? "bg-dark text-white" : "bg-light text-dark"

  return (
    <Container fluid className={`p-3 ${themeClass}`}>
      <h6 className="text-center mb-3">📝 Blocco Note IOC</h6>

      <Form.Group className="mb-3">
        <Form.Control
          as="textarea"
          value={note}
          onChange={onTextChange}
          placeholder="Scrivi qui..."
          rows={16}
          className={`form-control ${themeClass}`}
          aria-label="Textarea per note"
        />
      </Form.Group>

      <div className="d-grid gap-2 mb-3">
        <Button variant="outline-secondary" size="sm" onClick={onRefang}>
          <MdBuild className="me-1" /> Refang
        </Button>
        <Button variant="outline-secondary" size="sm" onClick={onDefang}>
          <MdBugReport className="me-1" /> Defang
        </Button>
      </div>

      <div className="d-grid gap-2">
        <Button variant="outline-success" size="sm" onClick={onSaveTxt}>
          <MdDownload className="me-1" /> Salva come TXT
        </Button>
        <Button variant="outline-danger" size="sm" onClick={onClearNote}>
          <MdDelete className="me-1" /> Elimina tutto
        </Button>
      </div>
    </Container>
  )
}

export default SidePanelUI
