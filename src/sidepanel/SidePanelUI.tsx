import React from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import { Container, Button, Form } from "react-bootstrap";

interface SidePanelUIProps {
  note: string;
  isDarkMode: boolean;
  onTextChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  onSaveTxt: () => void;
  onClearNote: () => void;
  onRefang: () => void;
  onDefang: () => void;
}

const SidePanelUI: React.FC<SidePanelUIProps> = ({
  note,
  isDarkMode,
  onTextChange,
  onSaveTxt,
  onClearNote,
  onRefang,
  onDefang,
}) => (
  <Container
    fluid
    className={`p-3 ${isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}`}
  >
    <Form.Group className="mb-3">
      <Form.Control
        as="textarea"
        value={note}
        onChange={onTextChange}
        placeholder="Scrivi qui..."
        style={{ height: "400px" }}
        className={isDarkMode ? "bg-dark text-white" : "bg-light text-dark"}
      />
    </Form.Group>

    <div className="d-grid gap-2 mb-3">
      <Button variant="secondary btn-sm" onClick={onRefang}>
        Refang IOC
      </Button>
      <Button variant="secondary btn-sm" onClick={onDefang}>
        Defang IOC
      </Button>
    </div>

    <div className="d-grid gap-2">
      <Button variant="success btn-sm" onClick={onSaveTxt}>
        Salva come TXT
      </Button>
      <Button variant="danger btn-sm" onClick={onClearNote}>
        Elimina tutto
      </Button>
    </div>
  </Container>
);

export default SidePanelUI;