import { useState, useEffect } from "react";

const Popup = () => {
  const [ioc, setIoc] = useState<string>("");

  // Leggi l'IOC dai parametri dell'URL
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const iocParam = urlParams.get("ioc");
    if (iocParam) {
      setIoc(iocParam);
    }
  }, []);

  // Funzione per chiudere il popup
  const handleClose = () => {
    window.close(); // Chiude il popup
  };

  return (
    <div style={{ padding: "16px", minWidth: "200px" }}>
      <h3>Analisi IOC</h3>
      <p>{ioc}</p>
      <button onClick={handleClose}>Chiudi</button>
    </div>
  );
};

export default Popup;