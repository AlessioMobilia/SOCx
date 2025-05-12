import { identifyIOC } from "../utility/utils";

/**
 * Creates a contextual button for a specific IOC type.
 * It displays either the VirusTotal or AbuseIPDB icon depending on the type.
 */
export function createButton(ioc: string, onClick: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  const type = identifyIOC(ioc);
  if (!type) return null;

  button.style.background = `url(${chrome.runtime.getURL(`/assets/${type === "IP" ? "abuseipdb" : "virustotal"}.png`)})`;
  button.style.backgroundSize = "cover";
  button.style.width = "25px";
  button.style.height = "25px";
  button.style.position = "absolute";
  button.style.zIndex = "1000";
  button.style.border = "none";
  button.style.borderRadius = "4px";
  button.style.cursor = "pointer";
  button.id = "IOCButton_SOCx";

  button.addEventListener("click", onClick);
  return button;
}

/**
 * Creates the "Magic" IOC button that triggers the full analysis flow.
 * It uses a generic extension icon and a yellow background.
 */
export function createMagicButton(ioc: string, onClick: () => void): HTMLButtonElement {
  const button = document.createElement("button");
  button.style.background = `url(${chrome.runtime.getURL("/assets/icon.png")})`;
  button.style.backgroundSize = "cover";
  button.style.width = "25px";
  button.style.height = "25px";
  button.style.position = "absolute";
  button.style.zIndex = "1000";
  button.style.border = "none";
  button.style.borderRadius = "4px";
  button.style.cursor = "pointer";
  button.style.backgroundColor = "#FFC107";
  button.id = "MagicButton_SOCx";

  button.addEventListener("click", onClick);
  return button;
}
