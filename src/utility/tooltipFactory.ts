import tippy from "tippy.js";

export const createTooltip = (text: string, button: HTMLButtonElement) => {
  let formatted = text.replaceAll("\n", "<br>");

  let threatStatus = "unknown";

  // Highlight "Abuse Score"
  formatted = formatted.replace(/Abuse Score:\s*(\d+)\%/g, (match, val) => {
    const score = parseInt(val);
    const cssClass = score === 0 ? "ioc-benign" : "ioc-malicious";
    threatStatus = score === 0 ? "benign" : "malicious";
    return `<span class="${cssClass}">${match}</span>`;
  });

  // Highlight "Malicious"
  formatted = formatted.replace(/Malicious:\s*(\d+)/g, (match, val) => {
    const detections = parseInt(val);
    let cssClass = "ioc-unknown";
    if (detections > 5) {
      cssClass = "ioc-malicious";
      threatStatus = "malicious";
    } else if (detections > 0) {
      cssClass = "ioc-suspicious";
      threatStatus = "suspicious";
    } else {
      cssClass = "ioc-benign";
      threatStatus = "benign";
    }
    return `<span class="${cssClass}">${match}</span>`;
  });

  // Status badge HTML
  const statusBadge = {
    malicious: `<div class="ioc-badge ioc-badge--malicious">⚠️ Malicious IOC</div>`,
    benign: `<div class="ioc-badge ioc-badge--benign">✅ Non-malicious IOC</div>`,
    suspicious: `<div class="ioc-badge ioc-badge--suspicious">❓ Suspicious IOC</div>`,
    unknown: ``,
  }[threatStatus];

  const contentHTML = `
    <div class="ioc-tooltip-wrapper">
      ${statusBadge}
      <div class="ioc-tooltip-content">${formatted}</div>
    </div>
  `;

  // Check system dark mode preference
  const isDarkMode = window.matchMedia?.('(prefers-color-scheme: dark)').matches;

  // Apply dynamic classes based on dark or light mode
  const tooltipTheme = isDarkMode ? 'socx-dark' : 'socx-light';

  // Use tippy.js to create a tooltip
  tippy(button, {
    allowHTML: true,
    content: contentHTML,
    theme: tooltipTheme,  // Uses tippy's built-in themes based on system preference
    maxWidth: 400,
    interactive: true,  // Ensures the tooltip stays open while hovering
    placement: 'right',
    animation: 'fade',  // Smooth fade-in and fade-out animation
    onShow(instance) {
      // Add the class 'socx-extension-container' to the popper element
      instance.popper.classList.add("socx-extension-container");
      instance.popper.classList.add("SOCx-tooltip");  // Optional for specific styling
    }
  }).show();
};
