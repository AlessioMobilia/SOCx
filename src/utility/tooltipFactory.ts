import tippy from "tippy.js"

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
    unknown: ``
  }[threatStatus];

  const contentHTML = `
    <div class="ioc-tooltip-wrapper">
      ${statusBadge}
      <div class="ioc-tooltip-content">${formatted}</div>
    </div>
  `;

  const isDarkMode = window.matchMedia?.('(prefers-color-scheme: dark)').matches;

  tippy(button, {
    allowHTML: true,
    content: contentHTML,
    theme: isDarkMode ? 'socx-dark' : 'socx-light',
    maxWidth: 400,
    interactive: true,
    placement: 'right',
    onShow(instance) {
      instance.popper.classList.add("SOCx-tooltip");
    }
  }).show();
};
