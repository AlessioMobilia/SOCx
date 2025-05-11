import tippy from "tippy.js"

export const createTooltip = (text: string, button: HTMLButtonElement) => {
  let formatted = text.replaceAll("\n", "<br>");

  let threatStatus = "unknown";

  formatted = formatted.replace(/Punteggio di Abuso:\s*(\d+)\%/g, (match, val) => {
    const score = parseInt(val);
    const cssClass = score === 0 ? "ioc-benign" : "ioc-malicious";
    threatStatus = score === 0 ? "benigno" : "malevolo";
    return `<span class="${cssClass}">${match}</span>`;
  });

  formatted = formatted.replace(/Malevoli:\s*(\d+)/g, (match, val) => {
    const detections = parseInt(val);
    let cssClass = "ioc-unknown";
    if (detections > 5) {
      cssClass = "ioc-malicious";
      threatStatus = "malevolo";
    } else if (detections > 0) {
      cssClass = "ioc-suspicious";
      threatStatus = "sospetto";
    } else {
      cssClass = "ioc-benign";
      threatStatus = "benigno";
    }
    return `<span class="${cssClass}">${match}</span>`;
  });

  const statusBadge = {
    malevolo: `<div class="ioc-badge ioc-badge--malicious">⚠️ IOC Malevolo</div>`,
    benigno: `<div class="ioc-badge ioc-badge--benign">✅ IOC Non malevolo</div>`,
    sospetto: `<div class="ioc-badge ioc-badge--suspicious">❓ IOC Sospetto</div>`,
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
