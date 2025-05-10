import tippy from 'tippy.js'

export const createTooltip = (text: string, button: HTMLButtonElement) => {
  let formatted = text.replaceAll("\n", "<br>");

  // Colora punteggio di abuso
  formatted = formatted.replace(/Punteggio di Abuso:\t(\d+)\%/g, (match, val) =>
    `<span class="${parseInt(val) === 0 ? "notMalicious_tooltip" : "malicious_tooltip"}">${match}</span>`
  );

  // Colora rilevamenti malevoli
  formatted = formatted.replace(/Malevoli:\t\t(\d+)/g, (match, val) =>
    `<span class="${parseInt(val) === 0 ? "notMalicious_tooltip" : "malicious_tooltip"}">${match}</span>`
  );




  tippy(button, {
    allowHTML: true,
    content: `<div>${formatted}</div>`,
    onShow(instance) {
      instance.popper.classList.add("SOCx-tooltip");
    }
  }).show();
}
