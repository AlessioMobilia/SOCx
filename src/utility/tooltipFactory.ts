import tippy from "tippy.js"

export const createTooltip = (text: string, button: HTMLButtonElement) => {
  let formatted = text.replaceAll("\n", "<br>")

  let threatStatus: "malicious" | "suspicious" | "benign" | "unknown" = "unknown"

  // Highlight "Abuse Score"
  formatted = formatted.replace(/Abuse Score:\s*(\d+)\%/g, (match, val) => {
    const score = parseInt(val)
    if (score === 0) {
      threatStatus = "benign"
      return `<span class="ioc-benign">${match}</span>`
    } else {
      threatStatus = "malicious"
      return `<span class="ioc-malicious">${match}</span>`
    }
  })

  // Highlight "Malicious"
  formatted = formatted.replace(/Malicious:\s*(\d+)/g, (match, val) => {
    const detections = parseInt(val)
    if (detections > 5) {
      threatStatus = "malicious"
      return `<span class="ioc-malicious">${match}</span>`
    } else if (detections > 0) {
      threatStatus = "suspicious"
      return `<span class="ioc-suspicious">${match}</span>`
    } else {
      threatStatus = "benign"
      return `<span class="ioc-benign">${match}</span>`
    }
  })

  const statusBadge = {
    malicious: `<div class="ioc-badge ioc-badge--malicious">⚠️ Malicious IOC</div>`,
    benign: `<div class="ioc-badge ioc-badge--benign">✅ Non-malicious IOC</div>`,
    suspicious: `<div class="ioc-badge ioc-badge--suspicious">❓ Suspicious IOC</div>`,
    unknown: `<div class="ioc-badge ioc-badge--unknown">ℹ️ Unknown Status</div>`
  }[threatStatus]

  const contentHTML = `
    <div class="socx-extension-container">
      <div class="SOCx-tooltip ioc-tooltip-wrapper">
        ${statusBadge}
        <div class="ioc-tooltip-content">${formatted}</div>
      </div>
    </div>
  `

  chrome.storage.local.get("isDarkMode", ({ isDarkMode }) => {
    const tooltipTheme = isDarkMode ? "socx-dark" : "socx-light"

    tippy(button, {
      allowHTML: true,
      content: contentHTML,
      theme: tooltipTheme,
      maxWidth: 400,
      interactive: true,
      placement: "right",
      animation: false // disable animation
    }).show()
  })
}
