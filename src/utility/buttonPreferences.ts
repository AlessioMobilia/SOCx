export const SELECTION_BUTTONS_KEY = "floatingButtonsEnabled"
export const SERVICE_PAGE_COPY_BUTTONS_KEY = "servicePageCopyButtonsEnabled"

export const SELECTION_BUTTONS_MESSAGE = "floating-buttons-preference-changed"
export const SERVICE_PAGE_COPY_BUTTONS_MESSAGE =
  "service-page-copy-buttons-preference-changed"

export const resolveSelectionButtonsPreference = (value: unknown): boolean =>
  typeof value === "boolean" ? value : true

export const resolveServicePageCopyButtonsPreference = (
  value: unknown,
  legacySelectionValue?: unknown
): boolean =>
  typeof value === "boolean"
    ? value
    : resolveSelectionButtonsPreference(legacySelectionValue)
