export type VisualRect = {
  top: number
  right: number
  bottom: number
  left: number
  width: number
  height: number
}

export type VisualToken = {
  text: string
  rect: VisualRect | null
  order: number
  element: HTMLElement
  parent: HTMLElement | null
  explicitLabel: boolean
  labelMarker: boolean
  emphasized: boolean
  fontWeight: number
  fontSize: number
}

export type VisualSelectionSnapshot = {
  text: string
  tokens: VisualToken[]
  geometryAvailable: boolean
}

export type VisualPair = {
  key: string
  value: string
  keyOrders: number[]
  valueOrders: number[]
  confidence: number
  singleSafe: boolean
}

export type VisualFormatCandidate = {
  pairs: Array<[string, string]>
  coverage: number
  score: number
}

type VisualLine = {
  tokens: VisualToken[]
  rect: VisualRect
  text: string
}

type VisualItem = {
  tokens: VisualToken[]
  rect: VisualRect
  text: string
  owner: HTMLElement
}

const normalizeText = (value: string | null | undefined): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")
    .replace(/[\t ]+/g, " ")
    .trim()

const normalizeSelectionText = (value: string | null | undefined): string =>
  (value ?? "")
    .replace(/\u00a0/g, " ")
    .replace(/[\u200b-\u200d\ufeff]/g, "")
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.replace(/[\t ]+/g, " ").trim())
    .filter(Boolean)
    .join("\n")

const normalizeLabel = (value: string): string =>
  normalizeText(value)
    .replace(/^[-•]\s*/, "")
    .replace(/[\s:：=.-]+$/, "")
    .trim()

const rectFrom = (rect: DOMRect | ClientRect): VisualRect => ({
  top: rect.top,
  right: rect.right,
  bottom: rect.bottom,
  left: rect.left,
  width: rect.width,
  height: rect.height
})

const unionRects = (rects: VisualRect[]): VisualRect | null => {
  if (rects.length === 0) return null
  const top = Math.min(...rects.map((rect) => rect.top))
  const right = Math.max(...rects.map((rect) => rect.right))
  const bottom = Math.max(...rects.map((rect) => rect.bottom))
  const left = Math.min(...rects.map((rect) => rect.left))
  return {
    top,
    right,
    bottom,
    left,
    width: Math.max(0, right - left),
    height: Math.max(0, bottom - top)
  }
}

const hasArea = (rect: VisualRect): boolean =>
  Number.isFinite(rect.width) &&
  Number.isFinite(rect.height) &&
  rect.width > 0 &&
  rect.height > 0

const parseFontWeight = (value: string): number => {
  if (/^bold(?:er)?$/i.test(value)) return 700
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 400
}

const isActionControl = (element: HTMLElement): boolean => {
  if (
    !element.matches(
      "button, [role='button'], [role='menuitem'], [role='checkbox'], [role='switch'], [role='tab']"
    )
  ) {
    return false
  }

  const marker = [
    element.id,
    element.className,
    element.getAttribute("data-testid"),
    element.getAttribute("data-test"),
    element.getAttribute("aria-label"),
    element.getAttribute("title")
  ]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")

  return /\b(copy|clipboard|expand|collapse|menu|more|sort|filter|help|info|close|dismiss|edit|delete|remove|toggle)\b/i.test(
    marker
  )
}

const isNoiseElement = (
  element: HTMLElement,
  boundary: HTMLElement | null
): boolean => {
  let current: HTMLElement | null = element
  while (current) {
    if (
      current.hidden ||
      current.hasAttribute("inert") ||
      current.getAttribute("aria-hidden") === "true" ||
      current.matches(
        "script, style, noscript, template, iframe, object, embed, svg, [role='tooltip'], [data-tippy-root]"
      ) ||
      isActionControl(current)
    ) {
      return true
    }

    if (
      typeof current.ownerDocument?.defaultView?.getComputedStyle === "function"
    ) {
      const style = current.ownerDocument.defaultView.getComputedStyle(current)
      const opacity = Number(style.opacity || "1")
      const rect = rectFrom(current.getBoundingClientRect())
      const visuallyClipped =
        /inset\(\s*50%\s*\)|circle\(\s*0/i.test(style.clipPath) ||
        (/^(?:absolute|fixed)$/.test(style.position) &&
          style.overflow === "hidden" &&
          rect.width <= 1 &&
          rect.height <= 1)
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.visibility === "collapse" ||
        (Number.isFinite(opacity) && opacity <= 0) ||
        visuallyClipped
      ) {
        return true
      }
    }

    if (current === boundary) break
    current = current.parentElement
  }
  return false
}

const rangeIntersectsNode = (range: Range, node: Node): boolean => {
  try {
    return range.intersectsNode(node)
  } catch {
    return false
  }
}

const selectedNodeText = (range: Range, node: Text): string => {
  const length = node.data.length
  let start = 0
  let end = length
  if (range.startContainer === node) start = Math.min(range.startOffset, length)
  if (range.endContainer === node) end = Math.min(range.endOffset, length)
  return normalizeText(node.data.slice(start, Math.max(start, end)))
}

const textNodeRect = (range: Range, node: Text): VisualRect | null => {
  const document = node.ownerDocument
  const nodeRange = document.createRange()
  nodeRange.selectNodeContents(node)
  if (range.startContainer === node) {
    nodeRange.setStart(node, Math.min(range.startOffset, node.data.length))
  }
  if (range.endContainer === node) {
    nodeRange.setEnd(node, Math.min(range.endOffset, node.data.length))
  }

  const rangeRects =
    typeof nodeRange.getClientRects === "function"
      ? Array.from(nodeRange.getClientRects()).map(rectFrom).filter(hasArea)
      : []
  if (rangeRects.length > 0) return unionRects(rangeRects)

  const elementRect = node.parentElement?.getBoundingClientRect()
  return elementRect && hasArea(rectFrom(elementRect))
    ? rectFrom(elementRect)
    : null
}

const labelMarkerFor = (element: HTMLElement): boolean => {
  const marker = [
    element.className,
    element.id,
    element.getAttribute("data-testid"),
    element.getAttribute("data-test")
  ]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
  return /(?:^|[-_\s])(label|field-name|key|term)(?:$|[-_\s])/i.test(marker)
}

const explicitLabelFor = (element: HTMLElement): boolean =>
  Boolean(
    element.closest(
      "label, dt, th, [role='rowheader'], [role='columnheader'], [data-field-label]"
    )
  )

const rootForRange = (range: Range): Node => {
  const common = range.commonAncestorContainer
  return common.nodeType === Node.TEXT_NODE
    ? (common.parentNode ?? common)
    : common
}

const collectOpenShadowRoots = (root: Document | ShadowRoot): ShadowRoot[] => {
  const roots: ShadowRoot[] = []
  root.querySelectorAll("*").forEach((element) => {
    if (!element.shadowRoot) return
    roots.push(element.shadowRoot)
    roots.push(...collectOpenShadowRoots(element.shadowRoot))
  })
  return roots
}

const rangeFromAbstractRange = (
  document: Document,
  source: AbstractRange
): Range | null => {
  if (
    source.startContainer.getRootNode() !== source.endContainer.getRootNode()
  ) {
    return null
  }
  try {
    const range = document.createRange()
    range.setStart(source.startContainer, source.startOffset)
    range.setEnd(source.endContainer, source.endOffset)
    return range
  } catch {
    return null
  }
}

const rangesForSelection = (selection: Selection): Range[] => {
  const document = selection.anchorNode?.ownerDocument ?? window.document
  if (typeof selection.getComposedRanges === "function") {
    try {
      const shadowRoots = collectOpenShadowRoots(document)
      const composed = selection
        .getComposedRanges({ shadowRoots })
        .map((range) => rangeFromAbstractRange(document, range))
        .filter((range): range is Range => !!range)
      if (composed.length > 0) return composed
    } catch {
      // Older engines may expose the method without accepting shadow roots.
    }
  }

  const ranges: Range[] = []
  for (let index = 0; index < selection.rangeCount; index += 1) {
    ranges.push(selection.getRangeAt(index).cloneRange())
  }
  return ranges
}

export const captureVisualSelection = (
  selection: Selection
): VisualSelectionSnapshot | null => {
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
    return null
  }

  const ranges = rangesForSelection(selection)
  if (ranges.length === 0) return null
  const tokens: VisualToken[] = []
  ranges.forEach((range) => {
    const root = rootForRange(range)
    const boundary =
      root.nodeType === Node.ELEMENT_NODE ? (root as HTMLElement) : null
    const document = range.startContainer.ownerDocument
    const nodes: Text[] = []

    if (root.nodeType === Node.TEXT_NODE) {
      nodes.push(root as Text)
    } else {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      while (walker.nextNode()) nodes.push(walker.currentNode as Text)
    }

    nodes.forEach((node) => {
      if (!rangeIntersectsNode(range, node)) return
      const text = selectedNodeText(range, node)
      const element = node.parentElement
      if (!text || !element || isNoiseElement(element, boundary)) return

      const style = document.defaultView?.getComputedStyle(element)
      tokens.push({
        text,
        rect: textNodeRect(range, node),
        order: tokens.length,
        element,
        parent: element.parentElement,
        explicitLabel: explicitLabelFor(element),
        labelMarker: labelMarkerFor(element),
        emphasized: Boolean(element.closest("strong, b")),
        fontWeight: parseFontWeight(style?.fontWeight ?? "400"),
        fontSize: Number.parseFloat(style?.fontSize ?? "16") || 16
      })
    })
  })

  return {
    text: normalizeSelectionText(
      ranges.map((range) => range.toString()).join("\n") || selection.toString()
    ),
    tokens,
    geometryAvailable: tokens.some((token) => token.rect && hasArea(token.rect))
  }
}

const looksLikeStandaloneValue = (value: string): boolean => {
  const text = normalizeText(value)
  return (
    /^https?:\/\//i.test(text) ||
    /^\w+:\/\//i.test(text) ||
    /^\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/.test(text) ||
    /^\d{4}-\d{2}-\d{2}(?:T|\s)/.test(text) ||
    /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(text) ||
    /^(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9]{0,4}$/.test(text) ||
    /^[A-Fa-f0-9]{32,128}$/.test(text) ||
    /^\S+@\S+\.\S+$/.test(text) ||
    /^\/?(?:[A-Za-z]:\\|[\w.-]+\/)[^\s]*$/.test(text)
  )
}

const isLikelyLabel = (value: string): boolean => {
  const label = normalizeLabel(value)
  if (!label || label.length > 96 || looksLikeStandaloneValue(label)) {
    return false
  }
  if (!/[\p{L}\p{N}]/u.test(label) || /^[\d\W_]+$/u.test(label)) {
    return false
  }
  return label.split(/\s+/).length <= 12
}

const labelScore = (token: VisualToken): number => {
  let score = 0
  if (token.explicitLabel) score += 6
  if (token.labelMarker) score += 4
  if (/[:：]\s*$/.test(token.text)) score += 4
  if (token.emphasized) score += 2
  if (token.fontWeight >= 600) score += 2
  if (isLikelyLabel(token.text)) score += 1
  if (looksLikeStandaloneValue(token.text)) score -= 6
  if (token.text.length > 96 || token.text.split(/\s+/).length > 12) score -= 3
  return score
}

const semanticOwner = (token: VisualToken): HTMLElement =>
  token.element.closest<HTMLElement>(
    "label, dt, dd, th, strong, b, [role='rowheader'], [role='columnheader']"
  ) ?? token.element

const itemsForLine = (line: VisualLine): VisualItem[] => {
  const items: VisualItem[] = []
  line.tokens.forEach((token) => {
    const owner = semanticOwner(token)
    const previous = items[items.length - 1]
    if (previous?.owner === owner) {
      previous.tokens.push(token)
      previous.rect = unionRects(
        previous.tokens
          .map((item) => item.rect)
          .filter((rect): rect is VisualRect => !!rect)
      )!
      previous.text = normalizeText(
        previous.tokens.map((item) => item.text).join(" ")
      )
      return
    }
    if (!token.rect) return
    items.push({ tokens: [token], rect: token.rect, text: token.text, owner })
  })
  return items
}

const itemLabelScore = (item: VisualItem): number =>
  Math.max(...item.tokens.map(labelScore))

const verticalOverlap = (left: VisualRect, right: VisualRect): number => {
  const overlap = Math.max(
    0,
    Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top)
  )
  return overlap / Math.max(1, Math.min(left.height, right.height))
}

const horizontalOverlap = (upper: VisualRect, lower: VisualRect): number => {
  const overlap = Math.max(
    0,
    Math.min(upper.right, lower.right) - Math.max(upper.left, lower.left)
  )
  return overlap / Math.max(1, Math.min(upper.width, lower.width))
}

const lineForToken = (token: VisualToken): VisualLine | null =>
  token.rect
    ? { tokens: [token], rect: token.rect, text: normalizeText(token.text) }
    : null

const buildLines = (tokens: VisualToken[]): VisualLine[] => {
  const positioned = tokens
    .filter(
      (token): token is VisualToken & { rect: VisualRect } => !!token.rect
    )
    .sort(
      (left, right) =>
        left.rect.top - right.rect.top ||
        left.rect.left - right.rect.left ||
        left.order - right.order
    )
  const lines: VisualLine[] = []

  positioned.forEach((token) => {
    const matching = lines.find(
      (line) =>
        verticalOverlap(line.rect, token.rect) >= 0.45 ||
        Math.abs(
          (line.rect.top + line.rect.bottom) / 2 -
            (token.rect.top + token.rect.bottom) / 2
        ) <= Math.max(3, Math.min(line.rect.height, token.rect.height) * 0.4)
    )
    if (!matching) {
      const line = lineForToken(token)
      if (line) lines.push(line)
      return
    }
    matching.tokens.push(token)
    matching.tokens.sort(
      (left, right) =>
        (left.rect?.left ?? 0) - (right.rect?.left ?? 0) ||
        left.order - right.order
    )
    matching.rect = unionRects(
      matching.tokens
        .map((item) => item.rect)
        .filter((rect): rect is VisualRect => !!rect)
    )!
    matching.text = matching.tokens.map((item) => item.text).join(" ")
  })

  return lines.sort(
    (left, right) =>
      left.rect.top - right.rect.top || left.rect.left - right.rect.left
  )
}

const makePair = (
  keyTokens: VisualToken[],
  valueTokens: VisualToken[],
  confidence: number,
  singleSafe: boolean = false
): VisualPair | null => {
  const key = normalizeLabel(keyTokens.map((token) => token.text).join(" "))
  const value = normalizeText(valueTokens.map((token) => token.text).join(" "))
  if (!key || !value || key.toLowerCase() === value.toLowerCase()) return null
  return {
    key,
    value,
    keyOrders: keyTokens.map((token) => token.order),
    valueOrders: valueTokens.map((token) => token.order),
    confidence,
    singleSafe
  }
}

const horizontalPairs = (lines: VisualLine[]): VisualPair[] => {
  const pairs: VisualPair[] = []
  lines.forEach((line) => {
    const items = itemsForLine(line)
    if (items.length < 2) return

    const alternating =
      items.length % 2 === 0 &&
      items.every((item, index) => index % 2 === 1 || itemLabelScore(item) >= 2)
    if (alternating) {
      for (let index = 0; index < items.length; index += 2) {
        const pair = makePair(
          items[index].tokens,
          items[index + 1].tokens,
          5,
          true
        )
        if (pair) pairs.push(pair)
      }
      return
    }

    const key = items[0]
    const values = items.slice(1)
    const firstValue = values[0]
    if (
      itemLabelScore(key) >= 2 &&
      firstValue.rect.left >= key.rect.right - 2
    ) {
      const pair = makePair(
        key.tokens,
        values.flatMap((value) => value.tokens),
        4,
        true
      )
      if (pair) pairs.push(pair)
    }
  })
  return pairs
}

const repeatedHorizontalPairs = (lines: VisualLine[]): VisualPair[] => {
  const rows = lines
    .map((line) => ({ line, items: itemsForLine(line) }))
    .filter(({ items }) => {
      if (items.length < 2 || items.length % 2 !== 0) return false
      return items.every((item, index) => {
        if (index % 2 === 0) return itemLabelScore(item) >= 1
        return item.rect.left >= items[index - 1].rect.right - 2
      })
    })
  if (rows.length < 3) return []

  const groups: (typeof rows)[] = []
  rows.forEach((row) => {
    const matching = groups.find((group) => {
      const anchor = group[0]
      return (
        anchor.items.length === row.items.length &&
        anchor.items.every(
          (item, index) =>
            Math.abs(item.rect.left - row.items[index].rect.left) <=
            Math.max(24, item.rect.height * 2)
        )
      )
    })
    if (matching) matching.push(row)
    else groups.push([row])
  })

  const best = groups
    .filter((group) => group.length >= 3)
    .sort(
      (left, right) =>
        right.length * right[0].items.length -
        left.length * left[0].items.length
    )[0]
  if (!best) return []

  return best.flatMap(({ items }) => {
    const pairs: VisualPair[] = []
    for (let index = 0; index < items.length; index += 2) {
      // Repetition across at least three aligned rows is stronger evidence
      // than interpreting two adjacent rows as labels-above-values.
      const pair = makePair(items[index].tokens, items[index + 1].tokens, 7)
      if (pair) pairs.push(pair)
    }
    return pairs
  })
}

const alignedColumns = (
  upper: VisualLine,
  lower: VisualLine
): Array<[VisualItem, VisualItem]> => {
  const upperItems = itemsForLine(upper)
  const lowerItems = itemsForLine(lower)
  if (upperItems.length !== lowerItems.length || upperItems.length < 2) {
    return []
  }

  const pairs: Array<[VisualItem, VisualItem]> = []
  for (let index = 0; index < upperItems.length; index += 1) {
    const key = upperItems[index]
    const value = lowerItems[index]
    if (
      horizontalOverlap(key.rect, value.rect) < 0.35 &&
      Math.abs(key.rect.left - value.rect.left) > Math.max(12, key.rect.height)
    ) {
      return []
    }
    pairs.push([key, value])
  }
  return pairs
}

const sharedParent = (line: VisualLine): HTMLElement | null => {
  const items = itemsForLine(line)
  const first = items[0]?.tokens[0]?.parent ?? null
  return first &&
    items.every((item) => item.tokens.every((token) => token.parent === first))
    ? first
    : null
}

const columnGridPairs = (lines: VisualLine[]): VisualPair[] => {
  const result: VisualPair[] = []
  for (let index = 0; index < lines.length - 1; index += 1) {
    const upper = lines[index]
    const lower = lines[index + 1]
    const columns = alignedColumns(upper, lower)
    if (columns.length < 2) continue
    const upperAverage =
      columns.reduce((sum, [key]) => sum + itemLabelScore(key), 0) /
      columns.length
    const lowerAverage =
      columns.reduce((sum, [, value]) => sum + itemLabelScore(value), 0) /
      columns.length
    if (upperAverage < 1 || upperAverage < lowerAverage) continue

    const upperParent = sharedParent(upper)
    const lowerParent = sharedParent(lower)
    if (
      upperParent &&
      lowerParent &&
      upperParent !== lowerParent &&
      upperAverage <= lowerAverage + 1
    ) {
      continue
    }

    columns.forEach(([key, value]) => {
      const pair = makePair(key.tokens, value.tokens, 6)
      if (pair) result.push(pair)
    })
    index += 1
  }
  return result
}

const singleItemLines = (
  lines: VisualLine[]
): Array<{ line: VisualLine; item: VisualItem }> =>
  lines
    .map((line) => ({ line, items: itemsForLine(line) }))
    .filter(({ items }) => items.length === 1)
    .map(({ line, items }) => ({ line, item: items[0] }))

const sequentialVerticalPairs = (lines: VisualLine[]): VisualPair[] => {
  const singles = singleItemLines(lines)
  if (singles.length < 2) return []
  const strongLabelIndices = singles
    .map(({ item }, index) => ({ index, score: itemLabelScore(item) }))
    .filter(({ score }) => score >= 2)
    .map(({ index }) => index)
  const result: VisualPair[] = []

  if (strongLabelIndices.length > 0) {
    strongLabelIndices.forEach((keyIndex, position) => {
      const nextKeyIndex = strongLabelIndices[position + 1] ?? singles.length
      const key = singles[keyIndex].item
      const valueLines = singles.slice(keyIndex + 1, nextKeyIndex)
      const values = valueLines.flatMap(({ item }) => item.tokens)
      const firstValue = valueLines[0]?.item
      if (values.length === 0 || !firstValue) return
      const aligned =
        horizontalOverlap(key.rect, firstValue.rect) >= 0.3 ||
        Math.abs(key.rect.left - firstValue.rect.left) <=
          Math.max(14, key.rect.height)
      if (!aligned) return
      const pair = makePair(
        key.tokens,
        values,
        5,
        key.tokens.some((token) => token.explicitLabel || token.labelMarker) ||
          /[:：]\s*$/.test(key.text)
      )
      if (pair) result.push(pair)
    })
    return result
  }

  if (singles.length < 4 || singles.length % 2 !== 0) return []
  for (let index = 0; index < singles.length; index += 2) {
    const key = singles[index].item
    const value = singles[index + 1].item
    if (!isLikelyLabel(key.text)) return []
    const aligned =
      horizontalOverlap(key.rect, value.rect) >= 0.3 ||
      Math.abs(key.rect.left - value.rect.left) <= Math.max(14, key.rect.height)
    if (!aligned || value.rect.top < key.rect.bottom - 2) return []
    const pair = makePair(key.tokens, value.tokens, 3)
    if (!pair) return []
    result.push(pair)
  }
  return result
}

const deduplicatePairs = (pairs: VisualPair[]): VisualPair[] => {
  const accepted: VisualPair[] = []
  const consumed = new Set<number>()
  const ordered = [...pairs].sort(
    (left, right) =>
      right.confidence - left.confidence ||
      Math.min(...left.keyOrders) - Math.min(...right.keyOrders)
  )

  ordered.forEach((pair) => {
    const orders = [...pair.keyOrders, ...pair.valueOrders]
    if (orders.some((order) => consumed.has(order))) return
    accepted.push(pair)
    orders.forEach((order) => consumed.add(order))
  })

  return accepted.sort(
    (left, right) => Math.min(...left.keyOrders) - Math.min(...right.keyOrders)
  )
}

export const buildVisualCandidate = (
  snapshot: VisualSelectionSnapshot
): VisualFormatCandidate | null => {
  if (!snapshot.geometryAvailable || snapshot.tokens.length < 2) return null
  const lines = buildLines(snapshot.tokens)
  const pairs = deduplicatePairs([
    ...horizontalPairs(lines),
    ...repeatedHorizontalPairs(lines),
    ...columnGridPairs(lines),
    ...sequentialVerticalPairs(lines)
  ])
  if (pairs.length === 0) return null

  const consumedOrders = new Set(
    pairs.flatMap((pair) => [...pair.keyOrders, ...pair.valueOrders])
  )
  const totalCharacters = snapshot.tokens.reduce(
    (sum, token) => sum + token.text.length,
    0
  )
  const consumedCharacters = snapshot.tokens.reduce(
    (sum, token) =>
      sum + (consumedOrders.has(token.order) ? token.text.length : 0),
    0
  )
  const coverage =
    totalCharacters > 0 ? consumedCharacters / totalCharacters : 0
  const strongest = Math.max(...pairs.map((pair) => pair.confidence))
  const acceptable =
    coverage >= 0.7 &&
    (pairs.length >= 2 ||
      (coverage >= 0.9 && strongest >= 4 && pairs[0]?.singleSafe))
  if (!acceptable) return null

  return {
    pairs: pairs.map((pair) => [pair.key, pair.value]),
    coverage,
    score: Math.min(
      98,
      89 +
        Math.min(pairs.length, 4) +
        Math.round(coverage * 3) +
        (strongest >= 5 ? 1 : 0)
    )
  }
}

export const visualSelectionText = (
  snapshot: VisualSelectionSnapshot
): string => {
  if (!snapshot.geometryAvailable) return snapshot.text
  return buildLines(snapshot.tokens)
    .map((line) => line.text)
    .join("\n")
    .trim()
}

export const readRenderedElementText = (element: HTMLElement): string => {
  const document = element.ownerDocument
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT)
  const values: string[] = []
  while (walker.nextNode()) {
    const node = walker.currentNode as Text
    const parent = node.parentElement
    const text = normalizeText(node.textContent)
    if (!parent || !text || isNoiseElement(parent, element)) continue
    values.push(text)
  }
  return normalizeText(values.join(" "))
}
