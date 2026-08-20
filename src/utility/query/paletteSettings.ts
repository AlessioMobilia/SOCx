// Palette preferences that belong to the analyst rather than to a pack.
//
// Kept apart from `paletteBridge`, which the background imports for its own
// settings, so the content script only pulls in the storage it actually uses.

import { Storage } from "@plasmohq/storage"

export const QUERY_MERGE_TYPES_KEY = "queryMergeTypes"

/**
 * One query covering every indicator type is what an analyst pastes into a
 * console, so it is the default; templates that cannot be merged still fall
 * back to one query per type on their own.
 */
export const DEFAULT_QUERY_MERGE_TYPES = true

const store = () => new Storage({ area: "local" })

export const readMergeTypes = async (): Promise<boolean> => {
  try {
    const stored = await store().get(QUERY_MERGE_TYPES_KEY)
    return typeof stored === "boolean" ? stored : DEFAULT_QUERY_MERGE_TYPES
  } catch {
    return DEFAULT_QUERY_MERGE_TYPES
  }
}

export const writeMergeTypes = async (value: boolean): Promise<void> => {
  await store().set(QUERY_MERGE_TYPES_KEY, value)
}
