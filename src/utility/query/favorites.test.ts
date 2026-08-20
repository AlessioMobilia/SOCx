import { describe, expect, it } from "vitest"

import {
  isFavoriteKey,
  MAX_FAVORITES,
  normalizeFavorites,
  toggleFavoriteKey
} from "./favorites"

describe("favorite keys", () => {
  it("drops anything that is not a usable key", () => {
    expect(
      normalizeFavorites([
        "pack::a",
        "pack::a",
        "  ",
        42,
        null,
        "x".repeat(300),
        "pack::b"
      ])
    ).toEqual(["pack::a", "pack::b"])
  })

  it("returns an empty list for corrupted storage", () => {
    expect(normalizeFavorites(undefined)).toEqual([])
    expect(normalizeFavorites("pack::a")).toEqual([])
  })

  it("caps the list", () => {
    const many = Array.from({ length: MAX_FAVORITES + 10 }, (_, i) => `k${i}`)
    expect(normalizeFavorites(many)).toHaveLength(MAX_FAVORITES)
  })

  it("adds to the front and removes on a second toggle", () => {
    const first = toggleFavoriteKey([], "a")
    expect(first).toEqual(["a"])
    const second = toggleFavoriteKey(first, "b")
    expect(second).toEqual(["b", "a"])
    expect(toggleFavoriteKey(second, "b")).toEqual(["a"])
    expect(isFavoriteKey(second, "a")).toBe(true)
    expect(isFavoriteKey(second, "z")).toBe(false)
  })

  it("never grows past the cap when starring", () => {
    const full = Array.from({ length: MAX_FAVORITES }, (_, i) => `k${i}`)
    const next = toggleFavoriteKey(full, "new")
    expect(next).toHaveLength(MAX_FAVORITES)
    expect(next[0]).toBe("new")
  })

  it("ignores an empty key", () => {
    expect(toggleFavoriteKey(["a"], "")).toEqual(["a"])
  })
})
