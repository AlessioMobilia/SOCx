import { describe, expect, it } from "vitest"

import {
  canonicalizeIOC,
  defang,
  extractIOCs,
  identifyIOC,
  isAlreadyDefanged,
  looksLikeFileName,
  refang
} from "./utils"

describe("defang", () => {
  it("keeps the transport marker of the original scheme", () => {
    expect(defang("https://evil.com/path")).toBe("hxxps://evil[.]com/path")
    expect(defang("http://evil.com")).toBe("hxxp://evil[.]com")
  })

  it("neutralises IPv6 addresses on their separator", () => {
    expect(defang("2001:db8::1")).toBe("2001[:]db8[:][:]1")
  })

  it("round-trips through refang without losing TLS information", () => {
    const original = "https://Evil.com/AbC123?x=Y"
    expect(refang(defang(original))).toBe(original)
  })
})

describe("refang", () => {
  it("restores every occurrence, not only the first one", () => {
    expect(refang("hxxp://a[.]com and hxxps://b[.]com")).toBe(
      "http://a.com and https://b.com"
    )
  })

  it("preserves the case of URL paths", () => {
    expect(refang("hxxps://evil[.]com/AbC3xYz")).toBe(
      "https://evil.com/AbC3xYz"
    )
  })

  it("handles the common obfuscation markers", () => {
    expect(refang("evil(.)com")).toBe("evil.com")
    expect(refang("evil{.}com")).toBe("evil.com")
    expect(refang("evil[dot]com")).toBe("evil.com")
    expect(refang("evil\\.com")).toBe("evil.com")
    expect(refang("user[at]evil[.]com")).toBe("user@evil.com")
    expect(refang("2001[:]db8[:][:]1")).toBe("2001:db8::1")
    expect(refang("hxxtps://evil[.]com")).toBe("https://evil.com")
    expect(refang("meow://evil[.]com")).toBe("http://evil.com")
  })

  it("does not rewrite unrelated backslash sequences", () => {
    expect(refang(String.raw`C:\Windows\Temp\sample.exe`)).toBe(
      String.raw`C:\Windows\Temp\sample.exe`
    )
    expect(refang(String.raw`evil\.com`)).toBe("evil.com")
  })

  it("detects defanged values with any supported marker", () => {
    expect(isAlreadyDefanged("evil[.]com")).toBe(true)
    expect(isAlreadyDefanged("hxxps://evil.com")).toBe(true)
    expect(isAlreadyDefanged("2001[:]db8[:][:]1")).toBe(true)
    expect(isAlreadyDefanged("https://evil.com")).toBe(false)
  })
})

describe("identifyIOC", () => {
  it("rejects IPv4 addresses with out-of-range octets", () => {
    expect(identifyIOC("999.999.999.999")).toBeNull()
    expect(identifyIOC("256.1.2.3")).toBeNull()
    expect(identifyIOC("8.8.8.8")).toBe("IP")
  })

  it("does not report file names as domains", () => {
    expect(identifyIOC("invoice.pdf")).toBeNull()
    expect(identifyIOC("setup.exe")).toBeNull()
    expect(identifyIOC("report.docx")).toBeNull()
    expect(identifyIOC("evil.com")).toBe("Domain")
  })

  it("keeps recognising TLDs that collide with file extensions", () => {
    expect(identifyIOC("payload.zip")).toBe("Domain")
    expect(identifyIOC("clip.mov")).toBe("Domain")
    expect(identifyIOC("readme.md")).toBe("Domain")
  })

  it("recognises internationalised domains", () => {
    expect(identifyIOC("münchen.de")).toBe("Domain")
    expect(identifyIOC("аpple.com")).toBe("Domain")
    expect(identifyIOC("xn--mnchen-3ya.de")).toBe("Domain")
  })
})

describe("looksLikeFileName", () => {
  it("only matches known non-TLD extensions", () => {
    expect(looksLikeFileName("invoice.pdf")).toBe(true)
    expect(looksLikeFileName("archive.tar.gz")).toBe(true)
    expect(looksLikeFileName("evil.com")).toBe(false)
    expect(looksLikeFileName("payload.zip")).toBe(false)
  })
})

describe("canonicalizeIOC", () => {
  it("lowercases hosts while preserving URL paths", () => {
    expect(canonicalizeIOC("HTTPS://Evil.COM/AbC")).toBe("https://evil.com/AbC")
  })

  it("normalises identifiers, hashes and domains", () => {
    expect(canonicalizeIOC("cve-2021-44228")).toBe("CVE-2021-44228")
    expect(canonicalizeIOC("as15169")).toBe("AS15169")
    expect(canonicalizeIOC("D41D8CD98F00B204E9800998ECF8427E")).toBe(
      "d41d8cd98f00b204e9800998ecf8427e"
    )
    expect(canonicalizeIOC("Evil.COM")).toBe("evil.com")
    expect(canonicalizeIOC("User.Name@Evil.COM")).toBe("User.Name@evil.com")
  })
})

describe("extractIOCs", () => {
  it("skips file names while keeping real indicators", () => {
    expect(extractIOCs("invoice.pdf dropped by 8.8.8.8 from evil.com")).toEqual(
      ["8.8.8.8", "evil.com"]
    )
  })

  it("skips IPv4 candidates with invalid octets", () => {
    expect(
      extractIOCs("version 999.999.999.999, 999[.]1[.]2[.]3 and 1.1.1.1")
    ).toEqual(["1.1.1.1"])
  })

  it("refangs and canonicalises every match", () => {
    expect(
      extractIOCs("hxxps://Evil[.]com/AbC and user[at]evil[.]com")
    ).toEqual(["https://evil.com/AbC", "user@evil.com"])
  })

  it("keeps full URLs, emails and IPv6 addresses intact", () => {
    expect(
      extractIOCs(
        "Visit https://sub.evil.com/a.pdf?x=1 mailed by user@corp.example.com via 2001:db8::1"
      )
    ).toEqual([
      "https://sub.evil.com/a.pdf?x=1",
      "user@corp.example.com",
      "2001:db8::1"
    ])
  })

  it("returns raw matches when refanging is disabled", () => {
    expect(extractIOCs("hxxps://Evil[.]com/AbC", false)).toEqual([
      "hxxps://Evil[.]com/AbC"
    ])
  })
})
