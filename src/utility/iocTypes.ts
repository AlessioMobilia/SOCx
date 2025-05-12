// src/utility/iocTypes.ts

// List of supported IOC types
export const supportedIOCTypes = [
  "IP",
  "Domain",
  "URL",
  "Hash",
  "Email",
  "ASN",
  "MAC"
] as const

// Literal type for a single IOC
export type IOCType = (typeof supportedIOCTypes)[number]

// Structure of user-defined custom services
export type CustomService = {
  type: IOCType
  name: string
  url: string // Must include {ioc}
}
