// src/utility/iocTypes.ts

// Lista dei tipi di IOC supportati
export const supportedIOCTypes = [
  "IP",
  "Dominio",
  "URL",
  "Hash",
  "Email",
  "ASN",
  "MAC"
] as const

// Tipo letterale per singolo IOC
export type IOCType = (typeof supportedIOCTypes)[number]

// Struttura dei servizi personalizzati salvabili dall’utente
export type CustomService = {
  type: IOCType
  name: string
  url: string // Deve contenere {ioc}
}
