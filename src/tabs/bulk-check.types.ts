export type BulkStatusKind = "pending" | "clean" | "flagged" | "error" | "skipped"

export type BulkServiceStatus = {
  name: string
  status: BulkStatusKind
  text: string
}

export type BulkCheckSummaryRow = {
  ioc: string
  displayType: string
  rawType: string | null
  serviceStatuses: BulkServiceStatus[]
  statusKind: BulkStatusKind
  statusText: string
  result?: any
  isPending: boolean
}
