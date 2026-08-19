import "@plasmohq/messaging"

declare module "@plasmohq/messaging" {
  interface MessagesMetadata {
    "check-bulk-iocs": {}
    "check-subnet-abuse": {}
    "clear-api-cache": {}
    "magic-ioc-request": {}
    "query-library": {}
    "query-sources": {}
  }
}
