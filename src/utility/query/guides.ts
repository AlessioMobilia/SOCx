// Compact, source-backed language reference used by the Query workspace.
// Keep this catalogue aligned with dialects.json: the audit test intentionally
// fails when a dialect is added without a guide.

import { QUERY_GUIDE_COMMANDS, type QueryGuideCommand } from "./guideCommands"

export type QueryGuideItem = {
  term: string
  description: string
  example?: string
  notes?: string[]
}

export type QueryLanguageGuide = {
  dialectId: string
  summary: string
  documentationUrl: string
  documentationLabel: string
  fields: QueryGuideItem[]
  commands: QueryGuideCommand[]
  caution?: string
}

type QueryLanguageGuideSeed = Omit<QueryLanguageGuide, "commands"> & {
  commands: QueryGuideItem[]
}

const QUERY_LANGUAGE_GUIDE_SEEDS: QueryLanguageGuideSeed[] = [
  {
    dialectId: "kql",
    summary:
      "Piped analytics language used by Microsoft Defender XDR, Microsoft Sentinel, Azure Data Explorer and Azure Monitor.",
    documentationUrl:
      "https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference",
    documentationLabel: "Microsoft KQL quick reference",
    fields: [
      {
        term: "Timestamp / TimeGenerated",
        description:
          "Event time. Defender advanced-hunting tables normally use Timestamp; many Sentinel tables use TimeGenerated."
      },
      {
        term: "DeviceName / Computer",
        description:
          "Host identity. The exact name depends on the selected table and product."
      },
      {
        term: "RemoteIP / SourceIP / DestinationIP",
        description: "Common network endpoint fields across hunting tables."
      },
      {
        term: "RemoteUrl / DomainName / Url",
        description: "Common URL and DNS fields used by SOCx IOC templates."
      },
      {
        term: "SHA1 / SHA256 / FileHashValue",
        description: "File-hash fields; availability depends on the table."
      }
    ],
    commands: [
      { term: "where", description: "Filters rows by a Boolean predicate." },
      { term: "project", description: "Keeps, renames or reorders columns." },
      { term: "extend", description: "Adds calculated columns." },
      {
        term: "summarize ... by",
        description:
          "Aggregates rows, optionally grouped by one or more fields."
      },
      { term: "sort by", description: "Orders the result set." },
      { term: "take / limit", description: "Returns a bounded row sample." },
      { term: "join", description: "Combines rows from two tabular inputs." },
      {
        term: "in~ / has_any",
        description:
          "Case-insensitive membership and term-list matching used by SOCx templates."
      },
      {
        term: "matches regex",
        description: "Matches a string against a regular expression."
      }
    ],
    caution:
      "Microsoft KQL and Elastic KQL share an acronym but are unrelated languages. Always start from the table that owns the fields you reference."
  },
  {
    dialectId: "spl",
    summary:
      "Splunk's piped Search Processing Language for Splunk Enterprise and Splunk Cloud Platform.",
    documentationUrl:
      "https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.0/quick-reference/command-quick-reference",
    documentationLabel: "Splunk SPL command quick reference",
    fields: [
      {
        term: "_time",
        description:
          "The event timestamp, stored internally as Unix time and rendered for the user's time zone. The time picker, timechart, bin and relative-time modifiers all operate on it.",
        example: "earliest=-24h | bin _time span=15m",
        notes: [
          "It represents event time, not necessarily ingestion time.",
          "Keep _time when a later command needs a timeline or time bucket."
        ]
      },
      {
        term: "_raw",
        description:
          "The original event payload. Bare keyword searches inspect it and search-time field extractions commonly derive structured fields from it.",
        example: '| regex _raw="(?i)failed login"',
        notes: [
          "Searching a well-scoped extracted field is usually clearer than repeatedly scanning _raw.",
          "The displayed raw text can contain fields that are not indexed fields."
        ]
      },
      {
        term: "index",
        description:
          "The Splunk index that stores the event. Restricting index and time as early as possible is one of the most important ways to reduce the amount of data read.",
        example: "index=security earliest=-1h",
        notes: [
          "Access is limited to the indexes allowed for the current role.",
          "tstats can query this index-time field directly from tsidx data."
        ]
      },
      {
        term: "source",
        description:
          "The concrete input an event came from, such as a file path, stream, script or network input. It identifies origin, not event format.",
        example: 'source="/var/log/auth.log"',
        notes: [
          "For network inputs it can look like udp:514.",
          "Many sources can share the same sourcetype."
        ]
      },
      {
        term: "sourcetype",
        description:
          "The data format and parsing classification assigned to an event. It drives event breaking, timestamp recognition and many search-time field extractions.",
        example: "sourcetype=WinEventLog:Security",
        notes: [
          "Use it to scope a search to comparable event shapes.",
          "It is different from source: format versus concrete input."
        ]
      },
      {
        term: "host",
        description:
          "The default origin tag assigned during ingestion, commonly a hostname, IP address or FQDN. It may describe a collector or forwarded source rather than the affected endpoint.",
        example: 'host="dc-01"',
        notes: [
          "Confirm the add-on's semantics before treating host as the endpoint.",
          "CIM fields such as src and dest can be more precise for network events."
        ]
      },
      {
        term: "src / dest / user / process",
        description:
          "Common Information Model (CIM) field names used to normalize source, destination, identity and process concepts across vendors.",
        example: "| stats count by src, dest, user",
        notes: [
          "They exist only when the source add-on, aliases or calculated fields map the original data correctly.",
          "Accelerated CIM data models expose prefixed fields such as Authentication.user to tstats."
        ]
      },
      {
        term: "_indextime / splunk_server",
        description:
          "Internal metadata for ingestion time and the indexer that handled an event. These fields are mainly useful for latency and platform troubleshooting.",
        example: "| eval ingest_delay=_indextime-_time",
        notes: [
          "_indextime is different from the event timestamp in _time.",
          "Internal fields may be hidden unless explicitly used or renamed."
        ]
      }
    ],
    commands: [
      {
        term: "search",
        description: "Filters events by terms or field comparisons."
      },
      { term: "where", description: "Filters with eval-style expressions." },
      { term: "rex", description: "Extracts or replaces fields with a regex." },
      { term: "eval", description: "Creates or updates calculated fields." },
      {
        term: "stats ... by",
        description: "Calculates grouped aggregate statistics."
      },
      { term: "timechart", description: "Builds a time-series aggregation." },
      { term: "table / fields", description: "Selects fields for the result." },
      {
        term: "sort / dedup",
        description: "Orders rows or removes duplicates."
      },
      {
        term: "IN (...) / AND / OR / NOT",
        description: "Membership and Boolean search operators."
      }
    ]
  },
  {
    dialectId: "udm",
    summary:
      "Google Security Operations search over events normalized to the Unified Data Model (UDM).",
    documentationUrl:
      "https://docs.cloud.google.com/chronicle/docs/investigation/udm-search",
    documentationLabel: "Google SecOps UDM search",
    fields: [
      {
        term: "metadata.event_type",
        description: "Normalized event category, such as NETWORK_CONNECTION."
      },
      {
        term: "principal.* / src.*",
        description: "Actor or source asset, user, process and IP fields."
      },
      {
        term: "target.*",
        description:
          "Destination asset, user, process, file, URL and IP fields."
      },
      {
        term: "network.*",
        description: "Protocol, DNS, HTTP, email and connection details."
      },
      {
        term: "security_result.*",
        description: "Detection, action, rule and severity context."
      }
    ],
    commands: [
      {
        term: "= / != / < / <= / > / >=",
        description: "Field comparisons supported according to field type."
      },
      {
        term: "AND / OR / NOT",
        description: "Combines or negates search expressions."
      },
      {
        term: "nocase",
        description: "Makes a supported string comparison case-insensitive."
      },
      {
        term: "/pattern/",
        description: "Regular-expression value syntax in UDM search."
      },
      {
        term: "ip / domain / user",
        description: "Grouped fields that search several related UDM paths."
      }
    ],
    caution:
      "UDM paths are schema fields, not raw vendor fields. Repeated fields can contain multiple values, and the console time range is selected outside the query text."
  },
  {
    dialectId: "yaral",
    summary:
      "Structured YARA-L 2.0 queries and detection rules in Google Security Operations, built on UDM.",
    documentationUrl:
      "https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started2",
    documentationLabel: "Google SecOps YARA-L 2.0 guide",
    fields: [
      {
        term: "$e.metadata.*",
        description: "Metadata for the event bound to variable $e."
      },
      {
        term: "$e.principal.* / $e.src.*",
        description: "Actor and source-side UDM fields."
      },
      {
        term: "$e.target.*",
        description:
          "Target-side UDM fields, including files, processes, users and IPs."
      },
      {
        term: "$e.network.*",
        description: "Network, DNS, HTTP and email UDM fields."
      }
    ],
    commands: [
      { term: "meta", description: "Declares descriptive rule metadata." },
      {
        term: "events",
        description: "Declares event variables and UDM filters."
      },
      {
        term: "match ... over",
        description: "Correlates events by keys and time window."
      },
      {
        term: "outcome",
        description: "Calculates metrics and output variables."
      },
      {
        term: "condition",
        description: "Defines when the rule or query matches."
      },
      { term: "options", description: "Controls supported rule behavior." },
      {
        term: "dedup / order / limit / select",
        description: "Shapes results in Search and Dashboards where supported."
      },
      {
        term: "re.regex()",
        description: "Tests a string with a regular expression."
      }
    ],
    caution:
      "Rules and Search do not support every section in exactly the same way. Rules require event variables; Search can reference UDM paths directly in supported cases."
  },
  {
    dialectId: "logscale",
    summary:
      "CrowdStrike Falcon LogScale and Next-Gen SIEM pipeline language; field names depend on the parser and repository.",
    documentationUrl: "https://library.humio.com/data-analysis/",
    documentationLabel: "CrowdStrike LogScale data analysis",
    fields: [
      {
        term: "@timestamp",
        description: "Canonical event timestamp when provided by the parser."
      },
      {
        term: "#repo / #event_simpleName",
        description:
          "Repository and Falcon event-type metadata commonly used to scope searches."
      },
      {
        term: "ComputerName / aid",
        description: "Common Falcon host name and agent identifier fields."
      },
      {
        term: "RemoteAddressIP4 / DomainName",
        description: "Common Falcon network and DNS fields used by SOCx packs."
      },
      {
        term: "SHA256HashData / MD5HashData",
        description: "Common Falcon file-hash fields."
      }
    ],
    commands: [
      {
        term: "field=value",
        description: "Filters a field; free text can precede the pipeline."
      },
      {
        term: "in(field=..., values=[...])",
        description: "Tests membership in a list."
      },
      {
        term: "regex() / field =~ regex()",
        description: "Extracts fields or filters with a regex."
      },
      {
        term: "groupBy()",
        description: "Groups rows and applies aggregate functions."
      },
      {
        term: "timeChart()",
        description: "Aggregates events over time buckets."
      },
      {
        term: "select() / sort() / head() / tail()",
        description: "Shapes, orders and limits results."
      }
    ]
  },
  {
    dialectId: "xql",
    summary:
      "Cortex XDR and Cortex XSIAM query language for endpoint, network and third-party datasets.",
    documentationUrl:
      "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/XQL-language-features",
    documentationLabel: "Palo Alto Networks XQL language features",
    fields: [
      {
        term: "event_type / event_sub_type",
        description: "Event classification in the xdr_data dataset."
      },
      {
        term: "agent_hostname / agent_id",
        description: "Endpoint and agent identity."
      },
      {
        term: "action_remote_ip",
        description: "Remote network endpoint used by SOCx IOC searches."
      },
      { term: "dns_query_name", description: "Queried DNS name." },
      {
        term: "action_process_image_*",
        description: "Process path, command line and hash family."
      }
    ],
    commands: [
      {
        term: "dataset =",
        description:
          "Selects the source dataset; xdr_data is the normal raw-data starting point."
      },
      {
        term: "filter",
        description: "Keeps rows that satisfy a Boolean expression."
      },
      { term: "fields", description: "Chooses output fields." },
      { term: "alter", description: "Creates or changes fields." },
      { term: "comp ... by", description: "Calculates grouped aggregations." },
      { term: "sort / limit", description: "Orders or bounds the result set." },
      { term: "join", description: "Combines datasets or query stages." }
    ],
    caution:
      "A valid XQL query requires a dataset. Field availability changes with the dataset and ingested product."
  },
  {
    dialectId: "aql",
    summary: "IBM QRadar Ariel Query Language for event and flow data.",
    documentationUrl:
      "https://www.ibm.com/docs/en/qradar-on-cloud?topic=aql-query-structure",
    documentationLabel: "IBM AQL query structure",
    fields: [
      {
        term: "startTime / endTime",
        description: "Ariel storage time fields."
      },
      {
        term: "sourceip / destinationip",
        description: "Source and destination IP addresses."
      },
      {
        term: "sourceport / destinationport / protocolid",
        description: "Network endpoint and protocol fields."
      },
      {
        term: "username / logsourceid / qid",
        description: "User, log source and QRadar event identifiers."
      },
      {
        term: "magnitude / severity / credibility / relevance",
        description: "QRadar event scoring fields."
      }
    ],
    commands: [
      {
        term: "SELECT ... FROM events|flows",
        description: "Selects fields from an Ariel database."
      },
      { term: "WHERE", description: "Filters the selected events or flows." },
      {
        term: "GROUP BY / HAVING",
        description: "Groups rows and filters grouped results."
      },
      { term: "ORDER BY / LIMIT", description: "Orders and limits output." },
      {
        term: "LAST / START / STOP",
        description: "Defines the query time frame."
      },
      {
        term: "LIKE / ILIKE / MATCHES / IN",
        description: "String, regex and membership comparisons."
      }
    ]
  },
  {
    dialectId: "lucene",
    summary:
      "Lucene query-string syntax used by Elasticsearch, OpenSearch, Graylog and other products with product-specific schemas.",
    documentationUrl:
      "https://www.elastic.co/docs/explore-analyze/query-filter/languages/lucene-query-syntax",
    documentationLabel: "Elastic Lucene query syntax",
    fields: [
      {
        term: "field",
        description:
          "A mapped field name followed by a colon; there is no universal Lucene event schema."
      },
      {
        term: "source.ip / destination.ip",
        description:
          "ECS network fields when the target product uses Elastic Common Schema."
      },
      {
        term: "host.name / user.name",
        description: "ECS host and user fields where ECS is present."
      },
      {
        term: "file.hash.sha256 / url.domain",
        description: "ECS file and URL fields used by SOCx templates."
      }
    ],
    commands: [
      {
        term: "field:value",
        description: "Matches a value in a specific mapped field."
      },
      {
        term: "AND / OR / NOT",
        description:
          "Combines or excludes clauses; uppercase is the portable form."
      },
      {
        term: "[a TO z] / {a TO z}",
        description: "Inclusive or exclusive range query."
      },
      {
        term: "* / ?",
        description: "Multi-character and single-character wildcards."
      },
      {
        term: "/pattern/",
        description:
          "Regular-expression query where the host product supports it."
      },
      { term: "~ / ^", description: "Fuzzy/proximity and boost syntax." }
    ],
    caution:
      "Supported query-string features and analyzers vary by host product. Confirm the mapped field names before running a query."
  },
  {
    dialectId: "es-kql",
    summary:
      "Elastic Kibana Query Language: a filter language for Kibana and Elastic Security, not Microsoft KQL.",
    documentationUrl:
      "https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql/",
    documentationLabel: "Elastic KQL reference",
    fields: [
      { term: "@timestamp", description: "Standard Elastic event timestamp." },
      {
        term: "event.category / event.action",
        description: "ECS event classification fields."
      },
      {
        term: "host.name / user.name",
        description: "ECS host and user identities."
      },
      {
        term: "source.ip / destination.ip",
        description: "ECS network endpoints."
      },
      {
        term: "process.command_line / file.hash.sha256",
        description: "ECS process and file IOC fields."
      }
    ],
    commands: [
      { term: "field: value", description: "Filters a mapped field by value." },
      { term: "field: *", description: "Tests whether a field exists." },
      { term: "and / or / not", description: "Combines or negates filters." },
      { term: "> / >= / < / <=", description: "Builds range comparisons." },
      {
        term: "*",
        description: "Wildcard for supported field and value searches."
      }
    ],
    caution:
      "Kibana KQL filters documents only; it does not aggregate, transform or sort them. Field behavior follows the Elasticsearch mapping."
  },
  {
    dialectId: "esql",
    summary:
      "Elastic's piped ES|QL language for filtering, transforming and analyzing Elasticsearch data.",
    documentationUrl:
      "https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax",
    documentationLabel: "Elastic ES|QL syntax",
    fields: [
      { term: "@timestamp", description: "Standard Elastic event timestamp." },
      {
        term: "event.category / event.action",
        description: "ECS event classification fields."
      },
      {
        term: "host.name / user.name",
        description: "ECS host and user identity fields."
      },
      {
        term: "source.ip / destination.ip",
        description: "ECS network endpoints."
      },
      {
        term: "process.command_line / file.hash.*",
        description: "ECS process and hash fields."
      }
    ],
    commands: [
      {
        term: "FROM",
        description: "Selects one or more indices or data streams."
      },
      { term: "WHERE", description: "Filters rows by a Boolean expression." },
      { term: "KEEP / DROP / RENAME", description: "Shapes output columns." },
      { term: "EVAL", description: "Adds calculated columns." },
      { term: "STATS ... BY", description: "Calculates grouped aggregations." },
      { term: "SORT / LIMIT", description: "Orders or bounds the output." },
      {
        term: "DISSECT / GROK",
        description: "Extracts structured fields from strings."
      },
      {
        term: "IN / LIKE / RLIKE / MATCH",
        description: "Membership, wildcard, regex and analyzed-text matching."
      }
    ]
  },
  {
    dialectId: "fortisiem",
    summary:
      "FortiSIEM Analytics Search expressions over normalized event attributes.",
    documentationUrl:
      "https://docs.fortinet.com/document/fortisiem/7.3.4/user-guide/898323/creating-a-new-search",
    documentationLabel: "FortiSIEM creating a search",
    fields: [
      { term: "phRecvTime", description: "FortiSIEM event receive time." },
      {
        term: "eventType / eventName",
        description: "Normalized event classification and display name."
      },
      {
        term: "srcIpAddr / destIpAddr",
        description: "Normalized source and destination IP fields."
      },
      {
        term: "srcUser / destUser",
        description:
          "Normalized source and destination user fields when parsed."
      },
      {
        term: "httpUrl / hashCode",
        description:
          "URL and hash attributes used by SOCx templates when present."
      }
    ],
    commands: [
      {
        term: "= / != / > / >= / < / <=",
        description:
          "Comparison operators selected according to attribute type."
      },
      { term: "IN / NOT IN", description: "List membership filters." },
      {
        term: "CONTAIN / NOT CONTAIN",
        description: "String containment filters."
      },
      {
        term: "REGEXP",
        description:
          "Regular-expression matching where supported by the selected search mode."
      },
      {
        term: "AND / OR / NOT",
        description: "Combines or negates conditions."
      },
      {
        term: "COUNT / SUM",
        description: "Common display aggregation functions."
      }
    ],
    caution:
      "Available attribute names depend on FortiSIEM release, parser and event type. Confirm them in the console attribute picker."
  },
  {
    dialectId: "trend-v1",
    summary:
      "Trend Vision One Search syntax for endpoint activity data and detections.",
    documentationUrl:
      "https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-search-syntax",
    documentationLabel: "Trend Vision One search syntax",
    fields: [
      {
        term: "endpointName / endpointHostName",
        description: "Endpoint identity fields."
      },
      {
        term: "src / dst",
        description:
          "Source and destination network values in supported data sources."
      },
      {
        term: "processCmd / objectCmd",
        description: "Process and object command-line fields."
      },
      {
        term: "processFileHash* / objectFileHash*",
        description:
          "Process and object hash families, including MD5, SHA-1 and SHA-256."
      },
      {
        term: "request / mailFromAddresses",
        description:
          "Request/domain and sender-address fields used by SOCx templates."
      }
    ],
    commands: [
      {
        term: "field: value",
        description: "Performs a field-based partial match."
      },
      {
        term: 'field: "value"',
        description: "Performs a full match for supported field types."
      },
      {
        term: "AND / OR / NOT",
        description: "Combines or excludes search criteria."
      },
      {
        term: "IN (...) ",
        description:
          "Matches one of several supported string or numeric values."
      },
      {
        term: "*",
        description:
          "Wildcard syntax; behavior and case sensitivity depend on its position."
      },
      {
        term: "/pattern/",
        description: "Regex search for supported string fields."
      }
    ],
    caution:
      "Searchable fields depend on the selected Search data source. Select Endpoint activity data, Detections or another source before validating a field."
  },
  {
    dialectId: "s1ql",
    summary:
      "SentinelOne Singularity Deep Visibility query syntax for endpoint telemetry.",
    documentationUrl:
      "https://www.sentinelone.com/blog/rapid-threat-hunting-with-deep-visibility-feature-spotlight/",
    documentationLabel: "SentinelOne Deep Visibility guide",
    fields: [
      {
        term: "EventType / EventTime",
        description: "Event class and timestamp in the Deep Visibility schema."
      },
      {
        term: "EndpointName / AgentUuid",
        description: "Endpoint and agent identity."
      },
      {
        term: "SrcProcName / SrcProcCmdLine",
        description: "Source process name and command line."
      },
      {
        term: "DstIP / DstPort / DnsRequest / Url",
        description: "Common network, DNS and URL fields."
      },
      {
        term: "TgtFileSha256 / TgtFileSha1 / TgtFileMd5",
        description: "Target-file hash fields used by SOCx templates."
      }
    ],
    commands: [
      { term: "= / !=", description: "Exact equality and inequality filters." },
      { term: "In / Not In", description: "List membership filters." },
      {
        term: "ContainsCIS",
        description: "Case-insensitive string containment."
      },
      { term: "RegExp", description: "Regular-expression comparison." },
      { term: "AND / OR / NOT", description: "Combines or negates conditions." }
    ],
    caution:
      "SentinelOne documentation and schemas are versioned and may require a customer login. Verify field names against the schema available in your console."
  },
  {
    dialectId: "leql",
    summary:
      "Rapid7 InsightIDR and InsightOps Log Entry Query Language over parsed log keys.",
    documentationUrl:
      "https://docs.rapid7.com/insightidr/components-for-building-a-query/",
    documentationLabel: "Rapid7 LEQL query components",
    fields: [
      { term: "#log", description: "The log that contains the entry." },
      {
        term: "#type / #datetime",
        description:
          "System variables for log type and event time where available."
      },
      {
        term: "source_ip / destination_ip",
        description:
          "Example parsed network keys; exact keys depend on the selected log set."
      },
      {
        term: "user / action / result",
        description: "Common parsed authentication and activity keys."
      }
    ],
    commands: [
      {
        term: "select()",
        description: "Chooses, renames and orders returned keys."
      },
      {
        term: "where()",
        description: "Filters entries; only one where clause is allowed."
      },
      {
        term: "groupby()",
        description: "Groups results by up to the supported number of keys."
      },
      {
        term: "calculate()",
        description: "Applies count, sum, average and other analytics."
      },
      {
        term: "having() / sort() / limit()",
        description: "Filters, orders and limits grouped results."
      },
      {
        term: "IN [...] / ICONTAINS",
        description: "List membership and case-insensitive containment."
      },
      { term: "=/pattern/", description: "RE2 regular-expression matching." }
    ],
    caution:
      "LEQL keys come from the selected log sets and parsing rules; inspect a sample event before assuming a key exists."
  },
  {
    dialectId: "sumo",
    summary:
      "Sumo Logic's piped Search Query Language for logs and security data.",
    documentationUrl:
      "https://www.sumologic.com/help/docs/search/get-started-with-search/build-search/search-syntax-overview/",
    documentationLabel: "Sumo Logic search syntax overview",
    fields: [
      {
        term: "_sourceCategory",
        description: "Logical source category, commonly used to scope a search."
      },
      {
        term: "_sourceHost / _sourceName",
        description: "Source host and source name metadata."
      },
      {
        term: "_collector",
        description: "Collector that received the message."
      },
      {
        term: "_messageTime / _receiptTime",
        description: "Message and ingestion timestamps."
      },
      {
        term: "_raw",
        description: "Raw log message before query-time parsing."
      }
    ],
    commands: [
      {
        term: "keyword expression",
        description: "Scopes the initial full-text and metadata search."
      },
      {
        term: "parse / parse regex",
        description: "Extracts fields from messages."
      },
      {
        term: "where",
        description: "Filters parsed rows with a Boolean expression."
      },
      { term: "count ... by", description: "Counts and groups results." },
      {
        term: "timeslice",
        description: "Creates time buckets for aggregation."
      },
      {
        term: "sort / limit / fields",
        description: "Orders, limits and shapes results."
      },
      {
        term: "matches / in",
        description: "Wildcard or regex matching and list membership."
      }
    ]
  },
  {
    dialectId: "devo",
    summary: "Devo LINQ pipeline language for querying data tables.",
    documentationUrl:
      "https://devodocs.atlassian.net/wiki/spaces/latest/pages/95191261",
    documentationLabel: "Devo: build a query using LINQ",
    fields: [
      {
        term: "eventdate",
        description: "Event timestamp commonly present in Devo tables."
      },
      {
        term: "table columns",
        description:
          "Fields are the columns exposed by the table selected in the from clause."
      },
      {
        term: "sourceIp / destinationIp",
        description:
          "Representative normalized network columns where the chosen table provides them."
      },
      {
        term: "host / user / message",
        description:
          "Representative identity and message columns; names vary by table."
      }
    ],
    commands: [
      { term: "from", description: "Selects the source data table." },
      { term: "where", description: "Filters rows." },
      {
        term: "select ... as",
        description: "Selects fields and creates aliases or calculated fields."
      },
      {
        term: "group every ... by",
        description: "Groups data into time windows and keys."
      },
      {
        term: "in / toktains / matches",
        description: "Membership, token containment and regex comparisons."
      }
    ],
    caution:
      "Devo fields are table columns, not one global schema. Confirm names in Data Search for the selected table."
  },
  {
    dialectId: "spotter",
    summary:
      "Securonix Spotter search over normalized Unified Defense SIEM attributes.",
    documentationUrl: "https://documentation.securonix.com/",
    documentationLabel: "Securonix documentation",
    fields: [
      {
        term: "rg_functionality",
        description:
          "Resource-group functionality used to scope normalized events."
      },
      {
        term: "sourceaddress / destinationaddress",
        description: "Normalized source and destination address fields."
      },
      {
        term: "sourceusername / destinationusername",
        description: "Normalized user identity fields where mapped."
      },
      {
        term: "requestclientapplication",
        description:
          "Client or user-agent-like request field in supported data."
      },
      {
        term: "resourcegroupname",
        description: "Normalized resource-group identity."
      }
    ],
    commands: [
      {
        term: "= / != / > / >= / < / <=",
        description: "Field comparison operators."
      },
      { term: "IN / NOT IN", description: "List membership filters." },
      { term: "CONTAINS", description: "String containment filter." },
      {
        term: "RLIKE",
        description:
          "Regular-expression-like string filter in supported versions."
      },
      { term: "AND / OR / NOT", description: "Combines or negates criteria." }
    ],
    caution:
      "Spotter syntax and event attributes can differ between platform versions and customer mappings. Use the in-product data dictionary as the final authority."
  },
  {
    dialectId: "ccl",
    summary:
      "ArcSight Common Conditions expressions used by ESM filters, rules and report queries.",
    documentationUrl:
      "https://www.microfocus.com/documentation/arcsight/arcsight-esm-7.6/ESM_ArcSightConsole_UserGuide/Content/ESM_UserGuide/Common_Conditions_Editor.htm",
    documentationLabel: "ArcSight Common Conditions Editor",
    fields: [
      {
        term: "sourceAddress / destinationAddress",
        description: "Normalized event source and destination addresses."
      },
      {
        term: "sourceUserName / destinationUserName",
        description: "Normalized source and destination users."
      },
      {
        term: "name / deviceEventClassId",
        description: "Event name and vendor event identifier."
      },
      {
        term: "deviceVendor / deviceProduct",
        description: "Event-producing vendor and product."
      },
      {
        term: "categoryBehavior / categoryOutcome",
        description: "ArcSight categorization fields."
      }
    ],
    commands: [
      {
        term: "AND / OR / NOT",
        description: "Builds a Boolean condition tree."
      },
      {
        term: "= / != / < / <= / > / >=",
        description: "Value comparisons allowed by field type."
      },
      { term: "In / InSubnet", description: "List and IP-subnet membership." },
      {
        term: "Contains / StartsWith / EndsWith",
        description: "String comparisons."
      },
      {
        term: "Matches / Like",
        description: "Pattern comparisons for supported string fields."
      }
    ],
    caution:
      "The UI label and script alias of an ArcSight data field can differ. Filters and textual exports should use the alias expected by that surface."
  },
  {
    dialectId: "nwql",
    summary: "NetWitness Investigate query conditions over indexed meta keys.",
    documentationUrl:
      "https://community.netwitness.com/ckkzj82364/attachments/ckkzj82364/netwitness-online-documentation/2295/2/rsa_nw_11.5_investigate_user_guide.pdf",
    documentationLabel: "NetWitness Investigate user guide",
    fields: [
      {
        term: "ip.src / ip.dst",
        description: "Indexed source and destination IP meta keys."
      },
      { term: "alias.host", description: "Host or domain alias meta key." },
      {
        term: "username / user.src / user.dst",
        description: "Common user identity meta keys."
      },
      {
        term: "service / action",
        description: "Application protocol and observed action."
      },
      {
        term: "filetype / checksum",
        description:
          "File type and hash-related metadata where parsed and indexed."
      }
    ],
    commands: [
      {
        term: "meta = value",
        description: "Matches an indexed meta key to a value."
      },
      {
        term: "meta = value1,value2",
        description: "Matches any comma-separated value for the same meta key."
      },
      { term: "&& / || / !", description: "Boolean AND, OR and negation." },
      {
        term: "contains / regex",
        description:
          "String and regex comparisons where supported by the meta type."
      }
    ],
    caution:
      "Only meta keys indexed by the active service are searchable. Profiles and parsers determine which keys are available."
  },
  {
    dialectId: "sql",
    summary:
      "SQLite-style SQL used by osquery, Fleet and related endpoint query products.",
    documentationUrl:
      "https://osquery.readthedocs.io/en/stable/introduction/sql/",
    documentationLabel: "osquery SQL introduction",
    fields: [
      {
        term: "processes.pid / name / path / cmdline",
        description: "Process identity and command-line columns."
      },
      {
        term: "users.uid / username / directory",
        description: "Local account columns."
      },
      {
        term: "listening_ports.address / port / protocol",
        description: "Listening network endpoint columns."
      },
      {
        term: "hash.path / md5 / sha1 / sha256",
        description: "File path and computed hash columns."
      },
      {
        term: "table schema",
        description:
          "Every virtual table defines its own platform-specific columns in the schema."
      }
    ],
    commands: [
      {
        term: "SELECT ... FROM",
        description: "Chooses columns from one or more virtual tables."
      },
      {
        term: "WHERE",
        description:
          "Filters rows and, for many tables, constrains data collection."
      },
      { term: "JOIN", description: "Combines related virtual tables." },
      {
        term: "GROUP BY / HAVING",
        description: "Groups rows and filters aggregates."
      },
      { term: "ORDER BY / LIMIT", description: "Orders and bounds results." },
      {
        term: "IN / LIKE / REGEXP",
        description:
          "Membership, wildcard and regex comparisons when available."
      }
    ],
    caution:
      "osquery table and column availability is operating-system and version dependent. Check the schema for the fleet version you run."
  },
  {
    dialectId: "regex",
    summary:
      "Portable regular-expression starter for grep, ripgrep and plain-text logs; SOCx escapes IOC values literally.",
    documentationUrl:
      "https://www.gnu.org/software/grep/manual/grep.html#Regular-Expressions",
    documentationLabel: "GNU grep regular expressions",
    fields: [
      {
        term: "input line",
        description:
          "Regex works on text, not named event fields unless the host tool adds them."
      },
      {
        term: "capture group (...) ",
        description: "Groups a subexpression and may capture its match."
      },
      {
        term: "character class [...]",
        description: "Matches one character from a set or range."
      },
      {
        term: "anchors ^ and $",
        description: "Match the beginning and end of a line."
      }
    ],
    commands: [
      {
        term: "literal",
        description:
          "Ordinary characters match themselves; metacharacters must be escaped for a literal match."
      },
      {
        term: ".",
        description: "Matches one character under the engine's newline rules."
      },
      {
        term: "* / + / ? / {n,m}",
        description: "Repetition quantifiers in extended regex syntax."
      },
      {
        term: "|",
        description:
          "Alternation: matches either side in ERE-compatible engines."
      },
      {
        term: "(...) / [...]",
        description: "Grouping and character-class constructs."
      },
      {
        term: "\\",
        description:
          "Escapes a metacharacter or introduces an engine-specific sequence."
      },
      {
        term: "grep -E / rg",
        description:
          "Common commands that use extended or Rust-regex-style patterns."
      }
    ],
    caution:
      "Regex dialects differ. GNU grep supports BRE and ERE, optional PCRE uses -P, and ripgrep's default engine intentionally omits features such as backreferences."
  },
  {
    dialectId: "powershell",
    summary:
      "PowerShell text and Windows Event Log hunting with Select-String and Get-WinEvent.",
    documentationUrl:
      "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string",
    documentationLabel: "Microsoft Select-String reference",
    fields: [
      {
        term: "TimeCreated / Id",
        description: "Windows event timestamp and event identifier."
      },
      {
        term: "ProviderName / LogName",
        description: "Event provider and channel."
      },
      {
        term: "LevelDisplayName / Message",
        description: "Rendered severity and event message."
      },
      {
        term: "MatchInfo.Path / LineNumber / Line",
        description:
          "File path, line number and matching line returned by Select-String."
      },
      {
        term: "MatchInfo.Matches",
        description: "Regex match objects returned for the selected pattern."
      }
    ],
    commands: [
      {
        term: "Select-String -Pattern",
        description: "Searches strings or files with regex by default."
      },
      {
        term: "Get-WinEvent -FilterHashtable",
        description: "Efficiently filters Windows event logs by supported keys."
      },
      {
        term: "Get-WinEvent -FilterXPath",
        description: "Filters event XML with XPath syntax."
      },
      {
        term: "Where-Object",
        description: "Filters objects later in the pipeline."
      },
      {
        term: "-match / -notmatch",
        description: "Regex match and negated match operators."
      },
      {
        term: "Select-Object / Group-Object",
        description: "Shapes and groups pipeline results."
      }
    ],
    caution:
      "Select-String patterns are regex unless -SimpleMatch is used. Get-WinEvent FilterHashtable supports a defined key set; named event-data keys require compatible PowerShell versions."
  }
]

export const QUERY_LANGUAGE_GUIDES: QueryLanguageGuide[] =
  QUERY_LANGUAGE_GUIDE_SEEDS.map((guide) => {
    const commands = QUERY_GUIDE_COMMANDS[guide.dialectId]
    if (!commands) {
      throw new Error(`Missing command guide for dialect: ${guide.dialectId}`)
    }
    return { ...guide, commands }
  })

const normalize = (value: string): string => value.trim().toLocaleLowerCase()

export const guideSearchText = (guide: QueryLanguageGuide): string =>
  normalize(
    [
      guide.dialectId,
      guide.summary,
      guide.documentationLabel,
      guide.caution ?? "",
      ...guide.fields.flatMap((item) => [
        item.term,
        item.description,
        item.example ?? "",
        ...(item.notes ?? [])
      ]),
      ...guide.commands.flatMap((item) => [
        item.term,
        item.description,
        item.syntax,
        item.example,
        ...item.options
      ])
    ].join(" ")
  )

export const filterQueryLanguageGuides = (
  guides: QueryLanguageGuide[],
  dialectId: string,
  search: string,
  productText: (dialectId: string) => string = () => ""
): QueryLanguageGuide[] => {
  const terms = normalize(search).split(/\s+/).filter(Boolean)
  return guides.filter(
    (guide) =>
      (dialectId === "all" || guide.dialectId === dialectId) &&
      terms.every((term) =>
        `${guideSearchText(guide)} ${normalize(productText(guide.dialectId))}`.includes(
          term
        )
      )
  )
}
