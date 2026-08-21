export type QueryGuideCommand = {
  term: string
  description: string
  syntax: string
  options: string[]
  example: string
}

type CommandSeed = readonly [
  term: string,
  description: string,
  syntax: string,
  example: string,
  options: readonly string[]
]

const commands = (seeds: readonly CommandSeed[]): QueryGuideCommand[] =>
  seeds.map(([term, description, syntax, example, options]) => ({
    term,
    description,
    syntax,
    example,
    options: [...options]
  }))

export const QUERY_GUIDE_COMMANDS: Record<string, QueryGuideCommand[]> = {
  kql: commands([
    [
      "where",
      "Filters rows using a Boolean predicate.",
      "Table | where Predicate",
      'DeviceNetworkEvents | where RemoteIP == "8.8.8.8"',
      [
        "Use and/or to combine predicates.",
        "Use ago() for relative time windows."
      ]
    ],
    [
      "project",
      "Keeps, renames and orders the columns returned by the query.",
      "| project Column, NewName = ExistingColumn",
      "| project Timestamp, DeviceName, RemoteIP",
      [
        "project-away removes named columns.",
        "project-rename renames without recalculating values."
      ]
    ],
    [
      "extend",
      "Adds calculated columns without dropping the existing ones.",
      "| extend NewColumn = Expression",
      "| extend Host = tolower(DeviceName)",
      [
        "Use scalar functions inside the expression.",
        "A reused column name replaces that column's value."
      ]
    ],
    [
      "summarize ... by",
      "Aggregates rows, optionally grouped by one or more expressions.",
      "| summarize Aggregation by GroupExpression",
      "| summarize Hits = count() by DeviceName",
      [
        "Common aggregations include count(), dcount(), min(), max() and make_set().",
        "Use bin(Timestamp, 1h) for time buckets."
      ]
    ],
    [
      "sort by",
      "Orders the result set by one or more expressions.",
      "| sort by Expression asc|desc",
      "| sort by Timestamp desc",
      [
        "desc is descending; asc is ascending.",
        "Add nulls first or nulls last when null placement matters."
      ]
    ],
    [
      "take / limit",
      "Returns an arbitrary bounded number of rows.",
      "| take Number",
      "| take 50",
      [
        "limit is an alias of take.",
        "Use top when the selected rows must follow a defined ordering."
      ]
    ],
    [
      "join",
      "Combines rows from two tabular inputs using matching keys.",
      "Left | join kind=Kind (Right) on Key",
      "DeviceInfo | join kind=inner (DeviceNetworkEvents) on DeviceId",
      [
        "Common kinds include inner, innerunique, leftouter and anti.",
        "Use $left and $right when key names differ."
      ]
    ],
    [
      "in~ / has_any",
      "Performs case-insensitive membership or term-list matching.",
      "Field in~ (Value1, Value2) | Field has_any (Term1, Term2)",
      'RemoteUrl has_any ("evil.example", "bad.example")',
      [
        "in~ compares complete values case-insensitively.",
        "has_any searches indexed terms rather than arbitrary substrings."
      ]
    ],
    [
      "matches regex",
      "Matches a string value against a regular expression.",
      "Field matches regex Regex",
      'FileName matches regex @"(?i)invoice.*\\.exe"',
      [
        'Use a verbatim @"..." string to reduce escaping.',
        "Prefer term operators for simple text searches."
      ]
    ],
    [
      "mv-expand",
      "Expands each value in a dynamic array or property bag into a row.",
      "| mv-expand Column [to typeof(Type)] [limit Number]",
      "| mv-expand IP = AdditionalFields",
      [
        "Use to typeof(...) to declare the expanded value type.",
        "A limit can cap values expanded per input row."
      ]
    ]
  ]),
  spl: commands([
    [
      "search",
      "Filters events with search-language expressions.",
      "search Expression",
      "search index=main src=8.8.8.8",
      [
        "Field comparisons and bare keywords are supported.",
        "AND, OR and NOT are uppercase Boolean operators."
      ]
    ],
    [
      "where",
      "Filters results with eval-style expressions.",
      "| where Expression",
      '| where status>=500 AND like(uri, "%admin%")',
      [
        "Use comparison and Boolean operators.",
        "Functions such as like(), match() and isnull() return Boolean values."
      ]
    ],
    [
      "eval",
      "Creates or updates calculated fields.",
      "| eval Field=Expression",
      "| eval normalized_user=lower(user)",
      [
        "Assign multiple comma-separated fields in one command.",
        "String, conversion, conditional and multivalue functions are available."
      ]
    ],
    [
      "rex",
      "Extracts fields or replaces text with a regular expression.",
      '| rex [field=Field] "Pattern"',
      '| rex field=_raw "user=(?<user>[^ ]+)"',
      [
        "Named capture groups create fields.",
        "Use mode=sed for sed-style substitution or masking."
      ]
    ],
    [
      "stats ... by",
      "Calculates aggregate statistics, optionally grouped by fields.",
      "| stats Function(Field) AS Name by GroupField",
      "| stats count AS hits by src",
      [
        "Common functions include count, dc, values, earliest and latest.",
        "Add multiple comma-separated aggregation functions when needed."
      ]
    ],
    [
      "timechart",
      "Creates a time-series statistical table.",
      "| timechart [span=Interval] Aggregation [by Field]",
      "| timechart span=1h count by action",
      [
        "span controls time bucket size.",
        "limit and useother control split-series cardinality."
      ]
    ],
    [
      "table / fields",
      "Selects and orders fields in the result.",
      "| table Field1 Field2 | fields +/- Field",
      "| table _time host user action",
      [
        "table keeps fields in the written order.",
        "fields - removes fields; fields + keeps them."
      ]
    ],
    [
      "sort / dedup",
      "Orders results or removes repeated field combinations.",
      "| sort [+|-] Field | dedup Field",
      "| sort - _time | dedup user",
      [
        "A minus sign sorts descending.",
        "dedup can keep a chosen number of duplicate combinations."
      ]
    ],
    [
      "lookup",
      "Enriches events with fields from a lookup table.",
      "| lookup LookupName Key [OUTPUT Field]",
      "| lookup asset_inventory ip AS src OUTPUT owner",
      [
        "OUTPUTNEW avoids overwriting existing fields.",
        "Aliases map event fields to lookup keys."
      ]
    ],
    [
      "rename",
      "Renames one or more result fields.",
      "| rename Old AS New",
      "| rename src AS source_ip",
      [
        "Wildcards can rename matching field families.",
        "Quote field names that contain spaces or special characters."
      ]
    ]
  ]),
  udm: commands([
    [
      "= / !=",
      "Tests exact equality or inequality on a UDM field.",
      "Field = Value",
      'principal.ip = "8.8.8.8"',
      [
        "Quote string and IP values.",
        "Use a field path that exists in the selected UDM event type."
      ]
    ],
    [
      "< / <= / > / >=",
      "Compares ordered values such as numbers or timestamps.",
      "Field Operator Value",
      "network.sent_bytes > 1000000",
      [
        "Choose an operator compatible with the field type.",
        "Combine bounds with AND for a closed range."
      ]
    ],
    [
      "AND",
      "Requires both adjacent conditions to match.",
      "Condition AND Condition",
      'principal.ip = "8.8.8.8" AND metadata.event_type = "NETWORK_CONNECTION"',
      [
        "Parentheses make mixed Boolean logic explicit.",
        "Boolean operators are written in uppercase."
      ]
    ],
    [
      "OR",
      "Accepts either adjacent condition.",
      "Condition OR Condition",
      'target.hostname = "host-a" OR target.hostname = "host-b"',
      [
        "Group alternatives with parentheses when AND is also present.",
        "Repeat the field for each alternative."
      ]
    ],
    [
      "NOT",
      "Negates a condition or grouped expression.",
      "NOT Condition",
      'NOT security_result.action = "ALLOW"',
      [
        "Apply NOT to the smallest intended condition.",
        "Use parentheses when negating a compound expression."
      ]
    ],
    [
      "nocase",
      "Makes a supported string or regular-expression comparison case-insensitive.",
      "Field = nocase Value",
      'target.hostname = nocase "SERVER-01"',
      [
        "Place nocase before the comparison value.",
        "It is relevant to text matching, not numeric fields."
      ]
    ],
    [
      "/pattern/",
      "Matches a UDM string field with a regular expression.",
      "Field = /RegularExpression/",
      "principal.process.command_line = /(?i)powershell.*-enc/",
      [
        "Escape the slash delimiter when it is part of the pattern.",
        "Keep the pattern narrow to reduce noisy matches."
      ]
    ],
    [
      "( ... )",
      "Groups conditions so Boolean precedence is unambiguous.",
      "(Condition OR Condition) AND Condition",
      '(principal.ip = "8.8.8.8" OR target.ip = "8.8.8.8") AND metadata.event_type = "NETWORK_CONNECTION"',
      [
        "Use groups around OR alternatives combined with AND.",
        "Nested groups are allowed when the logic requires them."
      ]
    ]
  ]),
  yaral: commands([
    [
      "rule",
      "Declares the rule and its identifier.",
      "rule RuleName { ... }",
      "rule suspicious_powershell { ... }",
      [
        "Use a stable identifier without spaces.",
        "The body contains the meta, events, match, outcome, condition and options sections that apply."
      ]
    ],
    [
      "meta",
      "Stores descriptive rule metadata.",
      "meta:\n  Key = Value",
      'meta:\n  description = "Encoded PowerShell"',
      [
        "Common keys include author, description and severity.",
        "Metadata does not determine whether events match."
      ]
    ],
    [
      "events",
      "Defines event variables and the predicates they must satisfy.",
      "events:\n  $Event.Field = Value",
      'events:\n  $e.metadata.event_type = "PROCESS_LAUNCH"',
      [
        "Prefix each event variable with $.",
        "Use UDM field paths and supported functions in predicates."
      ]
    ],
    [
      "match ... over",
      "Groups events by placeholders within a time window.",
      "match:\n  $Placeholder over Duration",
      "match:\n  $user over 10m",
      [
        "The placeholder must be assigned from an event field.",
        "Use a bounded window appropriate to the detection behavior."
      ]
    ],
    [
      "outcome",
      "Calculates values returned with a match.",
      "outcome:\n  $Name = Aggregation",
      "outcome:\n  $event_count = count($e.metadata.id)",
      [
        "Outcome variables start with $.",
        "Use supported aggregation or scalar functions."
      ]
    ],
    [
      "condition",
      "States the Boolean condition that makes the rule match.",
      "condition:\n  Condition",
      "condition:\n  #e > 5",
      [
        "#event counts matching events.",
        "$event tests whether at least one matching event exists."
      ]
    ],
    [
      "options",
      "Configures supported rule behavior.",
      "options:\n  Key = Value",
      "options:\n  allow_zero_values = true",
      [
        "Only documented option keys are accepted.",
        "Keep options at the rule level."
      ]
    ],
    [
      "re.regex()",
      "Tests a string with a regular expression.",
      "re.regex(Value, Pattern)",
      "re.regex($e.principal.process.command_line, `(?i)-enc`) ",
      [
        "Use a backtick-delimited regex literal.",
        "Prefer explicit event fields over scanning broad text fields."
      ]
    ]
  ]),
  logscale: commands([
    [
      "field=value",
      "Filters events by an exact field value.",
      "Field = Value",
      'RemoteAddressIP4 = "8.8.8.8"',
      [
        "Quote values that contain spaces or special characters.",
        "Use != to exclude a value."
      ]
    ],
    [
      "|",
      "Passes the current event stream to the next function.",
      "Filter | Function | Function",
      "#event_simpleName=DnsRequest | groupBy(DomainName)",
      [
        "Stages run from left to right.",
        "Place selective filters early when possible."
      ]
    ],
    [
      "in()",
      "Filters a field against a list of values.",
      "in(field=Field, values=[Value1, Value2])",
      'in(field=DomainName, values=["evil.example", "bad.example"])',
      [
        "Add ignoreCase=true for supported case-insensitive text matching.",
        "negate=true returns values outside the list."
      ]
    ],
    [
      "regex() / =~",
      "Filters with a regular expression and can capture named fields.",
      'regex("Pattern", field=Field) | Field =~ regex("Pattern")',
      'CommandLine =~ regex("(?i)powershell.*-enc")',
      [
        "Specify field=... instead of searching the raw event when possible.",
        "Named capture groups can create fields."
      ]
    ],
    [
      "groupBy()",
      "Groups events and applies aggregate functions.",
      "groupBy([Fields], function=Function)",
      "groupBy([ComputerName], function=count())",
      [
        "Pass one field or an array of fields.",
        "Functions include count(), collect(), min(), max() and sum()."
      ]
    ],
    [
      "timeChart()",
      "Builds time-bucketed aggregate series.",
      "timeChart(Span, function=Function, by=Field)",
      "timeChart(1h, function=count(), by=ComputerName)",
      [
        "Set span to the desired bucket size.",
        "by creates one series per field value."
      ]
    ],
    [
      "select()",
      "Keeps and optionally renames selected fields.",
      "select([Field, NewName := Expression])",
      "select([@timestamp, ComputerName, DomainName])",
      [
        "Use an array to keep multiple fields.",
        "Assignments can expose calculated or renamed values."
      ]
    ],
    [
      "sort() / head()",
      "Orders events and returns a bounded leading set.",
      "sort(Field, order=asc|desc) | head(Number)",
      "sort(@timestamp, order=desc) | head(50)",
      [
        "Sort before head when the chosen rows must be deterministic.",
        "tail() returns the end of the current stream."
      ]
    ]
  ]),
  xql: commands([
    [
      "dataset =",
      "Chooses the dataset that starts the query.",
      "dataset = DatasetName",
      "dataset = xdr_data",
      [
        "Start with a dataset available in the tenant.",
        "Dataset fields determine which later expressions are valid."
      ]
    ],
    [
      "filter",
      "Keeps rows that satisfy a Boolean expression.",
      "| filter Expression",
      '| filter action_remote_ip = "8.8.8.8"',
      [
        "Combine predicates with and/or.",
        "Use field-type-compatible comparison and string operators."
      ]
    ],
    [
      "fields",
      "Chooses the output columns.",
      "| fields Field1, Field2",
      "| fields _time, agent_hostname, action_remote_ip",
      [
        "List fields in the desired result order.",
        "Keep only fields needed by the investigation."
      ]
    ],
    [
      "alter",
      "Creates or changes fields using expressions.",
      "| alter Field = Expression",
      "| alter host_lower = lowercase(agent_hostname)",
      [
        "Multiple assignments can be comma-separated.",
        "Use documented scalar functions for the field type."
      ]
    ],
    [
      "comp ... by",
      "Calculates aggregate values, optionally grouped by fields.",
      "| comp Aggregation as Name by Field",
      "| comp count() as hits by agent_hostname",
      [
        "Use supported aggregations such as count(), sum(), min() and max().",
        "Add multiple group fields when needed."
      ]
    ],
    [
      "sort",
      "Orders the rows by one or more fields.",
      "| sort asc|desc Field",
      "| sort desc _time",
      [
        "Choose asc or desc explicitly.",
        "Sort before limit when returning top or latest rows."
      ]
    ],
    [
      "limit",
      "Caps the number of rows returned.",
      "| limit Number",
      "| limit 100",
      [
        "Use a modest value during exploration.",
        "Pair with sort when row choice must be deterministic."
      ]
    ],
    [
      "join",
      "Combines the pipeline with another dataset or query.",
      "| join type=Type ConflictStrategy (Subquery) as Alias Field = Alias.Field",
      "| join type=inner (dataset = endpoints) as e agent_id = e.agent_id",
      [
        "Select the join type that preserves the intended side.",
        "Resolve duplicate field names with an alias or conflict strategy."
      ]
    ]
  ]),
  aql: commands([
    [
      "SELECT ... FROM",
      "Selects properties from the events or flows data source.",
      "SELECT Expression FROM events|flows",
      "SELECT sourceip, destinationip FROM events",
      [
        "Use aliases for calculated columns.",
        "Property availability differs between events and flows."
      ]
    ],
    [
      "WHERE",
      "Filters records before aggregation.",
      "WHERE Predicate",
      "WHERE sourceip = '8.8.8.8'",
      [
        "Combine predicates with AND, OR and parentheses.",
        "Quote string and IP literals."
      ]
    ],
    [
      "GROUP BY",
      "Groups rows for aggregate calculations.",
      "GROUP BY Expression",
      "GROUP BY sourceip",
      [
        "Every non-aggregated selected expression must be grouped appropriately.",
        "Use more than one expression for compound groups."
      ]
    ],
    [
      "HAVING",
      "Filters aggregated groups.",
      "HAVING AggregatePredicate",
      "HAVING COUNT(*) > 10",
      ["Use after GROUP BY.", "Filter individual records in WHERE instead."]
    ],
    [
      "ORDER BY",
      "Orders query results.",
      "ORDER BY Expression ASC|DESC",
      "ORDER BY eventcount DESC",
      [
        "ASC is ascending; DESC is descending.",
        "Order by a selected property or alias."
      ]
    ],
    [
      "LIMIT",
      "Caps the number of records returned.",
      "LIMIT Number",
      "LIMIT 100",
      [
        "Apply after ordering for top-N output.",
        "Use a small limit while developing expensive searches."
      ]
    ],
    [
      "LAST / START / STOP",
      "Defines the time window examined by the Ariel query.",
      "LAST Number MINUTES|HOURS|DAYS",
      "LAST 24 HOURS",
      [
        "LAST specifies a relative period.",
        "START and STOP define absolute boundaries."
      ]
    ],
    [
      "LIKE / ILIKE / MATCHES / IN",
      "Performs text-pattern, regex or list matching.",
      "Field Operator PatternOrList",
      "WHERE username ILIKE '%admin%'",
      [
        "ILIKE is case-insensitive pattern matching.",
        "MATCHES uses a regular expression; IN compares against a list."
      ]
    ]
  ]),
  lucene: commands([
    [
      "field:value",
      "Searches a named indexed field for a value.",
      "Field:Value",
      "source.ip:8.8.8.8",
      [
        "Quote phrases and values containing spaces.",
        "Field analysis and mapping affect matching."
      ]
    ],
    [
      "AND / OR / NOT",
      "Combines or negates query clauses.",
      "Clause AND|OR Clause | NOT Clause",
      "event.category:network AND NOT event.action:allowed",
      [
        "Operators must be uppercase in classic Lucene syntax.",
        "Use parentheses to make precedence explicit."
      ]
    ],
    [
      "( ... )",
      "Groups clauses or multiple alternatives for one field.",
      "Field:(Value1 OR Value2)",
      "host.name:(server-a OR server-b)",
      ["Groups can be nested.", "A field prefix can apply to the whole group."]
    ],
    [
      "[a TO z] / {a TO z}",
      "Builds inclusive or exclusive range queries.",
      "Field:[Lower TO Upper]",
      "@timestamp:[now-24h TO now]",
      ["Square brackets include endpoints.", "Curly braces exclude endpoints."]
    ],
    [
      "* / ?",
      "Matches multiple or single characters in a term.",
      "Field:Wild*ard",
      "host.name:web-?",
      ["* matches zero or more characters.", "? matches exactly one character."]
    ],
    [
      "/pattern/",
      "Runs a regular-expression term query.",
      "Field:/RegularExpression/",
      "process.name:/power(shell)?/",
      [
        "The regex applies to indexed terms, not arbitrary raw text semantics.",
        "Keep expressions bounded to avoid expensive queries."
      ]
    ],
    [
      "~",
      "Applies fuzzy term matching or phrase proximity.",
      'Term~Distance | "Phrase"~Slop',
      'message:"failed login"~3',
      [
        "After a term, the number controls edit distance.",
        "After a phrase, it controls allowed positional distance."
      ]
    ],
    [
      "^",
      "Boosts the relevance weight of a clause.",
      "Clause^Boost",
      "event.action:blocked^2 OR event.action:allowed",
      [
        "Boost affects scoring, not Boolean eligibility.",
        "A positive decimal value can be used."
      ]
    ]
  ]),
  "es-kql": commands([
    [
      "field: value",
      "Filters a mapped field by a matching value.",
      "Field: Value",
      "source.ip: 8.8.8.8",
      [
        "Quote values containing spaces.",
        "Mapping type determines exact or analyzed matching behavior."
      ]
    ],
    [
      'field: "phrase"',
      "Matches a phrase as one quoted value.",
      'Field: "Value with spaces"',
      'process.command_line: "powershell -enc"',
      [
        "Escape embedded quotes and reserved characters.",
        "A quoted phrase does not turn KQL into Lucene syntax."
      ]
    ],
    [
      "field: *",
      "Tests whether a field has any indexed value.",
      "Field: *",
      "user.name: *",
      [
        "Use not Field:* to find documents where the field is absent.",
        "An empty string and a missing field are different states."
      ]
    ],
    [
      "and / or / not",
      "Combines or negates filter clauses.",
      "Clause and|or Clause | not Clause",
      "event.category: process and not user.name: SYSTEM",
      [
        "Use parentheses around mixed and/or clauses.",
        "Operators are case-insensitive in Elastic KQL."
      ]
    ],
    [
      "> / >= / < / <=",
      "Creates numeric, date or lexicographic range comparisons.",
      "Field >= Value",
      "@timestamp >= now-24h",
      [
        "Use a field whose mapping supports the comparison.",
        "Combine lower and upper bounds with and."
      ]
    ],
    [
      "*",
      "Matches zero or more characters in an unquoted value.",
      "Field: Prefix*",
      "host.name: web-*",
      [
        "Leading wildcards may be disabled by configuration.",
        "Elastic KQL does not support regular expressions."
      ]
    ],
    [
      "nested fields",
      "Matches properties within a mapped nested field.",
      "NestedPath: { Field: Value and Field: Value }",
      'user: { name: "alice" and role: "admin" }',
      [
        "Use only when the field is mapped as nested.",
        "Clauses inside the braces apply to the same nested object."
      ]
    ],
    [
      "\\ reserved characters",
      "Escapes characters that otherwise have KQL meaning.",
      "Field: EscapedValue",
      "url.path: \\/admin\\?debug=true",
      [
        "Escape reserved punctuation with a backslash.",
        "Quoting may be clearer for values containing spaces."
      ]
    ]
  ]),
  esql: commands([
    [
      "FROM",
      "Loads one or more Elasticsearch indices or data streams.",
      "FROM IndexPattern",
      "FROM logs-*",
      [
        "Comma-separate multiple index patterns.",
        "Place metadata requests in the FROM source when needed."
      ]
    ],
    [
      "WHERE",
      "Filters rows using a Boolean expression.",
      "| WHERE Predicate",
      '| WHERE source.ip == "8.8.8.8"',
      [
        "Use AND, OR and NOT for compound logic.",
        "Functions and operators must match the field data type."
      ]
    ],
    [
      "KEEP / DROP",
      "Keeps or removes columns from the result.",
      "| KEEP Columns | DROP Columns",
      "| KEEP @timestamp, host.name, source.ip",
      [
        "Wildcards can select field families.",
        "KEEP also controls output ordering."
      ]
    ],
    [
      "RENAME",
      "Renames one or more columns.",
      "| RENAME Old AS New",
      "| RENAME host.name AS host",
      [
        "Comma-separate multiple rename clauses.",
        "Rename before later stages that should use the new name."
      ]
    ],
    [
      "EVAL",
      "Adds or replaces calculated columns.",
      "| EVAL Name = Expression",
      "| EVAL host = TO_LOWER(host.name)",
      [
        "Comma-separate multiple assignments.",
        "Use scalar functions compatible with the input type."
      ]
    ],
    [
      "STATS ... BY",
      "Aggregates rows, optionally grouped by expressions.",
      "| STATS Aggregation [BY Group]",
      "| STATS hits = COUNT(*) BY host.name",
      [
        "Common functions include COUNT, COUNT_DISTINCT, SUM, MIN and MAX.",
        "Use BUCKET for numeric or time grouping."
      ]
    ],
    [
      "SORT / LIMIT",
      "Orders rows and caps the result size.",
      "| SORT Field ASC|DESC | LIMIT Number",
      "| SORT @timestamp DESC | LIMIT 100",
      [
        "Sort before limit for deterministic top-N results.",
        "NULLS FIRST or NULLS LAST controls null placement."
      ]
    ],
    [
      "DISSECT / GROK",
      "Extracts structured columns from text.",
      "| DISSECT Field Pattern | GROK Field Pattern",
      '| GROK message "%{IP:source_ip} %{WORD:action}"',
      [
        "DISSECT is delimiter-based and does not use regex.",
        "GROK uses reusable patterns and supports custom definitions."
      ]
    ],
    [
      "ENRICH",
      "Adds fields from a configured enrich policy.",
      "| ENRICH Policy ON Field WITH EnrichFields",
      "| ENRICH hosts_policy ON host.name WITH owner",
      [
        "The enrich policy must already exist and be executed.",
        "Use WITH to limit or rename copied fields."
      ]
    ],
    [
      "MV_EXPAND",
      "Expands a multivalued column into one row per value.",
      "| MV_EXPAND Column",
      "| MV_EXPAND related.ip",
      [
        "Other columns are repeated for each expanded value.",
        "Apply it only to multivalued fields."
      ]
    ]
  ]),
  fortisiem: commands([
    [
      "= / != / > / >= / < / <=",
      "Compares an event attribute with a compatible value.",
      "Attribute Operator Value",
      "Source IP = 10.1.1.1",
      [
        "The operator must support the attribute data type.",
        "IP attributes are stored as an IP/integer type, not free text."
      ]
    ],
    [
      "BETWEEN / NOT_BETWEEN",
      "Tests whether an ordered value falls inside or outside a range.",
      "Attribute BETWEEN (Lower, Upper)",
      "Source IP BETWEEN (10.1.1.1, 10.1.1.20)",
      [
        "Supported for IP and numeric attributes.",
        "Use NOT_BETWEEN for the inverse range."
      ]
    ],
    [
      "CONTAIN / NOT_CONTAIN",
      "Tests whether a string attribute contains a value.",
      "Attribute CONTAIN Value",
      "Event Type CONTAIN PH_DEV_MON",
      [
        "Use only with string attributes.",
        "The inverse form excludes containing values."
      ]
    ],
    [
      "REGEXP / NOT_REGEXP",
      "Matches or excludes a regular expression on a string attribute.",
      "Attribute REGEXP Pattern",
      "Raw Event Log REGEXP .*failed.*login.*",
      [
        "Regex behavior can differ between FortiSIEM storage backends.",
        "REGEXP is not valid for IP-typed attributes."
      ]
    ],
    [
      "IN / NOT IN",
      "Tests membership in a list, CMDB group or watch list.",
      "Attribute IN (Value1, Value2)",
      "Source IP IN (20.1.1.1, 10.1.1.3)",
      [
        "Lists support compatible IP, string and numeric values.",
        "FortiSIEM resources can also supply the membership set."
      ]
    ],
    [
      "IS NULL / IS NOT NULL",
      "Tests whether an event attribute is missing or present.",
      "Attribute IS NULL",
      "User IS NOT NULL",
      [
        "Use IS, not equality, for null tests.",
        "The inverse requires IS NOT NULL."
      ]
    ],
    [
      "AND / OR / AND_NOT",
      "Combines event-attribute predicates.",
      "(Predicate) AND|OR|AND_NOT (Predicate)",
      "(Source IP = 10.1.1.1) AND (Destination IP = 20.1.1.2)",
      [
        "Parenthesize tuples in compound filters.",
        "AND_NOT expresses conjunction with exclusion."
      ]
    ],
    [
      "COUNT / SUM",
      "Calculates aggregate display values in an analytics search.",
      "COUNT(*) | SUM(Attribute)",
      "COUNT(*)",
      [
        "Choose an aggregation supported by the attribute type.",
        "Add grouping and sorting in the search builder when needed."
      ]
    ]
  ]),
  "trend-v1": commands([
    [
      "field: value",
      "Matches an indexed field to a value.",
      "Field: Value",
      'endpointName: "server-01"',
      [
        "Use an available field from the selected data source.",
        "Quote non-alphanumeric strings that should not be regex."
      ]
    ],
    [
      'field: "value"',
      "Treats a spaced or punctuated string as one value.",
      'Field: "Quoted value"',
      'processCmd: "powershell.exe -enc"',
      [
        "Escape quotes that are part of the value.",
        "Quoting prevents punctuation from being interpreted as query syntax."
      ]
    ],
    [
      "AND / OR / NOT",
      "Combines or negates search criteria.",
      "Criterion AND|OR Criterion | NOT Criterion",
      "endpointName: server-01 AND NOT action: allow",
      [
        "Use parentheses to group mixed Boolean logic.",
        "Write an explicit field for each independent criterion."
      ]
    ],
    [
      "IN (...) ",
      "Matches a field against one of several values.",
      "Field IN (Value1, Value2)",
      "src IN (8.8.8.8, 1.1.1.1)",
      [
        "Separate values with commas.",
        "Keep values compatible with the field type."
      ]
    ],
    [
      "*",
      "Matches any value or a wildcard portion of a value.",
      "Field: Prefix* | Field: *",
      "endpointName: web-*",
      [
        "Field:* can be used as an existence test.",
        "A wildcard can broaden a value match substantially."
      ]
    ],
    [
      "/pattern/",
      "Matches field content with a regular expression.",
      "Field: /RegularExpression/",
      "processCmd: /(?i)powershell.*-enc/",
      [
        "Regex matches can occur within the field content.",
        "Quote instead when punctuation should remain literal."
      ]
    ],
    [
      "( ... )",
      "Groups criteria to control Boolean evaluation.",
      "(Criterion OR Criterion) AND Criterion",
      "(src: 8.8.8.8 OR dst: 8.8.8.8) AND endpointName: server-01",
      [
        "Group OR alternatives before combining them with AND.",
        "Nested groups are useful for multi-field IOC logic."
      ]
    ],
    [
      "dynamic.field",
      "Addresses a flattened nested property in new Search.",
      "Outer.Inner: Value",
      'vendorParsed.act: "blocked"',
      [
        "Join nested property names with dots.",
        "Use the exact dynamic path exposed by the data source."
      ]
    ]
  ]),
  s1ql: commands([
    [
      "= / !=",
      "Tests exact equality or inequality.",
      "Field = Value",
      'EventType = "Process Creation"',
      [
        "Quote text values.",
        "Use a field name available for the selected Deep Visibility event type."
      ]
    ],
    [
      "In / Not In",
      "Tests whether a field is inside or outside a value list.",
      "Field In (Value1, Value2)",
      'DstIP In ("8.8.8.8", "1.1.1.1")',
      [
        "Comma-separate values inside parentheses.",
        "Not In excludes the listed values."
      ]
    ],
    [
      "Contains",
      "Tests case-sensitive substring containment.",
      "Field Contains Value",
      'SrcProcCmdLine Contains "-enc"',
      [
        "Use for a literal substring.",
        "Choose ContainsCIS when case should be ignored."
      ]
    ],
    [
      "ContainsCIS",
      "Tests case-insensitive substring containment.",
      "Field ContainsCIS Value",
      'SrcProcCmdLine ContainsCIS "powershell"',
      [
        "CIS means case-insensitive string matching.",
        "The value remains a literal substring, not a regex."
      ]
    ],
    [
      "StartsWith / EndsWith",
      "Matches a literal prefix or suffix.",
      "Field StartsWith|EndsWith Value",
      'TgtFilePath EndsWith ".exe"',
      [
        "Use StartsWith for prefixes.",
        "Use EndsWith for extensions or other suffixes."
      ]
    ],
    [
      "RegExp",
      "Matches a field with a regular expression.",
      "Field RegExp Pattern",
      'SrcProcCmdLine RegExp ".*powershell.*-enc.*"',
      [
        "Keep the pattern specific to reduce broad scans.",
        "Use a literal operator when regex features are unnecessary."
      ]
    ],
    [
      "AND / OR",
      "Requires both predicates or accepts either predicate.",
      "Predicate AND|OR Predicate",
      'EventType = "DNS" AND DnsRequest ContainsCIS "example"',
      [
        "Parenthesize OR alternatives combined with AND.",
        "Repeat field predicates explicitly."
      ]
    ],
    [
      "NOT",
      "Negates a predicate or group.",
      "NOT Predicate",
      'NOT EndpointName = "test-host"',
      [
        "Use parentheses for compound exclusions.",
        "Not In is clearer for excluding a value list."
      ]
    ]
  ]),
  leql: commands([
    [
      "select()",
      "Chooses, renames and orders result keys.",
      "select(Key1, Key2 as Alias)",
      "select(source_ip, destination_ip, user)",
      [
        "Place select() first when it is used.",
        "Use aliases to make output columns clearer."
      ]
    ],
    [
      "where()",
      "Filters log entries with keywords, key-value pairs or expressions.",
      "where(Expression)",
      'where(source_ip = "8.8.8.8")',
      [
        "Only one where() clause is allowed per query.",
        "Combine conditions inside it with Boolean logic."
      ]
    ],
    [
      "groupby()",
      "Groups matching entries by up to five keys.",
      "groupby(Key1, Key2)",
      "groupby(destination_user, result)",
      [
        "Multiple keys create nested groupings.",
        "Pair with calculate(count) for occurrence counts."
      ]
    ],
    [
      "calculate()",
      "Computes an analytic function over matching data.",
      "calculate(Function[:Key])",
      "calculate(unique:source_address)",
      [
        "Functions include count, sum, average, unique, min and max.",
        "A field follows a colon for functions that require one."
      ]
    ],
    [
      "having()",
      "Filters groups using aggregate criteria.",
      "having(AggregateComparison)",
      "having(count > 10)",
      [
        "Use with groupby().",
        "Include the corresponding calculate(...) expression when required."
      ]
    ],
    [
      "sort()",
      "Changes the order of grouped results.",
      "sort(asc|desc[, Direction#Key])",
      "sort(desc)",
      [
        "asc sorts ascending; desc sorts descending.",
        "Multi-group results can specify key-specific direction."
      ]
    ],
    [
      "limit()",
      "Caps events or the number of values returned for groups.",
      "limit(Number[, Number...])",
      "limit(100)",
      [
        "With multiple group keys, per-level limits can be supplied.",
        "Its effect follows LEQL's defined execution order."
      ]
    ],
    [
      "timeslice()",
      "Sets the number or duration of time intervals for analytics.",
      "timeslice(Number|Duration)",
      "timeslice(30m)",
      [
        "A bare number selects 1 to 200 intervals.",
        "Duration units include s, m, h and d."
      ]
    ]
  ]),
  sumo: commands([
    [
      "keyword expression",
      "Finds messages containing terms, phrases or scoped metadata.",
      "Keyword AND|OR Keyword",
      '(_sourceCategory=prod/firewall) "connection blocked"',
      [
        "Quote exact phrases.",
        "Place the metadata scope before the first pipe."
      ]
    ],
    [
      "parse",
      "Extracts fields from text using anchor patterns.",
      '| parse "Pattern*Pattern" as Field',
      '| parse "user=* action=*" as user, action',
      [
        "Each * captures one value.",
        "Use nodrop to keep messages that do not match."
      ]
    ],
    [
      "parse regex",
      "Extracts named fields with a regular expression.",
      '| parse regex "(?<Field>Pattern)"',
      '| parse regex "src=(?<source_ip>\\S+)"',
      [
        "Use named capture groups.",
        "Add multi to extract repeated matches where supported."
      ]
    ],
    [
      "where",
      "Filters rows using a Boolean expression.",
      "| where Expression",
      "| where status_code >= 500",
      [
        "Combine comparisons with and/or.",
        "Functions such as matches and isNull can participate."
      ]
    ],
    [
      "count ... by",
      "Counts messages, optionally grouped by fields.",
      "| count [by Field1, Field2]",
      "| count by source_ip",
      [
        "The generated count field is named _count.",
        "Group by more than one parsed or built-in field when needed."
      ]
    ],
    [
      "timeslice",
      "Places messages into fixed time buckets.",
      "| timeslice Duration",
      "| timeslice 5m",
      [
        "Use before grouping by _timeslice.",
        "Choose a duration appropriate to the selected time range."
      ]
    ],
    [
      "fields",
      "Keeps or removes named result fields.",
      "| fields Field1, Field2 | fields -Field",
      "| fields _messageTime, source_ip, action",
      [
        "A minus prefix removes fields.",
        "Ordering the names controls displayed column order."
      ]
    ],
    [
      "sort / limit",
      "Orders results and caps the number returned.",
      "| sort by Field asc|desc | limit Number",
      "| sort by _count desc | limit 20",
      [
        "Sort before limit for deterministic top results.",
        "Multiple sort fields can be specified."
      ]
    ],
    [
      "matches / in",
      "Tests wildcard matching or list membership.",
      "Field matches Pattern | Field in (Values)",
      '| where host matches "web-*"',
      [
        "matches supports wildcard-style patterns.",
        "in compares a field with a comma-separated list."
      ]
    ]
  ]),
  devo: commands([
    [
      "from",
      "Selects the Devo data table.",
      "from TableName",
      "from box.all.win",
      [
        "Use the table that owns the referenced columns.",
        "Table availability depends on the Devo domain."
      ]
    ],
    [
      "where",
      "Filters rows with a Boolean predicate.",
      "where Predicate",
      "where sourceIp = 8.8.8.8",
      [
        "Combine predicates with and/or.",
        "Use functions and operators compatible with the column type."
      ]
    ],
    [
      "select ... as",
      "Chooses columns and assigns output aliases.",
      "select Expression as Alias, ...",
      "select eventdate, sourceIp as src",
      [
        "Comma-separate selected expressions.",
        "Aliases make calculated columns reusable and readable."
      ]
    ],
    [
      "group every ... by",
      "Creates time buckets and grouping keys for aggregation.",
      "group every Duration by Field",
      "group every 5m by sourceIp",
      [
        "Choose a duration suited to the search window.",
        "Add more keys for compound groups."
      ]
    ],
    [
      "count() / sum()",
      "Calculates aggregate values after grouping.",
      "select count() as Name",
      "select count() as hits",
      [
        "Use count() for row volume.",
        "Use numeric aggregations only on compatible columns."
      ]
    ],
    [
      "in",
      "Tests whether a value belongs to a list.",
      "Field in (Value1, Value2)",
      "sourceIp in (8.8.8.8, 1.1.1.1)",
      [
        "Comma-separate list values.",
        "Keep value types compatible with the field."
      ]
    ],
    [
      "toktains",
      "Tests whether tokenized text contains a token.",
      "toktains(Field, Token)",
      'toktains(message, "powershell")',
      [
        "Use for token-aware text search.",
        "Use exact comparison when the whole value must match."
      ]
    ],
    [
      "matches",
      "Tests a string against a regular expression.",
      "matches(Field, Regex)",
      'matches(message, "(?i).*failed login.*")',
      [
        "Keep the pattern specific.",
        "Escaping rules apply inside the query string literal."
      ]
    ]
  ]),
  spotter: commands([
    [
      "= / !=",
      "Tests exact equality or inequality on a Securonix attribute.",
      "Attribute Operator Value",
      'rg_functionality = "Login"',
      [
        "Use an indexed attribute exposed in Spotter.",
        "Quote text values where required by the editor."
      ]
    ],
    [
      "> / >= / < / <=",
      "Compares ordered numeric or date-compatible values.",
      "Attribute Operator Value",
      "risk_score >= 80",
      [
        "Use only with a compatible attribute type.",
        "Combine bounds with AND for a range."
      ]
    ],
    [
      "IN",
      "Matches any value in a list.",
      "Attribute IN (Value1, Value2)",
      'sourceaddress IN ("8.8.8.8", "1.1.1.1")',
      [
        "Comma-separate list values.",
        "Keep all values compatible with the attribute."
      ]
    ],
    [
      "NOT IN",
      "Excludes every value in a list.",
      "Attribute NOT IN (Value1, Value2)",
      'resourcegroupname NOT IN ("test", "lab")',
      [
        "Use for compact multi-value exclusion.",
        "Check missing-value behavior separately when relevant."
      ]
    ],
    [
      "CONTAINS",
      "Tests whether a text attribute contains a value.",
      "Attribute CONTAINS Value",
      'requestclientapplication CONTAINS "PowerShell"',
      [
        "Use for literal containment.",
        "Attribute normalization can affect case behavior."
      ]
    ],
    [
      "RLIKE",
      "Matches a text attribute using a regular expression.",
      "Attribute RLIKE Pattern",
      'requestclientapplication RLIKE ".*powershell.*-enc.*"',
      [
        "Use only when pattern matching is required.",
        "Keep expressions bounded to reduce noisy results."
      ]
    ],
    [
      "AND / OR",
      "Combines required or alternative criteria.",
      "Criterion AND|OR Criterion",
      'sourceaddress = "8.8.8.8" OR destinationaddress = "8.8.8.8"',
      [
        "Parenthesize OR alternatives combined with AND.",
        "Repeat the field comparison for each criterion."
      ]
    ],
    [
      "NOT",
      "Negates a criterion or group.",
      "NOT Criterion",
      'NOT resourcegroupname = "test"',
      [
        "Use parentheses around compound exclusions.",
        "NOT IN is clearer for excluding a value list."
      ]
    ]
  ]),
  ccl: commands([
    [
      "AND / OR / NOT",
      "Combines or negates ArcSight common conditions.",
      "Condition AND|OR Condition | NOT Condition",
      "sourceAddress = 8.8.8.8 OR destinationAddress = 8.8.8.8",
      [
        "Use groups to make mixed Boolean logic explicit.",
        "Evaluate null behavior when negating a field condition."
      ]
    ],
    [
      "= / != / < / <= / > / >=",
      "Compares an event field with a compatible value.",
      "Field Operator Value",
      "priority >= 8",
      [
        "Use an operator supported by the field type.",
        "Quote textual values in editors that require it."
      ]
    ],
    [
      "In",
      "Tests whether a field matches one of several values.",
      "Field In (Value1, Value2)",
      "sourceAddress In (8.8.8.8, 1.1.1.1)",
      [
        "Use for compact value lists.",
        "Keep list values compatible with the field."
      ]
    ],
    [
      "InSubnet",
      "Tests whether an address belongs to an IP subnet.",
      "Field InSubnet CIDR",
      "sourceAddress InSubnet 10.0.0.0/8",
      [
        "Use only with address fields.",
        "Choose the narrowest intended CIDR prefix."
      ]
    ],
    [
      "Contains",
      "Tests literal substring containment.",
      "Field Contains Value",
      'name Contains "failed login"',
      [
        "Use on compatible string fields.",
        "Choose Matches when a regex is required."
      ]
    ],
    [
      "StartsWith / EndsWith",
      "Tests a literal prefix or suffix.",
      "Field StartsWith|EndsWith Value",
      'requestUrl EndsWith ".exe"',
      [
        "StartsWith is useful for namespaces and prefixes.",
        "EndsWith is useful for extensions and suffixes."
      ]
    ],
    [
      "Matches",
      "Tests a string with a regular expression.",
      "Field Matches Pattern",
      'name Matches ".*(PowerShell|pwsh).*"',
      [
        "Keep the regex specific.",
        "Escape pattern metacharacters that should be literal."
      ]
    ],
    [
      "Like",
      "Matches a supported wildcard-style text pattern.",
      "Field Like Pattern",
      'deviceProduct Like "Windows*"',
      [
        "Use wildcard syntax supported by the condition editor.",
        "Use equality when wildcard behavior is unnecessary."
      ]
    ]
  ]),
  nwql: commands([
    [
      "meta = value",
      "Tests an indexed NetWitness meta key for equality.",
      "MetaKey = Value",
      "ip.src = 8.8.8.8",
      [
        "Use an indexed meta key available in the collection.",
        "Quote text containing spaces or reserved characters."
      ]
    ],
    [
      "meta = value1,value2",
      "Matches a meta key against a comma-separated value list.",
      "MetaKey = Value1, Value2",
      "service = 80, 443",
      [
        "Comma-separated values form alternatives for the same key.",
        "Keep values compatible with the meta type."
      ]
    ],
    [
      "&&",
      "Requires both query conditions.",
      "Condition && Condition",
      "ip.src = 8.8.8.8 && service = 53",
      [
        "Group mixed Boolean expressions with parentheses.",
        "Place selective conditions early for readability."
      ]
    ],
    [
      "||",
      "Accepts either query condition.",
      "Condition || Condition",
      "ip.src = 8.8.8.8 || ip.dst = 8.8.8.8",
      [
        "Group alternatives before combining them with &&.",
        "Repeat the meta key when alternatives target different fields."
      ]
    ],
    [
      "!",
      "Negates a query condition.",
      "! Condition",
      "!(action = allow)",
      [
        "Parenthesize the negated condition.",
        "Check whether missing meta values should also be included."
      ]
    ],
    [
      "contains",
      "Tests whether text meta contains a literal value.",
      "MetaKey contains Value",
      'alias.host contains "example"',
      [
        "Use with a compatible text meta key.",
        "Choose regex only for genuine pattern matching."
      ]
    ],
    [
      "regex",
      "Matches text meta with a regular expression.",
      "MetaKey regex Pattern",
      'filename regex ".*\\.(exe|dll)"',
      [
        "Escape literal punctuation.",
        "Keep the pattern constrained to reduce broad matches."
      ]
    ],
    [
      "( ... )",
      "Groups conditions to control Boolean evaluation.",
      "(Condition || Condition) && Condition",
      "(ip.src = 8.8.8.8 || ip.dst = 8.8.8.8) && service = 53",
      [
        "Use around OR alternatives combined with AND.",
        "Nested groups are allowed when needed."
      ]
    ]
  ]),
  sql: commands([
    [
      "SELECT ... FROM",
      "Chooses columns from an osquery virtual table.",
      "SELECT Columns FROM Table",
      "SELECT pid, name, path FROM processes",
      [
        "Use * only when every column is genuinely useful.",
        "Inspect the table schema for available platform-specific columns."
      ]
    ],
    [
      "WHERE",
      "Filters rows using a Boolean predicate.",
      "WHERE Predicate",
      "WHERE pid > 0 AND name = 'powershell.exe'",
      [
        "Use AND, OR, NOT and parentheses.",
        "SQLite comparison and type-conversion rules apply."
      ]
    ],
    [
      "JOIN",
      "Combines related rows from two virtual tables.",
      "FROM Left JOIN Right ON Left.Key = Right.Key",
      "FROM processes p JOIN users u ON p.uid = u.uid",
      [
        "Use table aliases to disambiguate columns.",
        "LEFT JOIN keeps unmatched rows from the left table."
      ]
    ],
    [
      "GROUP BY",
      "Groups rows for aggregate functions.",
      "GROUP BY Expression",
      "GROUP BY name",
      [
        "Selected non-aggregate columns should identify the group.",
        "Use multiple expressions for compound groups."
      ]
    ],
    [
      "HAVING",
      "Filters groups after aggregation.",
      "HAVING AggregatePredicate",
      "HAVING COUNT(*) > 3",
      ["Use after GROUP BY.", "Use WHERE to filter rows before aggregation."]
    ],
    [
      "ORDER BY",
      "Orders rows by expressions or aliases.",
      "ORDER BY Expression ASC|DESC",
      "ORDER BY process_count DESC",
      [
        "ASC is the default ascending direction.",
        "Add more fields to break ties deterministically."
      ]
    ],
    [
      "LIMIT",
      "Caps the result row count.",
      "LIMIT Number [OFFSET Number]",
      "LIMIT 50",
      [
        "Use OFFSET for pagination when appropriate.",
        "Pair with ORDER BY for a deterministic subset."
      ]
    ],
    [
      "IN",
      "Tests membership in a list or subquery result.",
      "Expression IN (ValuesOrSubquery)",
      "WHERE name IN ('powershell.exe', 'pwsh.exe')",
      [
        "NOT IN performs the inverse test.",
        "Nulls in a subquery can affect NOT IN semantics."
      ]
    ],
    [
      "LIKE",
      "Matches a string using % and _ wildcards.",
      "Expression LIKE Pattern",
      "WHERE path LIKE '%\\Temp\\%'",
      [
        "% matches any sequence; _ matches one character.",
        "Case behavior follows SQLite/osquery settings."
      ]
    ],
    [
      "REGEXP",
      "Matches a string with the regex implementation exposed by osquery.",
      "Expression REGEXP Pattern",
      "WHERE cmdline REGEXP 'powershell.*-enc'",
      [
        "Regex support can depend on the osquery build.",
        "Use LIKE for simple wildcard matching."
      ]
    ]
  ]),
  regex: commands([
    [
      "literal",
      "Matches an ordinary character exactly.",
      "text",
      "malware",
      [
        "Escape metacharacters when they should be literal.",
        "Case sensitivity is controlled by the host engine or flags."
      ]
    ],
    [
      ".",
      "Matches one character, usually excluding a newline.",
      ".",
      "file.exe",
      [
        "Escape as \\. to match a literal dot.",
        "Dot-all mode changes whether newlines are included."
      ]
    ],
    [
      "* / + / ?",
      "Repeats the preceding atom zero-or-more, one-or-more or zero-or-one times.",
      "Atom* | Atom+ | Atom?",
      "https?://",
      [
        "* and ? allow zero occurrences.",
        "Behavior can be greedy or lazy depending on engine and suffix."
      ]
    ],
    [
      "{n,m}",
      "Applies an explicit repetition bound.",
      "Atom{Minimum,Maximum}",
      "[0-9]{1,5}",
      [
        "{n} requires exactly n repetitions.",
        "An omitted upper bound, {n,}, means at least n."
      ]
    ],
    [
      "|",
      "Matches the expression on either side.",
      "Left|Right",
      "powershell|pwsh",
      [
        "Group alternatives when they are part of a larger expression.",
        "Alternation precedence is lower than concatenation."
      ]
    ],
    [
      "(...) ",
      "Groups subexpressions and, in many engines, captures the match.",
      "(Expression)",
      "(cmd|powershell)\\.exe",
      [
        "Use (?:...) for non-capturing groups only when the engine supports it.",
        "Capture numbering follows opening-parenthesis order."
      ]
    ],
    [
      "[...]",
      "Matches one character from a class or range.",
      "[Characters] | [^Characters]",
      "[A-Fa-f0-9]",
      [
        "A leading ^ negates the class.",
        "Hyphen defines a range unless escaped or placed safely."
      ]
    ],
    [
      "^ / $",
      "Anchors the match to the beginning or end of a line or string.",
      "^Expression$",
      "^[0-9]+$",
      [
        "Multiline mode changes line-anchor behavior.",
        "Some engines distinguish string anchors from line anchors."
      ]
    ],
    [
      "\\",
      "Escapes a metacharacter or introduces an engine-defined token.",
      "\\Metacharacter",
      "example\\.com",
      [
        "Double escaping may be required inside a programming-language string.",
        "Tokens such as \\d or \\w are engine-dependent."
      ]
    ],
    [
      "grep -E / rg",
      "Runs an extended-regex search from a command line.",
      "rg [Options] Pattern Path",
      'rg -n -i "powershell|pwsh" logs/',
      [
        "-i ignores case; -n shows line numbers.",
        "rg uses its own supported regex engine and command options."
      ]
    ]
  ]),
  powershell: commands([
    [
      "Select-String -Pattern",
      "Searches strings or files with one or more regex patterns.",
      "Select-String -Pattern Pattern [-Path Path]",
      "Select-String -Pattern 'failed|denied' -Path .\\*.log",
      [
        "-Path accepts wildcard paths; -LiteralPath treats them literally.",
        "Pipeline input can replace the path parameter."
      ]
    ],
    [
      "-SimpleMatch",
      "Treats Select-String patterns as literal text instead of regex.",
      "Select-String -Pattern Text -SimpleMatch",
      "Select-String -Pattern '[error]' -SimpleMatch app.log",
      [
        "Useful when punctuation must remain literal.",
        "Other Select-String output behavior remains unchanged."
      ]
    ],
    [
      "-CaseSensitive",
      "Makes Select-String matching case-sensitive.",
      "Select-String -Pattern Pattern -CaseSensitive",
      "Select-String -Pattern 'ERROR' -CaseSensitive app.log",
      [
        "Matching is case-insensitive by default.",
        "Combine with -SimpleMatch for case-sensitive literal text."
      ]
    ],
    [
      "-AllMatches",
      "Returns every match on each input line.",
      "Select-String -Pattern Pattern -AllMatches",
      "Select-String -Pattern '\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b' -AllMatches log.txt",
      [
        "Inspect the MatchInfo.Matches collection.",
        "Without it, Select-String reports only the first match per line."
      ]
    ],
    [
      "-Context",
      "Includes lines before and after each Select-String match.",
      "Select-String -Pattern Pattern -Context Before,After",
      "Select-String -Pattern 'error' -Context 2,3 app.log",
      [
        "One number applies the same context on both sides.",
        "Context lines are available on the MatchInfo object."
      ]
    ],
    [
      "Get-WinEvent -FilterHashtable",
      "Filters Windows event logs at the provider using supported hash-table keys.",
      "Get-WinEvent -FilterHashtable @{ LogName=...; Id=... }",
      "Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 }",
      [
        "Common keys include LogName, ProviderName, Id, Level, StartTime and EndTime.",
        "Provider-side filtering is preferable to filtering all events later."
      ]
    ],
    [
      "Get-WinEvent -FilterXPath",
      "Uses an XPath query to filter Windows events.",
      "Get-WinEvent -LogName Name -FilterXPath XPath",
      "Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4625)]]'",
      [
        "XPath addresses the event XML structure.",
        "Quote the XPath so PowerShell does not reinterpret its characters."
      ]
    ],
    [
      "Where-Object",
      "Filters PowerShell objects later in a pipeline.",
      "Pipeline | Where-Object { Predicate }",
      "Get-Process | Where-Object { $_.CPU -gt 100 }",
      [
        "$_ is the current pipeline object.",
        "Prefer source-side filtering when the command supports it."
      ]
    ],
    [
      "-match / -notmatch",
      "Tests a string against a regex or its negation.",
      "String -match Regex",
      "$line -match '(?i)powershell.*-enc'",
      [
        "Successful -match populates the automatic $Matches variable.",
        "Use -cmatch for an explicitly case-sensitive comparison."
      ]
    ],
    [
      "Select-Object / Group-Object",
      "Shapes pipeline output or groups objects by property.",
      "Pipeline | Select-Object Properties | Group-Object Property",
      "Get-Process | Group-Object Name | Select-Object Name, Count",
      [
        "Select-Object supports calculated properties.",
        "Group-Object can return a hash table with -AsHashTable."
      ]
    ]
  ])
}
