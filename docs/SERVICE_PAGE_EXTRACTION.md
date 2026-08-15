# IOC service-page extraction

SOCx only displays the page-copy button when a provider-specific parser finds
enough structured result data. The parser registry does not scan arbitrary
tables, headings, labels or visible summaries.

The matrix below was audited against the public destinations on 2026-08-15.
Opening a provider remains available even when page extraction is disabled.

| Provider                       | Page copy | Exact extraction source or reason                                                                                    |
| ------------------------------ | --------- | -------------------------------------------------------------------------------------------------------------------- |
| VirusTotal                     | Enabled   | Detection score card and the open Shadow DOM key/value widgets.                                                      |
| AbuseIPDB                      | Enabled   | `.col-md-6 .well`, after matching its displayed IP to the URL IOC.                                                   |
| Censys                         | Disabled  | The legacy public URL redirects to the authenticated Censys Platform.                                                |
| IPQualityScore                 | Enabled   | The result card containing `#lookupForm`, its first lookup table and `Risk Summary`.                                 |
| IPinfo                         | Enabled   | Summary and geolocation tables inside the IOC page `main`.                                                           |
| LevelBlue OTX                  | Enabled   | `.item` fields inside the `otx-ip-summary` component.                                                                |
| IBM X-Force                    | Enabled   | `h3.h3details + table.detailsline` and `#whois table.detailsline` only. Timeline tables are excluded.                |
| MxToolbox                      | Enabled   | `.tool-result-div.lookup-type-arin .tool-result-body`, parsed as an ARIN WHOIS transcript. Help tables are excluded. |
| Pulsedive                      | Enabled   | The IOC page `Risk`, `Highlights` and `Events` blocks.                                                               |
| Spur                           | Enabled   | Label/value elements inside the `IP CONTEXT` page `main`.                                                            |
| Mnemonic Passive DNS           | Disabled  | The public shell did not expose a stable result DOM.                                                                 |
| Hunter                         | Disabled  | The result requires an authenticated flow.                                                                           |
| Shodan                         | Enabled   | `#host`, specifically the `#general + .grid-table` host-information grid.                                            |
| SecurityTrails                 | Disabled  | DNS record rows did not expose sufficiently stable value hooks.                                                      |
| urlscan.io                     | Disabled  | The configured destination is an aggregate search result page.                                                       |
| Have I Been Pwned              | Disabled  | The configured unified-search endpoint returns `401 Unauthorized`.                                                   |
| MAC Vendors                    | Enabled   | The endpoint's `text/plain` vendor response.                                                                         |
| Wireshark OUI                  | Disabled  | The configured query URL did not expose a lookup result.                                                             |
| GreyNoise                      | Disabled  | The public page shell did not expose result data.                                                                    |
| MalwareBazaar                  | Disabled  | The destination returned an anti-bot interstitial.                                                                   |
| Robtex                         | Disabled  | The public result could not be loaded reliably.                                                                      |
| Hurricane Electric BGP Toolkit | Enabled   | `#asinfo`, including paired `.asleft`/`.asright` metadata and selected routing statistics.                           |
| Triage                         | Disabled  | The configured destination is an aggregate search result page.                                                       |
| ThreatFox                      | Disabled  | The destination returned an anti-bot interstitial.                                                                   |
| ViewDNS.info                   | Enabled   | The table following the IOC-specific “results for” heading.                                                          |
| Cisco Talos                    | Disabled  | The public result could not be loaded reliably.                                                                      |
| URLhaus                        | Disabled  | The destination returned an anti-bot interstitial.                                                                   |
| Spamhaus                       | Disabled  | The destination returned a localized Cloudflare interstitial.                                                        |
| RIPEstat                       | Enabled   | `#resource-tabs` Routing Status widget and its explicit status sentences.                                            |
| Cloudflare Radar               | Enabled   | WHOIS description list and DNS table in their named `article` widgets.                                               |
| ThreatMiner                    | Disabled  | The public result timed out during the audit.                                                                        |
| Certificate Transparency       | Disabled  | The public result timed out during the audit.                                                                        |
| CIRCL Hashlookup               | Enabled   | The endpoint's JSON response, restricted to scalar hash/file metadata and `ProductCode.ProductName`.                 |

When a provider changes its markup, keep extraction disabled until its parser
and DOM fixture are updated together. A single recognized field is not enough,
except for intrinsically single-value sources such as MAC Vendors and a
single-column ViewDNS result.
