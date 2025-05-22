// src/utils/servicesConfig.ts

export const servicesConfig = {
  services: {
    VirusTotal: {
      title: "Check on VirusTotal",
      supportedTypes: ["IP", "Domain", "URL", "Hash"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://www.virustotal.com/gui/ip-address/${text}`;
          case "Domain": return `https://www.virustotal.com/gui/domain/${text}`;
          case "URL": return `https://www.virustotal.com/gui/url/${encodeURIComponent(text)}`;
          case "Hash": return `https://www.virustotal.com/gui/file/${text}`;
          default: return null;
        }
      },
    },
    AbuseIPDB: {
      title: "Check on AbuseIPDB",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.abuseipdb.com/check/${text}`,
    },
    Censys: {
      title: "Check on Censys",
      supportedTypes: ["IP", "Domain"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://search.censys.io/hosts/${text}`;
          case "Domain": return `https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=${text}`;
          default: return null;
        }
      },
    },
    IPQualityScore: {
      title: "Check on IPQualityScore",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${text}`,
    },
    IPinfo: {
      title: "Check on IPinfo",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://ipinfo.io/${text}`,
    },
    AlienVault: {
      title: "Check on AlienVault",
      supportedTypes: ["IP", "Domain"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://otx.alienvault.com/indicator/ip/${text}`;
          case "Domain": return `https://otx.alienvault.com/indicator/domain/${text}`;
          case "Hash": return `https://otx.alienvault.com/indicator/file/${text}`;
          default: return null;
        }
      },
    },
    IBMXForce: {
      title: "Check on IBM X-Force",
      supportedTypes: ["IP", "Domain", "URL"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://exchange.xforce.ibmcloud.com/ip/${text}`;
          case "Domain": return `https://exchange.xforce.ibmcloud.com/url/${text}`;
          default: return null;
        }
      },
    },
    MxToolbox: {
      title: "Check on MxToolbox",
      supportedTypes: ["IP", "Domain"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://mxtoolbox.com/SuperTool.aspx?action=arin%3a${text}`;
          case "Domain": return `https://mxtoolbox.com/SuperTool.aspx?action=dns%3a${text}`;
          default: return null;
        }
      },
    },
    Pulsedive: {
      title: "Check on Pulsedive",
      supportedTypes: ["IP", "Domain", "Hash"],
      url: (type: string, text: string) => `https://pulsedive.com/indicator/${text}`,
    },
    Spur: {
      title: "Check on Spur.us",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://spur.us/context/${text}`,
    },
    PassiveDNS: {
      title: "Check on PassiveDNS (mnemonic)",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://passivedns.mnemonic.no/#/search?query=${text}`,
    },
    Hunter: {
      title: "Check on Hunter.io",
      supportedTypes: ["Email"],
      url: (type: string, text: string) => `https://hunter.io/email-verifier/${text}`,
    },
    Shodan: {
      title: "Check on Shodan",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.shodan.io/host/${text}`,
    },
    SecurityTrails: {
      title: "Check on SecurityTrails",
      supportedTypes: ["Domain"],
      url: (type: string, text: string) => `https://securitytrails.com/domain/${text}`,
    },
    UrlScan: {
      title: "Check on UrlScan",
      supportedTypes: ["Domain", "URL"],
      url: (type: string, text: string) => `https://urlscan.io/search/#${encodeURIComponent(text)}`,
    },
    HaveIBeenPwned: {
      title: "Check on Have I Been Pwned",
      supportedTypes: ["Email"],
      url: (type: string, text: string) => `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(text)}`,
    },
    MACVendors: {
      title: "Check on MAC Vendors",
      supportedTypes: ["MAC"],
      url: (type: string, text: string) => `https://api.macvendors.com/${text}`,
    },
    WiresharkOUI: {
      title: "Check on Wireshark OUI Lookup",
      supportedTypes: ["MAC"],
      url: (type: string, text: string) => `https://www.wireshark.org/tools/oui-lookup.html?search=${text}`,
    },
    GreyNoise: {
      title: "Check on GreyNoise",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://viz.greynoise.io/ip/${text}`,
    },
    PhishTank: {
      title: "Check on PhishTank",
      supportedTypes: ["URL"],
      url: (type: string, text: string) => `https://www.phishtank.com/`,
    },
    MalwareBazaar: {
      title: "Check on MalwareBazaar",
      supportedTypes: ["Hash"],
      url: (type: string, text: string) => `https://bazaar.abuse.ch/sample/${text}`,
    },
    Robtex: {
      title: "Check on Robtex",
      supportedTypes: ["IP", "Domain"],
      url: (type: string, text: string) => `https://www.robtex.com/ip-lookup/${text}`,
    },
    BGPToolkit: {
      title: "Check on BGP Toolkit",
      supportedTypes: ["ASN"],
      url: (type: string, text: string) => `https://bgp.he.net/${text}`,
    },
    Tria_ge: {
      title: "Check on Tria.ge",
      supportedTypes: ["Hash", "URL"],
      url: (type: string, text: string) => `https://tria.ge/s?q=${encodeURIComponent(text)}`,
    },
    ThreatFox: {
      title: "Check on ThreatFox",
      supportedTypes: ["IP", "Hash", "URL", "Domain"],
      url: (type: string, text: string) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A+${encodeURIComponent(text)}`,
    },
    Google: {
      title: "Search on Google",
      supportedTypes: ["IP", "Hash", "URL", "Domain", "Email", "ASN", "MAC"],
      url: (type: string, text: string) => `https://www.google.com/search?q="${encodeURIComponent(text)}"`,
    },
    ViewDNS: {
      title: "Check on ViewDNS.info",
      supportedTypes: ["Domain", "IP", "ASN"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://viewdns.info/reversedns/?ip=${text}`;
          case "Domain": return `https://viewdns.info/whois/?domain=${text}`;
          case "ASN": return `https://viewdns.info/asnlookup/?asn=${text.replace(/^AS/i, "")}`;
          default: return null;
        }
      },
    },
  },

  availableServices: {
    IP: [
      "VirusTotal", "AbuseIPDB", "Censys", "IPQualityScore", "IPinfo", "AlienVault",
      "IBMXForce", "MxToolbox", "Pulsedive", "Spur", "PassiveDNS", "Shodan",
      "GreyNoise", "ViewDNS", "ThreatFox", "Google"
    ],
    Domain: [
      "VirusTotal", "Censys", "AlienVault", "IBMXForce", "MxToolbox", "Pulsedive",
      "SecurityTrails", "ViewDNS", "Robtex", "ThreatFox", "Google"
    ],
    URL: [
      "VirusTotal", "IBMXForce", "UrlScan", "PhishTank", "Tria_ge", "ThreatFox", "Google"
    ],
    Hash: [
      "VirusTotal", "MalwareBazaar", "Pulsedive", "AlienVault", "Tria_ge", "ThreatFox", "Google"
    ],
    Email: ["Hunter", "HaveIBeenPwned", "Google"],
    ASN: ["BGPToolkit", "ViewDNS", "Google"],
    MAC: ["MACVendors", "WiresharkOUI", "Google"],
  },
};
