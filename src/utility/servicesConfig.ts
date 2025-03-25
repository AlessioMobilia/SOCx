// src/utils/servicesConfig.ts
// src/utils/servicesConfig.ts
export const servicesConfig = {
  services: {
    VirusTotal: {
      title: "Verifica su VirusTotal",
      supportedTypes: ["IP", "Dominio", "URL", "Hash"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://www.virustotal.com/gui/ip-address/${text}`;
          case "Dominio": return `https://www.virustotal.com/gui/domain/${text}`;
          case "URL": return `https://www.virustotal.com/gui/url/${encodeURIComponent(text)}`;
          case "Hash": return `https://www.virustotal.com/gui/file/${text}`;
          default: return null;
        }
      },
    },
    AbuseIPDB: {
      title: "Verifica su AbuseIPDB",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.abuseipdb.com/check/${text}`,
    },
    Censys: {
      title: "Verifica su Censys",
      supportedTypes: ["IP", "Dominio"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://search.censys.io/hosts/${text}`;
          case "Dominio": return `https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=${text}`;
          default: return null;
        }
      },
    },
    IPQualityScore: {
      title: "Verifica su IPQualityScore",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${text}`,
    },
    IPinfo: {
      title: "Verifica su IPinfo",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://ipinfo.io/${text}`,
    },
    AlienVault: {
      title: "Verifica su AlienVault",
      supportedTypes: ["IP", "Dominio"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://otx.alienvault.com/indicator/ip/${text}`;
          case "Dominio": return `https://otx.alienvault.com/indicator/domain/${text}`;
          case "Hash": return `https://otx.alienvault.com/indicator/file/${text}`;
          default: return null;
        }
      },
    },
    IBMXForce: {
      title: "Verifica su IBM X-Force",
      supportedTypes: ["IP", "Dominio", "URL"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://exchange.xforce.ibmcloud.com/ip/${text}`;
          case "Dominio": return `https://exchange.xforce.ibmcloud.com/url/${text}`;
          default: return null;
        }
      },
    },
    MxToolbox: {
      title: "Verifica su MxToolbox",
      supportedTypes: ["IP", "Dominio"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://mxtoolbox.com/SuperTool.aspx?action=arin%3a${text}`;
          case "Dominio": return `https://mxtoolbox.com/SuperTool.aspx?action=dns%3a${text}`;
          default: return null;
        }
      },
    },
    Pulsedive: {
      title: "Verifica su Pulsedive",
      supportedTypes: ["IP", "Dominio", "Hash"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://pulsedive.com/indicator/${text}`;
          case "Dominio": return `https://pulsedive.com/indicator/${text}`;
          case "Hash": return `https://pulsedive.com/indicator/${text}`;
          default: return null;
        }
      },
    },
    Spur: {
      title: "Verifica su Spur.us",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://spur.us/context/${text}`,
    },
    PassiveDNS: {
      title: "Verifica su PassiveDNS (mnemonic)",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://passivedns.mnemonic.no/#/search?query=${text}`,
    },
    Hunter: {
      title: "Verifica su Hunter.io",
      supportedTypes: ["Email"],
      url: (type: string, text: string) => `https://hunter.io/email-verifier/${text}`,
    },
    ViewDNS: {
      title: "Verifica su ViewDNS.info",
      supportedTypes: ["Dominio","IP"],
      url: (type: string, text: string) => {
        switch (type) {
          case "IP": return `https://viewdns.info/iphistory/?domain=${text}`;
          case "Dominio": return `https://viewdns.info/reverseip/?host=${text}&t=1`;
          default: return null;
        }
      },
    },
    Shodan: {
      title: "Verifica su Shodan",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://www.shodan.io/host/${text}`,
    },
    SecurityTrails: {
      title: "Verifica su SecurityTrails",
      supportedTypes: ["Dominio"],
      url: (type: string, text: string) => {
        switch (type) {
          case "Dominio": return `https://securitytrails.com/domain/${text}`;
          default: return null;
        }
      },
    },
    UrlScan: {
      title: "Verifica su UrlScan",
      supportedTypes: ["Dominio","URL"],
      url: (type: string, text: string) => `https://urlscan.io/search/#${encodeURIComponent(text)}`,
    },
    HaveIBeenPwned: {
      title: "Verifica su Have I Been Pwned",
      supportedTypes: ["Email"],
      url: (type: string, text: string) => `https://haveibeenpwned.com/unifiedsearch/${encodeURIComponent(text)}`,
    },
    // Servizi per la ricerca di indirizzi MAC
    MACVendors: {
      title: "Verifica su MAC Vendors",
      supportedTypes: ["MAC"],
      url: (type: string, text: string) => `https://api.macvendors.com/${text}`,
    },
    WiresharkOUI: {
      title: "Verifica su Wireshark OUI Lookup",
      supportedTypes: ["MAC"],
      url: (type: string, text: string) => `https://www.wireshark.org/tools/oui-lookup.html?search=${text}`,
    },
    GreyNoise: {
      title: "Verifica su GreyNoise",
      supportedTypes: ["IP"],
      url: (type: string, text: string) => `https://viz.greynoise.io/ip/${text}`,
    },
    PhishTank: {
      title: "Verifica su PhishTank",
      supportedTypes: ["URL"],
      url: (type: string, text: string) => `https://www.phishtank.com/`,
    },
    MalwareBazaar: {
      title: "Verifica su MalwareBazaar",
      supportedTypes: ["Hash"],
      url: (type: string, text: string) => `https://bazaar.abuse.ch/sample/${text}`,
    },
    Robtex: {
      title: "Verifica su Robtex",
      supportedTypes: ["IP", "Dominio"],
      url: (type: string, text: string) => `https://www.robtex.com/ip-lookup/${text}`,
    },
    BGPToolkit: {
      title: "Verifica su BGP Toolkit",
      supportedTypes: ["ASN"],
      url: (type: string, text: string) => `https://bgp.he.net/${text}`,
    },
  },
  availableServices: {
    IP: ["VirusTotal", "AbuseIPDB", "Censys", "IPQualityScore", "IPinfo", "AlienVault", "IBMXForce", "MxToolbox", "Pulsedive", "Spur", "PassiveDNS", "Shodan", "GreyNoise", "ViewDNS"],
    Dominio: ["VirusTotal", "Censys", "AlienVault", "IBMXForce", "MxToolbox", "Pulsedive", "SecurityTrails", "ViewDNS", "Robtex"],
    URL: ["VirusTotal", "IBMXForce", "UrlScan", "PhishTank"],
    Hash: ["VirusTotal", "MalwareBazaar", "Pulsedive", "AlienVault"],
    Email: [ "Hunter", "HaveIBeenPwned"],
    ASN: ["BGPToolkit"],
    MAC: ["MACVendors", "WiresharkOUI"],
  },
};