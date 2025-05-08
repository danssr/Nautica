// --- START OF ASSEMBLED Cloudflare Worker Code ---

// --- SECTION 1: Global State, Configuration Notes, Constants ---

// Global state
let workerGlobalProxyIP = ""; // Target IP for WebSocket proxying, set per request.
let workerGlobalCachedProxyList = []; // In-memory proxy list cache.
let workerGlobalCachedProxyListTimestamp = 0; // Timestamp for cache expiry.
const PROXY_LIST_CACHE_TTL_MS = 15 * 60 * 1000; // Cache Time-To-Live: 15 minutes in milliseconds.

// Configuration Notes:
// This worker expects certain configurations to be provided by the Cloudflare environment:
// - Worker Secrets (set via `wrangler secret put` or GitHub Actions):
//   - CF_API_KEY      : Your Cloudflare Global API Key.
//   - CF_API_EMAIL    : Your Cloudflare account email.
//   - CF_ACCOUNT_ID   : Your Cloudflare Account ID.
//   - CF_ZONE_ID      : Your Cloudflare Zone ID for domain operations.
// - Environment Variables (set in wrangler.toml `[vars]` or via GitHub Actions):
//   - ROOT_DOMAIN     : The primary domain (e.g., "foolvpn.me").
//   - SERVICE_NAME    : The name of this worker service (e.g., "nautica").
//   - (Optional) Override URLs for proxy lists, converter, etc. (e.g., KV_PROXY_URL_OVERRIDE)
// All these will be accessible via the `env` object passed to the fetch handler.

const APP_CONFIG = {
  DEFAULT_PORTS: [443, 80],
  PROXIES_PER_PAGE: 24,
  DNS_SERVER_ADDRESS: "8.8.8.8",
  DNS_SERVER_PORT: 53,
};

const PROTOCOLS = {
  URI_SCHEMES: {
    TROJAN: "najort".split("").reverse().join(""),
    VLESS: "sselv".split("").reverse().join(""),
    SHADOWSOCKS: "ss".split("").reverse().join(""),
  },
  SNIFFER_RESULTS: {
    TROJAN: "najorT".split("").reverse().join(""),
    VLESS: "SSELV".split("").reverse().join(""),
    SHADOWSOCKS: "skcoswodahS".split("").reverse().join(""),
  },
};

const ORDERED_PROTOCOLS_FOR_SUBSCRIPTION = [
  PROTOCOLS.URI_SCHEMES.TROJAN,
  PROTOCOLS.URI_SCHEMES.VLESS,
  PROTOCOLS.URI_SCHEMES.SHADOWSOCKS,
];

const DEFAULT_EXTERNAL_URLS = {
  KV_PROXY_LIST: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json",
  PROXY_BANK: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt",
  PROXY_HEALTH_CHECK_API: "https://id1.foolvpn.me/api/v1/check",
  CONFIG_CONVERTER_API: "https://api.foolvpn.me/convert",
  DONATE_LINK: "https://trakteer.id/dickymuliafiqri/tip",
  BAD_WORDS_LIST: "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt",
};

const WEBSOCKET_STATE = Object.freeze({
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
});

const CORS_HEADERS = Object.freeze({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, User-Agent, X-Requested-With, Sec-WebSocket-Protocol",
  "Access-Control-Max-Age": "86400",
});


// --- SECTION 11: Utility Helper Functions (Partial - needed early) ---
function arrayBufferToHexString(bufferSource) {
  const byteArray = bufferSource instanceof Uint8Array ? bufferSource : new Uint8Array(bufferSource);
  let hexString = "";
  for (let i = 0; i < byteArray.length; i++) {
    const hex = byteArray[i].toString(16);
    hexString += hex.length === 1 ? "0" + hex : hex;
  }
  return hexString;
}

function getFlagEmoji(isoCountryCode) {
  if (typeof isoCountryCode !== 'string' || isoCountryCode.length !== 2) {
    return isoCountryCode; 
  }
  try {
    const base = 127397;
    const codePoints = isoCountryCode
      .toUpperCase()
      .split("")
      .map(char => base + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  } catch (error) {
    console.warn(`getFlagEmoji: Could not convert ISO code "${isoCountryCode}" to emoji.`, error);
    return isoCountryCode;
  }
}

function shuffleArray(array) {
  if (!array || array.length === 0) return array;
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function decodeBase64ToArrayBuffer(base64UrlString) {
  if (!base64UrlString) {
    return { earlyData: null, error: null };
  }
  try {
    let base64StandardString = base64UrlString.replace(/-/g, "+").replace(/_/g, "/");
    while (base64StandardString.length % 4 !== 0) {
      base64StandardString += "=";
    }
    const decodedString = atob(base64StandardString);
    const buffer = new Uint8Array(decodedString.length);
    for (let i = 0; i < decodedString.length; i++) {
      buffer[i] = decodedString.charCodeAt(i);
    }
    return { earlyData: buffer.buffer, error: null };
  } catch (error) {
    console.error(`decodeBase64ToArrayBuffer: Failed to decode Base64 string. Input: "${base64UrlString.substring(0,30)}..."`, error);
    return { earlyData: null, error: new Error(`Base64 decoding failed: ${error.message}`) };
  }
}

// --- SECTION 10: Helper Functions (Partial - safeCloseWebSocket) ---
function safeCloseWebSocket(webSocketInstance, code, reason) {
  if (!webSocketInstance) {
    return;
  }
  try {
    if (
      webSocketInstance.readyState === WEBSOCKET_STATE.OPEN ||
      webSocketInstance.readyState === WEBSOCKET_STATE.CONNECTING
    ) {
      if (code !== undefined) {
        webSocketInstance.close(code, reason || "");
      } else {
        webSocketInstance.close();
      }
    }
  } catch (error) {
    console.error(`safeCloseWebSocket: Error attempting to close WebSocket: ${error.message}`, error);
  }
}


// --- SECTION 2: Proxy List Fetching Functions ---
async function fetchKVProxyList(kvProxyUrlOverride, env) {
  const url = kvProxyUrlOverride || env.KV_PROXY_URL_OVERRIDE || DEFAULT_EXTERNAL_URLS.KV_PROXY_LIST;
  if (!url) {
    console.error("fetchKVProxyList: No KV Proxy URL provided or configured.");
    return {};
  }
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': `CloudflareWorker/${env.SERVICE_NAME || 'NauticaProxy'}` }
    });
    if (response.ok) {
      return await response.json();
    } else {
      console.error(`fetchKVProxyList: Failed to fetch KV proxy list from ${url}. Status: ${response.status}`);
      return {};
    }
  } catch (error) {
    console.error(`fetchKVProxyList: Error fetching KV proxy list from ${url}. Error: ${error.message}`);
    return {};
  }
}

async function fetchAndCacheMainProxyList(proxyBankUrlOverride, env, forceRefresh = false) {
  const currentTime = Date.now();
  if (
    !forceRefresh &&
    workerGlobalCachedProxyList.length > 0 &&
    workerGlobalCachedProxyListTimestamp + PROXY_LIST_CACHE_TTL_MS > currentTime
  ) {
    return workerGlobalCachedProxyList;
  }

  const url = proxyBankUrlOverride || env.PROXY_BANK_URL_OVERRIDE || DEFAULT_EXTERNAL_URLS.PROXY_BANK;
  if (!url) {
    console.error("fetchAndCacheMainProxyList: No Proxy Bank URL provided or configured.");
    return workerGlobalCachedProxyList.length > 0 ? workerGlobalCachedProxyList : [];
  }

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': `CloudflareWorker/${env.SERVICE_NAME || 'NauticaProxy'}` }
    });
    if (response.ok) {
      const text = await response.text();
      if (!text) {
        console.warn(`fetchAndCacheMainProxyList: Proxy list from ${url} is empty.`);
        return workerGlobalCachedProxyList.length > 0 ? workerGlobalCachedProxyList : [];
      }
      const proxyEntries = text.trim().split("\n").filter(Boolean);
      const newProxyList = proxyEntries
        .map((entry) => {
          const parts = entry.split(",");
          if (parts.length < 2) {
            console.warn(`fetchAndCacheMainProxyList: Malformed entry: "${entry}"`);
            return null;
          }
          const [ip, port, country, org] = parts;
          return {
            proxyIP: ip.trim() || "Unknown",
            proxyPort: port.trim() || "Unknown",
            country: country ? country.trim().toUpperCase() : "XX",
            org: org ? org.trim() : "Unknown Organization",
          };
        })
        .filter(Boolean);

      if (newProxyList.length > 0) {
        workerGlobalCachedProxyList = newProxyList;
        workerGlobalCachedProxyListTimestamp = currentTime;
      } else if (workerGlobalCachedProxyList.length === 0) {
        workerGlobalCachedProxyListTimestamp = currentTime;
      }
      return workerGlobalCachedProxyList;
    } else {
      console.error(`fetchAndCacheMainProxyList: Failed to fetch proxy list from ${url}. Status: ${response.status}`);
      return workerGlobalCachedProxyList.length > 0 ? workerGlobalCachedProxyList : [];
    }
  } catch (error) {
    console.error(`fetchAndCacheMainProxyList: Error fetching proxy list from ${url}. Error: ${error.message}`);
    return workerGlobalCachedProxyList.length > 0 ? workerGlobalCachedProxyList : [];
  }
}


// --- SECTION 13: HtmlDocumentBuilder Class ---
class HtmlDocumentBuilder {
  constructor(request, env) {
    this.request = request;
    this.env = env;
    this.pageTitle = "";
    this.infoElements = [];
    this.proxyCardHtmlElements = [];
    this.paginationButtonHtmlElements = [];
    this.countryFlagHtmlElements = [];

    this.appDomain = `${this.env.SERVICE_NAME || 'worker'}.${this.env.ROOT_DOMAIN || 'example.com'}`;
    this.isCfApiConfigured = !!(env.CF_API_KEY && env.CF_API_EMAIL && env.CF_ACCOUNT_ID && env.CF_ZONE_ID);
  }

  setTitle(titleHtml) {
    this.pageTitle = titleHtml;
  }

  addInfo(infoText) {
    const sanitizedText = infoText.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    this.infoElements.push(`<span>${sanitizedText}</span>`);
  }

  registerProxyCard(proxyData, generatedConfigs) {
    const { proxyIP, proxyPort, country, org } = proxyData;
    const configTypeNames = [
      `${PROTOCOLS.URI_SCHEMES.TROJAN.toUpperCase()} TLS`,
      `${PROTOCOLS.URI_SCHEMES.VLESS.toUpperCase()} TLS`,
      `${PROTOCOLS.URI_SCHEMES.SHADOWSOCKS.toUpperCase()} TLS`,
      `${PROTOCOLS.URI_SCHEMES.TROJAN.toUpperCase()} NTLS`,
      `${PROTOCOLS.URI_SCHEMES.VLESS.toUpperCase()} NTLS`,
      `${PROTOCOLS.URI_SCHEMES.SHADOWSOCKS.toUpperCase()} NTLS`,
    ];

    let cardHtml = `
      <div class="proxy-card lozad scale-95 mb-2 bg-white dark:bg-neutral-800 transition-transform duration-200 rounded-lg p-4 w-60 border-2 border-neutral-800 dark:border-neutral-700 relative">
        <div class="country-flag absolute -top-4 -left-2 border-2 border-neutral-800 dark:border-neutral-700 rounded-full overflow-hidden bg-white">
          <img width="32" height="32" src="https://hatscripts.github.io/circle-flags/flags/${country.toLowerCase()}.svg" alt="${country} flag" />
        </div>
        <div class="proxy-ping text-xs font-semibold dark:text-white mb-1 animate-pulse" data-proxy-target="${proxyIP}:${proxyPort}">
          Pinging ${proxyIP}:${proxyPort}...
        </div>
        <div class="rounded py-1 px-2 bg-amber-400 dark:bg-neutral-700 dark:border-amber-500">
          <h5 class="font-bold text-md text-neutral-900 dark:text-white mb-1 overflow-x-auto scrollbar-hide text-nowrap proxy-org">${org}</h5>
          <div class="text-neutral-900 dark:text-white text-sm">
            <p>IP: ${proxyIP}</p>
            <p>Port: ${proxyPort}</p>
            <div class="region-check-container" data-config-sample="${generatedConfigs[0] || ''}"></div>
          </div>
        </div>
        <div class="flex flex-col gap-2 mt-3 text-sm">`;

    for (let i = 0; i < generatedConfigs.length; i += 2) {
      cardHtml += `<div class="flex gap-2 justify-around w-full">`;
      if (generatedConfigs[i]) {
        cardHtml += `<button class="config-button bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 dark:border-blue-500 rounded p-1 w-full text-white" onclick="handleConfigCopy('${generatedConfigs[i]}')">${configTypeNames[i] || 'Config '+(i+1)}</button>`;
      }
      if (generatedConfigs[i + 1]) {
        cardHtml += `<button class="config-button bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 dark:border-blue-500 rounded p-1 w-full text-white" onclick="handleConfigCopy('${generatedConfigs[i+1]}')">${configTypeNames[i+1] || 'Config '+(i+2)}</button>`;
      }
      cardHtml += `</div>`;
    }
    cardHtml += `
        </div>
      </div>`;
    this.proxyCardHtmlElements.push(cardHtml);
  }

  addPageButton(text, link, isDisabled) {
    const disabledAttrs = isDisabled ? 'disabled aria-disabled="true"' : '';
    const buttonClass = isDisabled
      ? "px-3 py-1 bg-neutral-300 dark:bg-neutral-700 border-2 border-neutral-400 dark:border-neutral-600 rounded text-neutral-500 dark:text-neutral-400 cursor-not-allowed"
      : "px-3 py-1 bg-amber-400 hover:bg-amber-500 dark:bg-amber-500 dark:hover:bg-amber-600 border-2 border-neutral-800 dark:border-neutral-700 rounded text-neutral-900 dark:text-white";
    this.paginationButtonHtmlElements.push(
      `<li><button class="${buttonClass}" onclick="navigateToPage('${link}')" ${disabledAttrs}>${text}</button></li>`
    );
  }

  buildCountryFlagSidebar() {
    const uniqueCountryCodes = [...new Set(workerGlobalCachedProxyList.map(p => p.country.toUpperCase()))].sort();
    const proxyBankUrlQuery = new URL(this.request.url).searchParams.get("proxy-list");
    uniqueCountryCodes.forEach(code => {
      let countryLink = `/sub/0?cc=${code}`;
      if (proxyBankUrlQuery) {
        countryLink += `&proxy-list=${encodeURIComponent(proxyBankUrlQuery)}`;
      }
      this.countryFlagHtmlElements.push(
        `<a href="${countryLink}" title="${code}" class="py-1 block hover:opacity-75 transition-opacity">
           <img width="24" height="24" src="https://hatscripts.github.io/circle-flags/flags/${code.toLowerCase()}.svg" alt="${code} flag" />
         </a>`
      );
    });
  }

  build() {
    this.buildCountryFlagSidebar();
    let html = HtmlDocumentBuilder.getBaseHtmlTemplate(this.env, this.isCfApiConfigured, this.appDomain);
    html = html.replace("<!-- PLACEHOLDER_TITLE -->", this.pageTitle);
    html = html.replace("<!-- PLACEHOLDER_INFO_ELEMENTS -->", this.infoElements.join("\n"));
    html = html.replace("<!-- PLACEHOLDER_PROXY_CARDS -->", this.proxyCardHtmlElements.join("\n"));
    html = html.replace("<!-- PLACEHOLDER_PAGINATION_BUTTONS -->", this.paginationButtonHtmlElements.join("\n"));
    html = html.replace("<!-- PLACEHOLDER_COUNTRY_FLAGS_SIDEBAR -->", this.countryFlagHtmlElements.join("\n"));
    html = html.replace(/<!--\s*PLACEHOLDER_\w+\s*-->/g, "");
    return html;
  }

  static getBaseHtmlTemplate(env, isCfApiConfigured, appDomain) {
    const donateLink = env.DONATE_LINK_OVERRIDE || DEFAULT_EXTERNAL_URLS.DONATE_LINK;
    const converterApiUrl = env.CONVERTER_URL_OVERRIDE || DEFAULT_EXTERNAL_URLS.CONFIG_CONVERTER_API;
    const serviceName = env.SERVICE_NAME || "Nautica";
    return `
<!DOCTYPE html>
<html lang="en" id="htmlEl" class="scroll-smooth dark">
<head>
    <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${serviceName} Proxy List</title>
    <script src="https://cdn.tailwindcss.com?plugins=forms"></script>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🚀</text></svg>">
    <style>
        .scrollbar-hide::-webkit-scrollbar { display: none; } .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
        .proxy-card { animation: fadeIn 0.5s ease-out; } @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .tooltip { position: relative; display: inline-block; }
        .tooltip .tooltiptext { visibility: hidden; width: 140px; background-color: #555; color: #fff; text-align: center; border-radius: 6px; padding: 5px 0; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -70px; opacity: 0; transition: opacity 0.3s; }
        .tooltip:hover .tooltiptext { visibility: visible; opacity: 1; }
        .toast { visibility: hidden; min-width: 250px; margin-left: -125px; background-color: #333; color: #fff; text-align: center; border-radius: 2px; padding: 16px; position: fixed; z-index: 100; left: 50%; bottom: 30px; font-size: 17px; opacity: 0; transition: visibility 0s 2s, opacity 0.5s linear; }
        .toast.show { visibility: visible; opacity: 1; transition: opacity 0.5s linear; }
        .modal-button { padding: 0.75rem 1rem; background-color: #3b82f6; color: white; border-radius: 0.375rem; text-align: center; font-weight: 500; transition: background-color 0.2s; }
        .modal-button:hover { background-color: #2563eb; }
        .modal-close-button { padding: 0.75rem 1rem; background-color: #6b7280; color: white; border-radius: 0.375rem; text-align: center; font-weight: 500; transition: background-color 0.2s; }
        .modal-close-button:hover { background-color: #4b5563; }
        .fab-button { display: flex; align-items: center; justify-content: center; width: 3.5rem; height: 3.5rem; border-radius: 9999px; color: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: background-color 0.2s; }
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script> tailwind.config = { darkMode: 'class' }; </script>
</head>
<body class="bg-neutral-100 dark:bg-neutral-900 text-neutral-900 dark:text-neutral-100 font-sans leading-relaxed अंतlass antialiased">
    <div id="toastNotification" class="toast">Copied to clipboard!</div>
    <aside class="fixed top-0 left-0 h-full w-16 bg-white dark:bg-neutral-800 border-r border-neutral-300 dark:border-neutral-700 z-30 overflow-y-auto scrollbar-hide flex flex-col items-center py-4 space-y-2 shadow-lg">
        <a href="/sub/0" title="All Proxies" class="py-1 block hover:opacity-75 transition-opacity">🌍</a>
        <!-- PLACEHOLDER_COUNTRY_FLAGS_SIDEBAR -->
    </aside>
    <main class="ml-16 p-4 md:p-6 lg:p-8">
        <header id="pageHeader" class="sticky top-0 bg-neutral-100/80 dark:bg-neutral-900/80 backdrop-blur-md z-20 py-4 mb-6 border-b border-neutral-300 dark:border-neutral-700">
            <div class="max-w-6xl mx-auto px-4">
                <div id="userInfo" class="text-xs text-neutral-600 dark:text-neutral-400 text-right mb-2">
                    <span id="userInfoIP">IP: Loading...</span> | <span id="userInfoCountry">Country: Loading...</span> | <span id="userInfoISP">ISP: Loading...</span>
                </div>
                <h1 id="pageTitle" class="text-2xl md:text-3xl font-bold text-center text-blue-600 dark:text-blue-400"><!-- PLACEHOLDER_TITLE --></h1>
                <div id="pageInfo" class="text-sm text-center text-neutral-700 dark:text-neutral-300 mt-1"><!-- PLACEHOLDER_INFO_ELEMENTS --></div>
            </div>
        </header>
        <div id="proxyGridContainer" class="max-w-6xl mx-auto px-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6"><!-- PLACEHOLDER_PROXY_CARDS --></div>
        <nav id="paginationContainer" class="max-w-6xl mx-auto px-4 mt-10 mb-6 py-4 flex justify-center"><ul class="flex items-center justify-center space-x-2 md:space-x-4"><!-- PLACEHOLDER_PAGINATION_BUTTONS --></ul></nav>
    </main>
    <div id="modalOverlay" class="fixed inset-0 bg-black/50 z-40 hidden items-center justify-center" onclick="closeAllModals(event)">
        <div id="outputFormatModal" class="modal-content bg-white dark:bg-neutral-800 p-6 rounded-lg shadow-xl w-full max-w-md hidden" onclick="event.stopPropagation()">
            <h3 class="text-xl font-semibold mb-4 text-center">Select Output Format</h3>
            <div class="grid grid-cols-2 gap-3 mb-4">
                <button onclick="copyToClipboardAsFormat('clash')" class="modal-button">Clash</button> <button onclick="copyToClipboardAsFormat('sfa')" class="modal-button">SFA</button>
                <button onclick="copyToClipboardAsFormat('bfr')" class="modal-button">BFR</button> <button onclick="copyToClipboardAsFormat('v2ray')" class="modal-button">V2Ray/Xray (Base64)</button>
                <button onclick="copyRawConfigToClipboard()" class="modal-button col-span-2">Raw Text</button>
            </div>
            <button onclick="toggleModal('outputFormatModal', false)" class="modal-close-button w-full">Close</button>
        </div>
        <div id="wildcardDomainsModal" class="modal-content bg-white dark:bg-neutral-800 p-6 rounded-lg shadow-xl w-full max-w-lg hidden" onclick="event.stopPropagation()">
            <h3 class="text-xl font-semibold mb-4">Manage Custom Domains</h3>
            <div class="mb-4">
                <label for="newDomainInput" class="block text-sm font-medium mb-1">Add New Subdomain (e.g., myproxy):</label>
                <div class="flex gap-2">
                    <input id="newDomainInput" type="text" placeholder="your-subdomain" class="flex-grow p-2 border border-neutral-300 dark:border-neutral-600 rounded-md focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-neutral-700">
                    <span class="self-center text-neutral-500 dark:text-neutral-400">.${appDomain}</span>
                    <button onclick="handleRegisterDomain()" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-md">Add</button>
                </div>
            </div>
            <h4 class="text-md font-semibold mt-6 mb-2">Registered Custom Domains:</h4>
            <div id="registeredDomainsContainer" class="h-40 overflow-y-auto border border-neutral-300 dark:border-neutral-600 rounded-md p-3 bg-neutral-50 dark:bg-neutral-700/50 space-y-1"><p class="text-sm text-neutral-500">Loading domains...</p></div>
            <button onclick="toggleModal('wildcardDomainsModal', false)" class="modal-close-button w-full mt-6">Close</button>
        </div>
    </div>
    <div class="fixed bottom-5 right-5 flex flex-col space-y-3 z-50">
        <a href="${donateLink}" target="_blank" rel="noopener noreferrer" class="fab-button bg-green-500 hover:bg-green-600" title="Donate"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6"><path d="M10.464 8.746c.227-.18.497-.311.786-.394v2.795a2.252 2.252 0 0 1-.786-.393c-.394-.313-.546-.681-.546-1.004 0-.323.152-.691.546-1.004ZM12.75 15.662v-2.824c.347.085.664.228.921.421.427.32.579.686.579.991 0 .305-.152.671-.579.991a2.534 2.534 0 0 1-.921.42Z" /><path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25ZM12.75 6a.75.75 0 0 0-1.5 0v.816a3.836 3.836 0 0 0-1.72.756c-.712.566-1.112 1.35-1.112 2.178 0 .829.4 1.612 1.113 2.178.502.4 1.102.647 1.719.756v2.978a2.536 2.536 0 0 1-.921-.421l-.879-.66a.75.75 0 0 0-.9 1.2l.879.66c.533.4 1.169.645 1.821.75V18a.75.75 0 0 0 1.5 0v-.81a4.124 4.124 0 0 0 1.821-.749c.745-.559 1.179-1.344 1.179-2.191 0-.847-.434-1.632-1.179-2.191a4.122 4.122 0 0 0-1.821-.75V8.354c.29.082.559.213.786.393l.415.33a.75.75 0 0 0 .933-1.175l-.415-.33a3.836 3.836 0 0 0-1.719-.755V6Z" clip-rule="evenodd" /></svg></a>
        ${isCfApiConfigured ? `<button onclick="openWildcardModal()" class="fab-button bg-indigo-500 hover:bg-indigo-600" title="Manage Custom Domains"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg></button>` : ''}
        <button onclick="toggleClientDarkMode()" class="fab-button bg-amber-500 hover:bg-amber-600" title="Toggle Dark Mode"><svg id="darkModeIcon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" /> <path id="sunIcon" stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" style="display:none;"/></svg></button>
    </div>
    ${HtmlDocumentBuilder.getInlineClientScript(appDomain, converterApiUrl, serviceName)}
</body></html>`;
  }

  static getInlineClientScript(appDomain, converterApiUrl, serviceName) {
    return `<script type="module">
// --- START OF CLIENT-SIDE SCRIPT ---
const APP_DOMAIN = "${appDomain}";
const CONVERTER_API_URL = "${converterApiUrl}";
const SERVICE_NAME = "${serviceName}";

const htmlEl = document.getElementById("htmlEl");
const toastEl = document.getElementById("toastNotification");
const userInfoIPEl = document.getElementById("userInfoIP");
const userInfoCountryEl = document.getElementById("userInfoCountry");
const userInfoISPEl = document.getElementById("userInfoISP");
const modalOverlayEl = document.getElementById("modalOverlay");
const outputFormatModalEl = document.getElementById("outputFormatModal");
const wildcardDomainsModalEl = document.getElementById("wildcardDomainsModal");
const newDomainInputEl = document.getElementById("newDomainInput");
const registeredDomainsContainerEl = document.getElementById("registeredDomainsContainer");
const darkModeIcon = document.getElementById("darkModeIcon")?.querySelector("path:first-child"); // Moon
const sunIcon = document.getElementById("darkModeIcon")?.querySelector("#sunIcon"); // Sun


let currentRawConfigToCopy = "";
let isDomainListFetched = false;
let activeModalId = null;

function showToast(message, duration = 2000) {
  if (!toastEl) return;
  toastEl.textContent = message;
  toastEl.classList.add("show");
  setTimeout(() => { toastEl.classList.remove("show"); }, duration);
}

function applyDarkModePreference() {
  const isDarkMode = localStorage.getItem("darkMode") === "true";
  htmlEl.classList.toggle("dark", isDarkMode);
  if (darkModeIcon && sunIcon) {
    darkModeIcon.style.display = isDarkMode ? "none" : "block";
    sunIcon.style.display = isDarkMode ? "block" : "none";
  }
}

window.toggleClientDarkMode = function () {
  const isCurrentlyDark = htmlEl.classList.contains("dark");
  localStorage.setItem("darkMode", !isCurrentlyDark);
  applyDarkModePreference();
  showToast(!isCurrentlyDark ? "Dark mode enabled" : "Light mode enabled");
};

window.toggleModal = function(modalId, show) {
  if (!modalOverlayEl) return;
  const modalEl = document.getElementById(modalId);
  if (!modalEl) return;
  if (show) {
    activeModalId = modalId;
    modalOverlayEl.classList.remove("hidden"); modalOverlayEl.classList.add("flex");
    modalEl.classList.remove("hidden");
  } else {
    activeModalId = null;
    modalEl.classList.add("hidden");
    modalOverlayEl.classList.add("hidden"); modalOverlayEl.classList.remove("flex");
  }
}

window.closeAllModals = function(event) {
  if (event.target === modalOverlayEl && activeModalId) {
    toggleModal(activeModalId, false);
  }
}

window.navigateToPage = function (link) {
  const currentSearchParams = new URLSearchParams(window.location.search);
  const newUrl = new URL(link, window.location.origin);
  currentSearchParams.forEach((value, key) => {
    if (!newUrl.searchParams.has(key)) newUrl.searchParams.set(key, value);
  });
  const linkUrl = new URL(link, window.location.origin); // Check original link for 'cc'
  if(linkUrl.searchParams.has('cc') && !newUrl.searchParams.has('cc')) {
    newUrl.searchParams.set('cc', linkUrl.searchParams.get('cc'));
  }
  if (newUrl.pathname === window.location.pathname && newUrl.search === window.location.search) return; // Avoid reload same page
  window.location.href = newUrl.toString();
};

window.handleConfigCopy = function (configString) {
  currentRawConfigToCopy = configString;
  toggleModal('outputFormatModal', true);
};

window.copyRawConfigToClipboard = async function () {
  if (!currentRawConfigToCopy) return;
  try {
    await navigator.clipboard.writeText(currentRawConfigToCopy);
    showToast("Raw config copied!");
    toggleModal('outputFormatModal', false);
  } catch (err) {
    console.error("Failed to copy raw config: ", err); showToast("Failed to copy. See console.", 3000);
  }
};

window.copyToClipboardAsFormat = async function (format) {
  if (!currentRawConfigToCopy || !CONVERTER_API_URL) {
    showToast("Converter API not configured or no config selected.", 3000); return;
  }
  showToast(\`Converting to \${format}...\`, 5000);
  try {
    const response = await fetch(CONVERTER_API_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentRawConfigToCopy, format: format, template: "cf" }),
    });
    if (!response.ok) { const errorText = await response.text(); throw new Error(\`Converter API error (\${response.status}): \${errorText}\`); }
    const formattedConfig = await response.text();
    await navigator.clipboard.writeText(formattedConfig);
    showToast(\`\${format.toUpperCase()} config copied!\`);
    toggleModal('outputFormatModal', false);
  } catch (err) {
    console.error(\`Failed to copy as \${format}: \`, err); showToast(\`Failed to convert/copy. \${err.message.substring(0,100)}\`, 4000);
  }
};

async function fetchRegisteredDomains() {
  if (!registeredDomainsContainerEl) return;
  registeredDomainsContainerEl.innerHTML = '<p class="text-sm text-neutral-500">Fetching domains...</p>';
  isDomainListFetched = true;
  try {
    const response = await fetch(\`https://\${APP_DOMAIN}/api/v1/domains/get\`);
    if (!response.ok) throw new Error(\`API error \${response.status}\`);
    const result = await response.json();
    if (result.success && Array.isArray(result.data)) {
      if (result.data.length === 0) {
        registeredDomainsContainerEl.innerHTML = '<p class="text-sm text-neutral-500">No custom domains registered yet.</p>';
      } else {
        registeredDomainsContainerEl.innerHTML = result.data.map(domain =>
          \`<div class="p-2 bg-neutral-200 dark:bg-neutral-600 rounded-md text-sm">\${domain}</div>\`
        ).join('');
      }
    } else { throw new Error(result.error || "Failed to parse domain list."); }
  } catch (err) {
    console.error("Failed to fetch domains: ", err);
    registeredDomainsContainerEl.innerHTML = \`<p class="text-sm text-red-500">Error: \${err.message}</p>\`;
  }
}

window.openWildcardModal = function() {
  toggleModal('wildcardDomainsModal', true);
  if (!isDomainListFetched) { fetchRegisteredDomains(); }
}

window.handleRegisterDomain = async function () {
  if (!newDomainInputEl) return;
  const subDomain = newDomainInputEl.value.trim().toLowerCase();
  if (!subDomain) { showToast("Please enter a subdomain.", 3000); return; }
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subDomain)) {
    showToast("Invalid subdomain format (alphanumeric, hyphens, 1-63 chars).", 4000); return;
  }
  const fullDomain = \`\${subDomain}.\${APP_DOMAIN}\`; // Use appDomain from server
  showToast(\`Registering \${fullDomain}...\`, 5000);
  try {
    const response = await fetch(\`https://\${APP_DOMAIN}/api/v1/domains/put?domain=\${encodeURIComponent(fullDomain)}\`);
    const result = await response.json();
    if (result.success) {
      showToast(result.message || \`Domain \${fullDomain} action successful!\`);
      newDomainInputEl.value = ""; fetchRegisteredDomains();
    } else { throw new Error(result.message || \`Failed to register domain (status \${response.status})\`); }
  } catch (err) {
    console.error("Failed to register domain: ", err); showToast(\`Error: \${err.message.substring(0,100)}\`, 4000);
  }
};

async function checkAllProxyPings() {
  const pingElements = document.querySelectorAll(".proxy-ping[data-proxy-target]");
  pingElements.forEach(async (el) => {
    const target = el.dataset.proxyTarget;
    if (!target) { el.textContent = "Invalid target"; el.classList.remove("animate-pulse"); return; }
    try {
      const response = await fetch(\`https://\${APP_DOMAIN}/check?target=\${encodeURIComponent(target)}\`);
      if (!response.ok) { el.textContent = \`Check failed (HTTP \${response.status})\`; el.classList.add("text-red-500"); return; }
      const result = await response.json();
      if (result.proxyip === true) {
        el.textContent = \`Active (\${result.delay}ms @ \${result.colo || 'N/A'})\`; el.classList.add("text-green-500");
      } else { el.textContent = "Inactive"; el.classList.add("text-red-500"); }
    } catch (err) {
      console.warn(\`Ping check failed for \${target}:\`, err); el.textContent = "Ping Error"; el.classList.add("text-orange-500");
    } finally { el.classList.remove("animate-pulse"); }
  });
}

async function fetchGeoIpInfo() {
  if (!userInfoIPEl) return;
  try {
    const response = await fetch(\`https://\${APP_DOMAIN}/api/v1/myip\`);
    if (!response.ok) throw new Error(\`API error \${response.status}\`);
    const data = await response.json();
    userInfoIPEl.textContent = \`IP: \${data.ip || 'Unknown'}\`;
    userInfoCountryEl.textContent = \`Country: \${data.country || 'Unknown'}\`;
    userInfoISPEl.textContent = \`ISP: \${data.asOrganization || 'Unknown'}\`;
  } catch (err) { console.error("Failed to fetch GeoIP info:", err); userInfoIPEl.textContent = "IP: Error"; }
}

function initPage() {
  applyDarkModePreference(); fetchGeoIpInfo(); checkAllProxyPings();
  const observer = lozad(".lozad", { loaded: function(el) { el.classList.add("is-loaded"); } });
  observer.observe();
  const paginationContainer = document.getElementById("paginationContainer");
  if (paginationContainer) {
    const togglePaginationVisibility = () => {
        const isAtBottom = window.innerHeight + Math.round(window.scrollY) >= document.body.offsetHeight - 100; // threshold
        paginationContainer.style.opacity = isAtBottom ? '1' : '0';
        paginationContainer.style.transform = isAtBottom ? 'translateY(0)' : 'translateY(1.5rem)'; // -translate-y-6 is 1.5rem
    };
    window.addEventListener("scroll", togglePaginationVisibility, { passive: true });
    togglePaginationVisibility(); // Initial check
  }
}
if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", initPage); } else { initPage(); }
// --- END OF CLIENT-SIDE SCRIPT ---
</script>`;
  }
}


// --- SECTION 4: generateSubscriptionPageHTML Function ---
function generateSubscriptionPageHTML(request, currentHostname, fullProxyList, currentPageIndex, env) {
  const itemsPerPage = APP_CONFIG.PROXIES_PER_PAGE;
  const totalProxies = fullProxyList.length;
  const totalPages = Math.max(0, Math.ceil(totalProxies / itemsPerPage) -1) ;
  const validCurrentPageIndex = Math.max(0, Math.min(currentPageIndex, totalPages));
  const paginatedProxies = fullProxyList.slice(validCurrentPageIndex * itemsPerPage, (validCurrentPageIndex + 1) * itemsPerPage);

  try {
    const newUuid = crypto.randomUUID();
    const baseUri = new URL(`http://${currentHostname}`);
    baseUri.searchParams.set("encryption", "none");
    baseUri.searchParams.set("type", "ws");
    baseUri.searchParams.set("host", currentHostname);

    const docBuilder = new HtmlDocumentBuilder(request, env);
    const serviceDisplayName = env.SERVICE_NAME ? env.SERVICE_NAME.charAt(0).toUpperCase() + env.SERVICE_NAME.slice(1) : "Nautica";
    docBuilder.setTitle(`Welcome to <span class='text-blue-500 font-semibold'>${serviceDisplayName}</span> Proxies`);
    docBuilder.addInfo(`Total Proxies: ${totalProxies}`);
    docBuilder.addInfo(`Page: ${validCurrentPageIndex + 1} / ${totalPages + 1}`);

    for (let i = 0; i < paginatedProxies.length; i++) {
      const proxyData = paginatedProxies[i];
      if (!proxyData) continue;
      const { proxyIP, proxyPort, country, org } = proxyData;
      const uniquePath = `/${proxyIP}-${proxyPort}`;
      baseUri.searchParams.set("path", uniquePath);
      const generatedConfigsForThisProxy = [];

      for (const port of APP_CONFIG.DEFAULT_PORTS) {
        baseUri.port = port.toString();
        const isTlsPort = (port === 443);
        const portTypeRemark = isTlsPort ? "TLS" : "NTLS";
        const remark = `${(validCurrentPageIndex * itemsPerPage) + i + 1} ${getFlagEmoji(country)} ${org} WS ${portTypeRemark} [${env.SERVICE_NAME || 'Nautica'}]`;
        baseUri.hash = encodeURIComponent(remark);

        for (const protocolScheme of ORDERED_PROTOCOLS_FOR_SUBSCRIPTION) {
          baseUri.protocol = `${protocolScheme}:`;
          if (protocolScheme === PROTOCOLS.URI_SCHEMES.SHADOWSOCKS) {
            baseUri.username = btoa(`none:${newUuid}`);
            const pluginParts = ["v2ray-plugin", isTlsPort ? "tls" : "", "mux=0", "mode=websocket", `path=${uniquePath}`, `host=${currentHostname}`];
            baseUri.searchParams.set("plugin", pluginParts.filter(Boolean).join(";"));
          } else {
            baseUri.username = newUuid;
            baseUri.searchParams.delete("plugin");
          }
          baseUri.searchParams.set("security", isTlsPort ? "tls" : "none");
          const requiresSni = !(port === 80 && protocolScheme === PROTOCOLS.URI_SCHEMES.VLESS);
          baseUri.searchParams.set("sni", requiresSni ? currentHostname : "");
          generatedConfigsForThisProxy.push(baseUri.toString());
        }
      }
      docBuilder.registerProxyCard(proxyData, generatedConfigsForThisProxy);
    }

    docBuilder.addPageButton("Prev", `/sub/${validCurrentPageIndex > 0 ? validCurrentPageIndex - 1 : 0}`, validCurrentPageIndex <= 0);
    docBuilder.addPageButton("Next", `/sub/${validCurrentPageIndex < totalPages ? validCurrentPageIndex + 1 : totalPages}`, validCurrentPageIndex >= totalPages);
    return docBuilder.build();
  } catch (error) {
    console.error(`generateSubscriptionPageHTML: Error generating HTML. URI: ${request.url}, Error: ${error.message}`, error.stack);
    const errorProtocolName = PROTOCOLS.SNIFFER_RESULTS.VLESS || "VLESS";
    return `An error occurred while generating the ${errorProtocolName} configurations. Details: ${error.message}`;
  }
}

// --- SECTION 10: Helper Functions (checkProxyHealth) ---
async function checkProxyHealth(targetProxyIp, targetProxyPort, env) {
  const healthCheckApiUrl = env.PROXY_HEALTH_CHECK_API_OVERRIDE || DEFAULT_EXTERNAL_URLS.PROXY_HEALTH_CHECK_API;
  if (!healthCheckApiUrl) {
    console.error("checkProxyHealth: PROXY_HEALTH_CHECK_API URL is not configured.");
    return { error: true, message: "Health check API URL not configured.", proxyip: false, delay: -1, colo: "N/A" };
  }
  const target = `${targetProxyIp}:${targetProxyPort}`;
  const url = `${healthCheckApiUrl}?ip=${encodeURIComponent(target)}`;
  try {
    const response = await fetch(url, { method: 'GET', headers: { 'User-Agent': `CloudflareWorker/${env.SERVICE_NAME || 'NauticaProxy'}-HealthCheck` }});
    if (response.ok) { return await response.json(); }
    else {
      const errorText = await response.text().catch(() => "Could not read error response body.");
      console.error(`checkProxyHealth: API request to ${url} failed with status ${response.status}: ${response.statusText}`);
      return { error: true, message: `Health check API request failed: ${response.status}. ${errorText.substring(0,100)}`, proxyip: false, delay: -1, colo: "Error" };
    }
  } catch (error) {
    console.error(`checkProxyHealth: Error fetching proxy health from ${url}: ${error.message}`, error);
    return { error: true, message: `Exception during health check: ${error.message}`, proxyip: false, delay: -1, colo: "Exception" };
  }
}


// --- SECTION 12: CloudflareApiClient Class ---
class CloudflareApiClient {
  constructor(env) {
    this.env = env;
    if (!env.CF_API_KEY || !env.CF_API_EMAIL || !env.CF_ACCOUNT_ID || !env.CF_ZONE_ID || !env.ROOT_DOMAIN || !env.SERVICE_NAME) {
      console.error("CloudflareApiClient: Missing one or more required environment configurations.");
    }
    this.baseHeaders = {
      "X-Auth-Email": this.env.CF_API_EMAIL, "X-Auth-Key": this.env.CF_API_KEY,
      "Content-Type": "application/json", "User-Agent": `CloudflareWorker/${this.env.SERVICE_NAME || 'NauticaProxy'}-ApiClient`
    };
  }

  async _request(method, path, body = null) {
    if (!this.env.CF_API_KEY || !this.env.CF_API_EMAIL) {
        return { success: false, data: null, error: "API credentials not configured.", status: 503 };
    }
    const apiUrl = `https://api.cloudflare.com/client/v4${path}`;
    const options = { method: method, headers: { ...this.baseHeaders } };
    if (body) { options.body = JSON.stringify(body); }
    try {
      const response = await fetch(apiUrl, options);
      let responseData = (response.headers.get("content-type") || "").includes("application/json") ? await response.json() : await response.text();
      if (!response.ok) {
        const errorMessage = responseData?.errors?.[0]?.message || responseData?.message || (typeof responseData === 'string' ? responseData : `API Error ${response.status}`);
        console.error(`Cloudflare API Error (${method} ${path}): ${response.status} - ${errorMessage}`, responseData);
        return { success: false, data: responseData, error: errorMessage, status: response.status };
      }
      return { success: true, data: responseData, error: null, status: response.status };
    } catch (error) {
      console.error(`Cloudflare API Request Exception (${method} ${path}): ${error.message}`, error);
      return { success: false, data: null, error: `Network error: ${error.message}`, status: 500 };
    }
  }

  async getDomainList() {
    if (!this.env.CF_ACCOUNT_ID || !this.env.SERVICE_NAME) {
        return { success: false, data: null, error: "Account ID or Service Name not configured.", status: 503 };
    }
    const path = `/accounts/${this.env.CF_ACCOUNT_ID}/workers/domains`;
    const result = await this._request("GET", path);
    if (result.success && result.data?.result) {
      const filteredHostnames = result.data.result
        .filter(d => d.service === this.env.SERVICE_NAME).map(d => d.hostname);
      return { ...result, data: filteredHostnames };
    } else if (result.success) {
      return { ...result, success: false, error: "Unexpected data from getDomainList API." };
    }
    return result;
  }

  async registerDomain(domain) {
    if (!this.env.CF_ACCOUNT_ID || !this.env.CF_ZONE_ID || !this.env.ROOT_DOMAIN || !this.env.SERVICE_NAME) {
        return { success: false, message: "Required configurations missing for domain registration.", status: 503 };
    }
    const normalizedDomain = domain.trim().toLowerCase();
    const appDomainForCheck = `${this.env.SERVICE_NAME}.${this.env.ROOT_DOMAIN}`;
    if (!normalizedDomain.endsWith(`.${this.env.ROOT_DOMAIN}`)) {
      return { success: false, message: `Domain must end with '.${this.env.ROOT_DOMAIN}'.`, status: 400 };
    }
    if (normalizedDomain === this.env.ROOT_DOMAIN || normalizedDomain === appDomainForCheck) {
        return { success: false, message: "Cannot register root or default service domain.", status: 400 };
    }
    const { data: registeredDomains, success: fetchSuccess } = await this.getDomainList();
    if (!fetchSuccess || !registeredDomains) {
      return { success: false, message: "Failed to fetch existing domain list.", status: 500 };
    }
    if (registeredDomains.includes(normalizedDomain)) {
      return { success: false, message: "Domain already registered.", status: 409 };
    }
    const badWordsListUrl = this.env.BAD_WORDS_LIST_URL_OVERRIDE || DEFAULT_EXTERNAL_URLS.BAD_WORDS_LIST;
    try {
      const badWordsResponse = await fetch(badWordsListUrl, { headers: { 'User-Agent': this.baseHeaders['User-Agent'] } });
      if (badWordsResponse.ok) {
        const badWordsList = (await badWordsResponse.text()).split("\n").map(w => w.trim().toLowerCase()).filter(Boolean);
        if (badWordsList.some(bw => normalizedDomain.includes(bw))) {
          return { success: false, message: "Domain contains a prohibited word.", status: 403 };
        }
      } else { console.warn(`CloudflareApiClient: Bad words list fetch failed (status ${badWordsResponse.status}).`); }
    } catch (error) { console.warn(`CloudflareApiClient: Error fetching bad words list: ${error.message}.`); }

    const path = `/accounts/${this.env.CF_ACCOUNT_ID}/workers/domains`;
    const payload = { hostname: normalizedDomain, service: this.env.SERVICE_NAME, zone_id: this.env.CF_ZONE_ID, environment: "production" };
    const result = await this._request("PUT", path, payload);
    return { success: result.success, message: result.success ? `Domain '${normalizedDomain}' operation successful.` : (result.error || "Failed to register domain."), status: result.status };
  }
}


// --- SECTION 3: executeReverseProxy Function ---
async function executeReverseProxy(originalRequest, targetHostAndPort, targetPathname, env) {
  const newTargetUrl = new URL(originalRequest.url);
  let [hostname, port] = targetHostAndPort.split(":");
  newTargetUrl.hostname = hostname;
  newTargetUrl.port = port || (newTargetUrl.protocol === "https:" ? "443" : "80");
  if (targetPathname !== undefined) {
    newTargetUrl.pathname = (targetPathname && !targetPathname.startsWith('/')) ? `/${targetPathname}` : (targetPathname || '/');
  }
  const upstreamRequest = new Request(newTargetUrl.toString(), originalRequest);
  upstreamRequest.headers.set("X-Forwarded-Host", originalRequest.headers.get("Host"));
  upstreamRequest.headers.set("Host", newTargetUrl.hostname);
  upstreamRequest.headers.set("User-Agent", `CloudflareWorker-ReverseProxy/${env.SERVICE_NAME || 'NauticaProxy'}`);
  try {
    const upstreamResponse = await fetch(upstreamRequest);
    const downstreamResponse = new Response(upstreamResponse.body, upstreamResponse);
    for (const [key, value] of Object.entries(CORS_HEADERS)) {
      downstreamResponse.headers.set(key, value);
    }
    downstreamResponse.headers.set("X-Proxied-By", env.SERVICE_NAME || "Cloudflare-Worker-Nautica");
    return downstreamResponse;
  } catch (error) {
    console.error(`ReverseProxy: Error fetching from target ${newTargetUrl.toString()}: ${error.message}`, error);
    return new Response(`Reverse proxy failed: ${error.message}`, {
      status: 502, headers: { "Content-Type": "text/plain", ...(CORS_HEADERS || {}), "X-Proxied-By": env.SERVICE_NAME || "Cloudflare-Worker-Nautica" },
    });
  }
}


// --- SECTION 9: Protocol Header Parsers ---
function parseShadowsocksHeader(ssBuffer, env) {
  const buffer = new Uint8Array(ssBuffer);
  if (buffer.byteLength < 1) return { hasError: true, message: "SS buffer too short for ATYP." };
  const addressType = buffer[0];
  let addressLength = 0, addressStartIndex = 1, addressRemote = "";
  try {
    switch (addressType) {
      case 0x01: addressLength = 4; if (buffer.byteLength < addressStartIndex + addressLength) return { hasError: true, message: "SS buffer short for IPv4." }; addressRemote = new Uint8Array(buffer.slice(addressStartIndex, addressStartIndex + addressLength)).join("."); break;
      case 0x03: if (buffer.byteLength < addressStartIndex + 1) return { hasError: true, message: "SS buffer short for domain_len." }; addressLength = buffer[addressStartIndex]; addressStartIndex += 1; if (buffer.byteLength < addressStartIndex + addressLength) return { hasError: true, message: "SS buffer short for domain." }; addressRemote = new TextDecoder().decode(buffer.slice(addressStartIndex, addressStartIndex + addressLength)); break;
      case 0x04: addressLength = 16; if (buffer.byteLength < addressStartIndex + addressLength) return { hasError: true, message: "SS buffer short for IPv6." }; const ipv6Bytes = buffer.slice(addressStartIndex, addressStartIndex + addressLength); const ipv6Segments = []; for (let i = 0; i < 8; i++) ipv6Segments.push(new DataView(ipv6Bytes.buffer, ipv6Bytes.byteOffset + i * 2, 2).getUint16(0).toString(16)); addressRemote = ipv6Segments.join(":"); break;
      default: return { hasError: true, message: `Invalid SS ATYP: ${addressType}` };
    }
    if (!addressRemote) return { hasError: true, message: `SS dest addr empty for type ${addressType}.` };
    const portStartIndex = addressStartIndex + addressLength;
    if (buffer.byteLength < portStartIndex + 2) return { hasError: true, message: "SS buffer short for port." };
    const portRemote = new DataView(buffer.buffer, buffer.byteOffset + portStartIndex, 2).getUint16(0, false);
    const rawDataStartIndex = portStartIndex + 2;
    const rawClientData = buffer.slice(rawDataStartIndex);
    return { hasError: false, addressRemote, addressType, portRemote, rawDataIndex: rawDataStartIndex, rawClientData: rawClientData.buffer.slice(rawClientData.byteOffset, rawClientData.byteOffset + rawClientData.byteLength), version: null, isUDP: false };
  } catch (e) { return { hasError: true, message: `Error parsing SS header: ${e.message}` }; }
}

function parseSselvHeader(vlessBuffer, env) {
  const buffer = new Uint8Array(vlessBuffer);
  if (buffer.byteLength < 21) return { hasError: true, message: "VLESS buffer too short." };
  try {
    const version = buffer[0]; const addonsLength = buffer[17]; let currentIndex = 18 + addonsLength;
    if (buffer.byteLength < currentIndex + 1) return { hasError: true, message: "VLESS buffer short for cmd." };
    const command = buffer[currentIndex++]; let isUDP = false;
    if (command === 0x01) isUDP = false; else if (command === 0x02) isUDP = true; else return { hasError: true, message: `Unsupported VLESS cmd: ${command}.` };
    if (buffer.byteLength < currentIndex + 2) return { hasError: true, message: "VLESS buffer short for port." };
    const portRemote = new DataView(buffer.buffer, buffer.byteOffset + currentIndex, 2).getUint16(0, false); currentIndex += 2;
    if (buffer.byteLength < currentIndex + 1) return { hasError: true, message: "VLESS buffer short for ATYP." };
    const addressType = buffer[currentIndex++]; let addressLength = 0, addressRemote = "";
    switch (addressType) {
      case 0x01: addressLength = 4; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "VLESS buffer short for IPv4." }; addressRemote = new Uint8Array(buffer.slice(currentIndex, currentIndex + addressLength)).join("."); break;
      case 0x02: if (buffer.byteLength < currentIndex + 1) return { hasError: true, message: "VLESS buffer short for domain_len." }; addressLength = buffer[currentIndex++]; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "VLESS buffer short for domain." }; addressRemote = new TextDecoder().decode(buffer.slice(currentIndex, currentIndex + addressLength)); break;
      case 0x03: addressLength = 16; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "VLESS buffer short for IPv6." }; const ipv6Bytes = buffer.slice(currentIndex, currentIndex + addressLength); const ipv6Segments = []; for (let i = 0; i < 8; i++) ipv6Segments.push(new DataView(ipv6Bytes.buffer, ipv6Bytes.byteOffset + i * 2, 2).getUint16(0).toString(16)); addressRemote = ipv6Segments.join(":"); break;
      default: return { hasError: true, message: `Invalid VLESS ATYP: ${addressType}` };
    }
    if (!addressRemote) return { hasError: true, message: `VLESS dest addr empty for type ${addressType}.` };
    const rawDataStartIndex = currentIndex + addressLength; const rawClientData = buffer.slice(rawDataStartIndex);
    return { hasError: false, addressRemote, addressType, portRemote, rawDataIndex: rawDataStartIndex, rawClientData: rawClientData.buffer.slice(rawClientData.byteOffset, rawClientData.byteOffset + rawClientData.byteLength), version: new Uint8Array([version, 0x00]).buffer, isUDP };
  } catch (e) { return { hasError: true, message: `Error parsing VLESS header: ${e.message}` }; }
}

function parseNajortHeader(najortBuffer, env) {
  const buffer = new Uint8Array(najortBuffer);
  if (buffer.byteLength < 4) return { hasError: true, message: "Trojan/SOCKS5 buffer too short." };
  let currentIndex = 0;
  try {
    const command = buffer[currentIndex++]; let isUDP = false;
    if (command === 0x01) isUDP = false; else if (command === 0x03) isUDP = true; else return { hasError: true, message: `Unsupported Trojan/SOCKS5 cmd: ${command}.` };
    const addressType = buffer[currentIndex++]; let addressLength = 0, addressRemote = "";
    switch (addressType) {
      case 0x01: addressLength = 4; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "Trojan/SOCKS5 buffer short for IPv4." }; addressRemote = new Uint8Array(buffer.slice(currentIndex, currentIndex + addressLength)).join("."); break;
      case 0x03: if (buffer.byteLength < currentIndex + 1) return { hasError: true, message: "Trojan/SOCKS5 buffer short for domain_len." }; addressLength = buffer[currentIndex++]; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "Trojan/SOCKS5 buffer short for domain." }; addressRemote = new TextDecoder().decode(buffer.slice(currentIndex, currentIndex + addressLength)); break;
      case 0x04: addressLength = 16; if (buffer.byteLength < currentIndex + addressLength) return { hasError: true, message: "Trojan/SOCKS5 buffer short for IPv6." }; const ipv6Bytes = buffer.slice(currentIndex, currentIndex + addressLength); const ipv6Segments = []; for (let i = 0; i < 8; i++) ipv6Segments.push(new DataView(ipv6Bytes.buffer, ipv6Bytes.byteOffset + i * 2, 2).getUint16(0).toString(16)); addressRemote = ipv6Segments.join(":"); break;
      default: return { hasError: true, message: `Invalid Trojan/SOCKS5 ATYP: ${addressType}` };
    }
    if (!addressRemote) return { hasError: true, message: `Trojan/SOCKS5 dest addr empty for type ${addressType}.` };
    currentIndex += addressLength;
    if (buffer.byteLength < currentIndex + 2) return { hasError: true, message: "Trojan/SOCKS5 buffer short for port." };
    const portRemote = new DataView(buffer.buffer, buffer.byteOffset + currentIndex, 2).getUint16(0, false); currentIndex += 2;
    const rawDataStartIndex = currentIndex; const rawClientData = buffer.slice(rawDataStartIndex);
    return { hasError: false, addressRemote, addressType, portRemote, rawDataIndex: rawDataStartIndex, rawClientData: rawClientData.buffer.slice(rawClientData.byteOffset, rawClientData.byteOffset + rawClientData.byteLength), version: null, isUDP };
  } catch (e) { return { hasError: true, message: `Error parsing Trojan/SOCKS5 header: ${e.message}` }; }
}

function createReadableWebSocketStream(webSocketInstance, earlyDataHeaderValue, logger) {
  let isStreamCancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocketInstance.addEventListener("message", (event) => { if (isStreamCancelled) return; controller.enqueue(event.data); });
      webSocketInstance.addEventListener("close", (event) => { if (isStreamCancelled) return; logger('info', `WS client closed. Code: ${event.code}`); controller.close(); });
      webSocketInstance.addEventListener("error", (errorEvent) => { if (isStreamCancelled) return; logger('error', "WS error event.", errorEvent); controller.error(new Error("WebSocket error.")); });
      if (earlyDataHeaderValue) {
        const { earlyData, error: earlyDataError } = decodeBase64ToArrayBuffer(earlyDataHeaderValue);
        if (earlyDataError) { logger('error', "Early data decode error.", earlyDataError); controller.error(earlyDataError); }
        else if (earlyData && earlyData.byteLength > 0) { logger('info', `Early data ${earlyData.byteLength}b.`); controller.enqueue(earlyData); }
      }
    },
    pull(controller) {},
    cancel(reason) {
      if (isStreamCancelled) return; isStreamCancelled = true;
      logger('warn', `ReadableWSStream cancelled. Reason: ${reason.message || reason}`, reason);
      safeCloseWebSocket(webSocketInstance);
    },
  });
}

// --- SECTION 7: sniffConnectionProtocol Function ---
async function sniffConnectionProtocol(initialChunk, env) {
  const dataView = new Uint8Array(initialChunk);
  if (dataView.byteLength >= 17) {
    const vlessUuidBytes = dataView.slice(1, 17); const vlessUuidHex = arrayBufferToHexString(vlessUuidBytes.buffer);
    if (/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i.test(vlessUuidHex)) {
      return PROTOCOLS.SNIFFER_RESULTS.VLESS;
    }
  }
  if (dataView.byteLength >= 60) {
    const trojanDelimiter = dataView.slice(56, 60);
    if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
      const atyp = trojanDelimiter[2]; const cmd = trojanDelimiter[3];
      const isValidAtyp = atyp === 0x01 || atyp === 0x03 || atyp === 0x04 || atyp === 0x7f;
      if (isValidAtyp && (cmd === 0x01 || cmd === 0x03 || cmd === 0x04)) {
        return PROTOCOLS.SNIFFER_RESULTS.TROJAN;
      }
    }
  }
  return PROTOCOLS.SNIFFER_RESULTS.SHADOWSOCKS;
}


// --- SECTION 8: Outbound Data Handling Functions ---
async function pipeRemoteSocketToClientWS(remoteTcpSocket, clientWebSocket, clientResponseHeader, logger, onFailToReceiveDataCallback) {
  let hasReceivedDataFromRemote = false; let headerToSendToClient = clientResponseHeader;
  try {
    await remoteTcpSocket.readable.pipeTo( new WritableStream({
        async write(chunk) {
          if (clientWebSocket.readyState !== WEBSOCKET_STATE.OPEN) { logger('warn', "Client WS not open."); throw new Error("Client WS not open."); }
          hasReceivedDataFromRemote = true;
          if (headerToSendToClient) {
            logger('info', `Prepending ${headerToSendToClient.byteLength}b hdr to client.`);
            clientWebSocket.send(await new Blob([headerToSendToClient, chunk]).arrayBuffer());
            headerToSendToClient = null;
          } else { clientWebSocket.send(chunk); }
        },
        close() {
          logger('info', `Remote TCP stream closed. HasRcvdData: ${hasReceivedDataFromRemote}`);
          if (!hasReceivedDataFromRemote && onFailToReceiveDataCallback) {
            logger('info', "Remote closed w/o data. Invoking retry."); onFailToReceiveDataCallback();
          } else { safeCloseWebSocket(clientWebSocket); }
        },
        abort(reason) { logger('error', `Remote TCP stream aborted: ${reason.message||reason}`,reason); safeCloseWebSocket(clientWebSocket); },
      })
    );
  } catch (error) { logger('error', `Error piping remote->client: ${error.message}`, error.stack); safeCloseWebSocket(clientWebSocket); }
}

async function handleTcpOutbound(outboundSocketWrapper, primaryTargetAddress, primaryTargetPort, initialClientPayload, clientWebSocket, clientResponseHeader, logger, env, fallbackProxyIpString) {
  let hasSuccessfullyConnectedOnce = false;
  async function attemptConnection(targetAddress, targetPort, isRetry = false) {
    logger('info', `TCP conn to ${targetAddress}:${targetPort}` + (isRetry ? " (Retry)" : ""));
    try {
      const remoteTcpSocket = connect({ hostname: targetAddress, port: targetPort });
      outboundSocketWrapper.current = remoteTcpSocket;
      logger('info', `Connected to ${targetAddress}:${targetPort}.`); hasSuccessfullyConnectedOnce = true;
      const writer = remoteTcpSocket.writable.getWriter();
      if (initialClientPayload && initialClientPayload.byteLength > 0) {
        await writer.write(initialClientPayload);
        logger('info', `Sent initial ${initialClientPayload.byteLength}b to ${targetAddress}:${targetPort}.`);
      }
      initialClientPayload = null; writer.releaseLock();
      pipeRemoteSocketToClientWS(remoteTcpSocket, clientWebSocket, clientResponseHeader, logger, isRetry ? null : retryConnection);
      return true;
    } catch (error) {
      logger('error', `Fail connect/write to ${targetAddress}:${targetPort}: ${error.message}`, error);
      outboundSocketWrapper.current = null; return false;
    }
  }
  async function retryConnection() {
    if (!fallbackProxyIpString) { logger('warn', "No fallback proxy, cannot retry."); safeCloseWebSocket(clientWebSocket); return; }
    const parts = fallbackProxyIpString.split(/[:=-]/); const fallbackHost = parts[0]; const fallbackPort = parts[1] ? parseInt(parts[1], 10) : primaryTargetPort;
    if (!fallbackHost || isNaN(fallbackPort)) { logger('error', `Invalid fallback fmt: ${fallbackProxyIpString}`); safeCloseWebSocket(clientWebSocket); return; }
    logger('info', `Retrying with fallback: ${fallbackHost}:${fallbackPort}`);
    const success = await attemptConnection(fallbackHost, fallbackPort, true);
    if (!success) { logger('error', "Retry also failed."); safeCloseWebSocket(clientWebSocket); }
  }
  const initialSuccess = await attemptConnection(primaryTargetAddress, primaryTargetPort, false);
  if (!initialSuccess && fallbackProxyIpString) { await retryConnection(); }
  else if (!initialSuccess && !fallbackProxyIpString) { logger('warn', "Initial conn failed, no fallback."); safeCloseWebSocket(clientWebSocket); }
}

async function handleUdpOutbound(dnsServerAddress, dnsServerPort, clientUdpPayload, clientWebSocket, clientResponseHeader, logger, env) {
  logger('info', `UDP outbound to ${dnsServerAddress}:${dnsServerPort} (TCP tunnel).`);
  let outboundTcpToDnsSocket;
  try {
    outboundTcpToDnsSocket = connect({ hostname: dnsServerAddress, port: dnsServerPort });
    logger('info', `TCP to DNS server ${dnsServerAddress}:${dnsServerPort} OK.`);
    const writer = outboundTcpToDnsSocket.writable.getWriter();
    await writer.write(clientUdpPayload); logger('info', `Sent ${clientUdpPayload.byteLength}b UDP payload to DNS.`); writer.releaseLock();
    let headerToSendToClient = clientResponseHeader;
    await outboundTcpToDnsSocket.readable.pipeTo( new WritableStream({
        async write(dnsResponseChunk) {
          if (clientWebSocket.readyState !== WEBSOCKET_STATE.OPEN) { logger('warn', "Client WS not open for DNS resp."); throw new Error("Client WS not open."); }
          if (headerToSendToClient) {
            logger('info', `Prepending ${headerToSendToClient.byteLength}b hdr to DNS resp.`);
            clientWebSocket.send(await new Blob([headerToSendToClient, dnsResponseChunk]).arrayBuffer());
            headerToSendToClient = null;
          } else { clientWebSocket.send(dnsResponseChunk); }
        },
        close() { logger('info', `TCP to DNS ${dnsServerAddress}:${dnsServerPort} closed by remote.`); safeCloseWebSocket(clientWebSocket); },
        abort(reason) { logger('error', `TCP to DNS ${dnsServerAddress}:${dnsServerPort} aborted: ${reason.message||reason}`,reason); safeCloseWebSocket(clientWebSocket); },
      })
    );
  } catch (error) {
    logger('error', `Error in UDP (DNS) handling: ${error.message}`, error.stack);
    if (outboundTcpToDnsSocket) { outboundTcpToDnsSocket.close().catch(e => logger('warn', `Error closing TCP to DNS: ${e.message}`)); }
    safeCloseWebSocket(clientWebSocket);
  }
}

// --- SECTION 6: handleWebSocketConnection Function ---
function WebSocketPairObject() { const pair = new WebSocketPair(); return { client: pair[0], server: pair[1] }; }

async function handleWebSocketConnection(request, env) {
  const { client: clientWebSocketForRuntime, server: downstreamWebSocket } = WebSocketPairObject();
  downstreamWebSocket.accept();
  let logAddressInfo = "INIT";
  const logger = (level, message, details) => {
    const logMessage = `[WebSocket:${logAddressInfo}] ${message}`;
    if (level === 'error') console.error(logMessage, details || "");
    else if (level === 'warn') console.warn(logMessage, details || "");
    // else console.log(logMessage, details || ""); // Verbose
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableClientStream = createReadableWebSocketStream(downstreamWebSocket, earlyDataHeader, logger);
  const connectionState = { isDnsQuery: false, outboundSocketWrapper: { current: null }, hasSniffedProtocol: false, isUdpConnection: false, targetAddress: '', targetPort: 0, clientDataBuffer: null, responseHeaderForClient: null };

  try {
    await readableClientStream.pipeTo( new WritableStream({
        async write(chunk, controller) {
          if (connectionState.isDnsQuery) {
            return handleUdpOutbound(APP_CONFIG.DNS_SERVER_ADDRESS, APP_CONFIG.DNS_SERVER_PORT, chunk, downstreamWebSocket, connectionState.responseHeaderForClient, logger, env);
          }
          if (connectionState.outboundSocketWrapper.current) {
            const writer = connectionState.outboundSocketWrapper.current.writable.getWriter();
            try { await writer.write(chunk); } catch (e) { logger('error', `Err writing to remote TCP: ${e.message}`, e); controller.error(e); safeCloseWebSocket(downstreamWebSocket); }
            finally { writer.releaseLock(); } return;
          }
          if (!connectionState.hasSniffedProtocol) {
            const sniffedProtocolName = await sniffConnectionProtocol(chunk, env);
            let parsedHeader;
            if (sniffedProtocolName === PROTOCOLS.SNIFFER_RESULTS.TROJAN) parsedHeader = parseNajortHeader(chunk, env);
            else if (sniffedProtocolName === PROTOCOLS.SNIFFER_RESULTS.VLESS) parsedHeader = parseSselvHeader(chunk, env);
            else if (sniffedProtocolName === PROTOCOLS.SNIFFER_RESULTS.SHADOWSOCKS) parsedHeader = parseShadowsocksHeader(chunk, env);
            else { logger('error', `Unknown protocol: ${sniffedProtocolName}`); controller.error(new Error("Unknown protocol.")); safeCloseWebSocket(downstreamWebSocket); return; }

            if (parsedHeader.hasError || !parsedHeader.addressRemote) { logger('error', `Header parse error: ${parsedHeader.message || 'Addr missing'}`); controller.error(new Error(parsedHeader.message || "Header parse fail.")); safeCloseWebSocket(downstreamWebSocket); return; }
            
            connectionState.hasSniffedProtocol = true; connectionState.isUdpConnection = parsedHeader.isUDP || false;
            connectionState.targetAddress = parsedHeader.addressRemote; connectionState.targetPort = parsedHeader.portRemote;
            connectionState.clientDataBuffer = parsedHeader.rawClientData; connectionState.responseHeaderForClient = parsedHeader.version;
            logAddressInfo = `${connectionState.targetAddress}:${connectionState.targetPort} (${connectionState.isUdpConnection ? "UDP" : "TCP"}) via ${sniffedProtocolName}`;
            logger('info', `Sniffed: ${sniffedProtocolName}. Target: ${logAddressInfo}`);

            if (connectionState.isUdpConnection) {
              if (connectionState.targetPort === APP_CONFIG.DNS_SERVER_PORT) {
                connectionState.isDnsQuery = true; logAddressInfo = `DNS_TO:${APP_CONFIG.DNS_SERVER_ADDRESS}:${APP_CONFIG.DNS_SERVER_PORT}`;
                logger('info', 'Identified as DNS query.'); return this.write(connectionState.clientDataBuffer, controller);
              } else {
                logger('error', `Unsupported UDP port: ${connectionState.targetPort}.`); controller.error(new Error("UDP only for DNS port 53.")); safeCloseWebSocket(downstreamWebSocket); return;
              }
            }
          }
          await handleTcpOutbound(connectionState.outboundSocketWrapper, connectionState.targetAddress, connectionState.targetPort, connectionState.clientDataBuffer, downstreamWebSocket, connectionState.responseHeaderForClient, logger, env, workerGlobalProxyIP);
          connectionState.clientDataBuffer = null;
        },
        close() { logger('info', `Client WS stream closed.`); },
        abort(reason) {
          logger('warn', `Client WS stream aborted: ${reason.message || reason}`, reason);
          if (connectionState.outboundSocketWrapper.current) { connectionState.outboundSocketWrapper.current.close().catch(e => logger('warn', `Error closing remote on abort: ${e.message}`)); }
        },
      })
    );
  } catch (err) { logger('error', `WS pipeline error: ${err.message}`, err.stack); safeCloseWebSocket(downstreamWebSocket); }
  return new Response(null, { status: 101, webSocket: clientWebSocketForRuntime });
}


// --- SECTION 5: Main Fetch Handler ---
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const method = request.method;

    if (method === "OPTIONS") { return new Response(null, { headers: CORS_HEADERS }); }

    const isCloudflareApiConfigured = !!(env.CF_API_KEY && env.CF_API_EMAIL && env.CF_ACCOUNT_ID && env.CF_ZONE_ID);
    const rootDomain = env.ROOT_DOMAIN || "example.com";
    const serviceName = env.SERVICE_NAME || "worker";
    const appDomain = `${serviceName}.${rootDomain}`;

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      if (pathname.length === 3 || (pathname.startsWith("/") && pathname.includes(","))) {
        const targetCountryCodes = pathname.substring(1).toUpperCase().split(",").map(c => c.trim()).filter(Boolean);
        if (targetCountryCodes.length > 0) {
          const kvProxyUrl = searchParams.get("kv-list") || env.KV_PROXY_URL_OVERRIDE;
          const kvProxyMapping = await fetchKVProxyList(kvProxyUrl, env);
          if (Object.keys(kvProxyMapping).length > 0) {
            const selectedCountryCode = targetCountryCodes[Math.floor(Math.random() * targetCountryCodes.length)];
            const availableProxiesInCountry = kvProxyMapping[selectedCountryCode];
            if (availableProxiesInCountry && availableProxiesInCountry.length > 0) {
              workerGlobalProxyIP = availableProxiesInCountry[Math.floor(Math.random() * availableProxiesInCountry.length)];
              return handleWebSocketConnection(request, env);
            } else { return new Response("No proxy for country in KV.", { status: 404 }); }
          } else { return new Response("KV proxy list unavailable.", { status: 503 }); }
        } else { return new Response("Invalid country code format for WS.", { status: 400 }); }
      }
      const directProxyMatch = pathname.match(/^\/(.+?[:=-]\d+)$/);
      if (directProxyMatch && directProxyMatch[1]) {
        workerGlobalProxyIP = directProxyMatch[1];
        return handleWebSocketConnection(request, env);
      }
      return new Response("WS upgrade path not recognized.", { status: 400 });
    }

    if (pathname.startsWith("/sub")) {
      const pageMatch = pathname.match(/^\/sub\/(\d+)$/);
      const pageIndex = pageMatch && pageMatch[1] ? parseInt(pageMatch[1], 10) : 0;
      const requestHostname = request.headers.get("Host") || appDomain;
      const countryFilterCodes = searchParams.get("cc")?.toUpperCase().split(",").map(c => c.trim()).filter(Boolean);
      const proxyBankUrlOverride = searchParams.get("proxy-list");
      const forceProxyListRefresh = searchParams.get("refresh") === "true";
      let fullProxyList = await fetchAndCacheMainProxyList(proxyBankUrlOverride, env, forceProxyListRefresh);
      if (countryFilterCodes && countryFilterCodes.length > 0) {
        fullProxyList = fullProxyList.filter(p => p.country && countryFilterCodes.includes(p.country.toUpperCase()));
      }
      const htmlContent = generateSubscriptionPageHTML(request, requestHostname, fullProxyList, pageIndex, env);
      return new Response(htmlContent, { status: 200, headers: { "Content-Type": "text/html;charset=utf-8" } });
    }

    if (pathname.startsWith("/check")) {
      const targetProxy = searchParams.get("target");
      if (!targetProxy) return new Response(JSON.stringify({ error: "Missing 'target' param." }), { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
      const [targetIP, targetPortStr] = targetProxy.split(":");
      const targetPort = targetPortStr || (url.protocol === "https:" ? "443" : "80");
      if (!targetIP) return new Response(JSON.stringify({ error: "Invalid 'target' format." }), { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
      const healthCheckResult = await checkProxyHealth(targetIP, targetPort, env);
      return new Response(JSON.stringify(healthCheckResult), { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
    }

    if (pathname.startsWith("/api/v1")) {
      const apiSubPath = pathname.substring("/api/v1".length);
      if (apiSubPath.startsWith("/domains")) {
        if (!isCloudflareApiConfigured) return new Response(JSON.stringify({ error: "CF API not configured." }), { status: 503, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
        const domainApiPath = apiSubPath.substring("/domains".length);
        const cfApiClient = new CloudflareApiClient(env);
        if (domainApiPath === "/get") {
          const { success, data, error, status } = await cfApiClient.getDomainList();
          return new Response(JSON.stringify(success ? data : { error: error || "Failed to get domains." }), { status: status || (success ? 200 : 500), headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
        }
        if (domainApiPath === "/put") {
          const domainToRegister = searchParams.get("domain");
          if (!domainToRegister) return new Response(JSON.stringify({ error: "Missing 'domain' param." }), { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
          const { success, message, status } = await cfApiClient.registerDomain(domainToRegister);
          return new Response(JSON.stringify({ success, message: message || (success ? "OK" : "Fail") }), { status, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
        }
        return new Response(JSON.stringify({ error: "Unknown /api/v1/domains path." }), { status: 404, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
      }

      if (apiSubPath.startsWith("/sub")) {
        const filterCC = searchParams.get("cc")?.toUpperCase().split(",").map(c => c.trim()).filter(Boolean) || [];
        const filterPortsRaw = searchParams.get("port")?.split(",").map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
        const filterPorts = (filterPortsRaw && filterPortsRaw.length > 0) ? filterPortsRaw : APP_CONFIG.DEFAULT_PORTS;
        const filterVPNRaw = searchParams.get("vpn")?.toLowerCase().split(",").map(v => v.trim()).filter(Boolean);
        const validUriSchemes = Object.values(PROTOCOLS.URI_SCHEMES);
        const filterVPN = (filterVPNRaw && filterVPNRaw.length > 0) ? filterVPNRaw.filter(vpn => validUriSchemes.includes(vpn)) : ORDERED_PROTOCOLS_FOR_SUBSCRIPTION;
        const filterLimit = parseInt(searchParams.get("limit"), 10) || 10;
        const outputFormat = searchParams.get("format")?.toLowerCase() || "raw";
        const subscriptionDomain = searchParams.get("domain") || appDomain;
        const proxyBankUrlOverride = searchParams.get("proxy-list");
        const forceProxyListRefresh = searchParams.get("refresh") === "true";
        let availableProxies = await fetchAndCacheMainProxyList(proxyBankUrlOverride, env, forceProxyListRefresh);
        if (filterCC.length > 0) availableProxies = availableProxies.filter(p => p.country && filterCC.includes(p.country.toUpperCase()));
        shuffleArray(availableProxies);
        const generatedConfigs = []; const newUuid = crypto.randomUUID();

        for (const proxy of availableProxies) {
          if (generatedConfigs.length >= filterLimit) break;
          const baseUri = new URL(`http://${subscriptionDomain}`); baseUri.searchParams.set("encryption", "none"); baseUri.searchParams.set("type", "ws"); baseUri.searchParams.set("host", subscriptionDomain);
          const uniquePath = `/${proxy.proxyIP}-${proxy.proxyPort}`; baseUri.searchParams.set("path", uniquePath);
          for (const port of filterPorts) {
            if (generatedConfigs.length >= filterLimit) break; baseUri.port = port.toString(); const isTlsPort = (port === 443);
            for (const protocolScheme of filterVPN) {
              if (generatedConfigs.length >= filterLimit) break; baseUri.protocol = `${protocolScheme}:`;
              if (protocolScheme === PROTOCOLS.URI_SCHEMES.SHADOWSOCKS) {
                baseUri.username = btoa(`none:${newUuid}`);
                const pluginParts = ["v2ray-plugin", isTlsPort ? "tls" : "", "mux=0", "mode=websocket", `path=${uniquePath}`, `host=${subscriptionDomain}`];
                baseUri.searchParams.set("plugin", pluginParts.filter(Boolean).join(";"));
              } else { baseUri.username = newUuid; baseUri.searchParams.delete("plugin"); }
              baseUri.searchParams.set("security", isTlsPort ? "tls" : "none");
              const requiresSni = !(port === 80 && protocolScheme === PROTOCOLS.URI_SCHEMES.VLESS);
              baseUri.searchParams.set("sni", requiresSni ? subscriptionDomain : "");
              const remark = `${generatedConfigs.length + 1} ${getFlagEmoji(proxy.country)} ${proxy.org} WS ${isTlsPort ? "TLS" : "NTLS"} [${env.SERVICE_NAME || 'API'}]`;
              baseUri.hash = encodeURIComponent(remark); generatedConfigs.push(baseUri.toString());
            }
          }
        }
        let finalResult = ""; const converterApiUrl = env.CONVERTER_URL_OVERRIDE || DEFAULT_EXTERNAL_URLS.CONFIG_CONVERTER_API;
        switch (outputFormat) {
          case "raw": finalResult = generatedConfigs.join("\n"); break;
          case "v2ray": finalResult = btoa(generatedConfigs.join("\n")); break;
          case "clash": case "sfa": case "bfr":
            if (!converterApiUrl) return new Response(JSON.stringify({ error: "Converter API URL not configured." }), { status: 503, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
            try {
              const convRes = await fetch(converterApiUrl, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": `CloudflareWorker/${env.SERVICE_NAME || 'NauticaProxy'}-Converter` }, body: JSON.stringify({ url: generatedConfigs.join(","), format: outputFormat, template: "cf" }) });
              if (convRes.ok) finalResult = await convRes.text();
              else { const errTxt = await convRes.text(); throw new Error(`Converter API err (${convRes.status}): ${errTxt.substring(0,100)}`); }
            } catch (e) { return new Response(JSON.stringify({ error: `Converter API call failed: ${e.message}` }), { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }); }
            break;
          default: return new Response(JSON.stringify({ error: `Unsupported format: ${outputFormat}` }), { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
        }
        let contentType = (outputFormat === "clash") ? "application/yaml;charset=utf-8" : "text/plain;charset=utf-8";
        return new Response(finalResult, { status: 200, headers: { ...CORS_HEADERS, "Content-Type": contentType } });
      }

      if (apiSubPath.startsWith("/myip")) {
        const ipInfo = { ip: request.headers.get("cf-connecting-ipv6") || request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "Unknown", colo: request.headers.get("cf-ray")?.split("-")[1] || "Unknown", ...(request.cf || {}) };
        for(const key in ipInfo) if (ipInfo[key] === undefined) delete ipInfo[key];
        return new Response(JSON.stringify(ipInfo), { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ error: "Unknown /api/v1 path." }), { status: 404, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
    }

    const defaultReverseProxyTarget = env.REVERSE_PROXY_TARGET || "https://cloudflare.com";
    return executeReverseProxy(request, defaultReverseProxyTarget, undefined, env);

  } } catch (error) {
    console.error(`FetchHandler: Unhandled error for ${request.url}. Error: ${error.message}`, error.stack);
    return new Response(`An unexpected server error occurred: ${error.message}`, { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "text/plain;charset=utf-8" } });
  }
}
};

// --- END OF ASSEMBLED Cloudflare Worker Code ---