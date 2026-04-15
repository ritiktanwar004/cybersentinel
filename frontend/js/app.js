/**
 * CyberSentinel — app.js
 * Frontend logic: ML inference in-browser, API calls to backend, AI chain-of-thought
 */

"use strict";

// ═══════════════════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════════════════
const API = "http://localhost:5000/api"; // change if backend on different port
let MODEL_WEIGHTS = null; // loaded from /ml/model_weights.json
let currentQrUrl = "";
let cameraStream = null;
let lastScanResult = null;
let historyData = [];
let statsData = {};
let rfToggleState = {
  rf_available: false,
  rf_enabled: false,
  rf_requested: false,
};

// ═══════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", async () => {
  startClock();
  loadModelWeights();
  setupModelToggle();
  await fetchStats();
  checkBackend();
  setupNavigation();
  setupScannerEvents();
  setupQrEvents();
  setupBulkEvents();
  setupHistoryEvents();
  setupCameraEvents();
  renderModelPage();
  startFeedAnimation();
});

// ═══════════════════════════════════════════════════
//  CLOCK
// ═══════════════════════════════════════════════════
function startClock() {
  const el = document.getElementById("topClock");
  const update = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString("en-US", { hour12: false });
  };
  update();
  setInterval(update, 1000);
}

// ═══════════════════════════════════════════════════
//  LOAD JS MODEL WEIGHTS (in-browser LR inference)
// ═══════════════════════════════════════════════════
async function loadModelWeights() {
  try {
    const resp = await fetch("../ml/model_weights.json");
    if (resp.ok) {
      MODEL_WEIGHTS = await resp.json();
      console.log(
        "[ML] LR weights loaded in browser:",
        MODEL_WEIGHTS.feature_names.length,
        "features",
      );
      setSidebarStatus(
        "dotML",
        "sidebarML",
        true,
        `LR ${(MODEL_WEIGHTS.accuracy * 100).toFixed(1)}%`,
      );
      updateModelBadges(false, true, false);
    }
  } catch (e) {
    updateModelBadges(false, false, false);
    console.warn("[ML] Could not load browser weights:", e.message);
  }
}

// ═══════════════════════════════════════════════════
//  BACKEND HEALTH CHECK
// ═══════════════════════════════════════════════════
async function checkBackend() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      document.getElementById("sidebarBackend").textContent = "Online";
      document
        .querySelector(".sidebar-status .status-dot")
        .classList.add("active");
      rfToggleState = {
        rf_available: Boolean(data.rf_available),
        rf_enabled: Boolean(data.rf_enabled),
        rf_requested: Boolean(data.rf_requested),
      };
      updateModelBadges(Boolean(data.rf_enabled), true, true);
      updateRFToggleButton(rfToggleState);
      if (data.rf_enabled) {
        setSidebarStatus(
          "dotML",
          "sidebarML",
          true,
          `RF+LR ${(data.rf_accuracy * 100).toFixed(1)}%`,
        );
      } else if (MODEL_WEIGHTS?.accuracy) {
        setSidebarStatus(
          "dotML",
          "sidebarML",
          true,
          `LR ${(MODEL_WEIGHTS.accuracy * 100).toFixed(1)}% (RF off)`,
        );
      } else {
        setSidebarStatus("dotML", "sidebarML", false, "LR only (RF off)");
      }
      setSidebarStatus("dotAI", "sidebarAI", true, "Ready");
    }
  } catch {
    document.getElementById("sidebarBackend").textContent = "Offline";
    document.getElementById("sidebarAI").textContent = "Local";
    updateRFToggleButton({
      rf_available: false,
      rf_enabled: false,
      offline: true,
    });
    updateModelBadges(false, Boolean(MODEL_WEIGHTS), false);
    console.warn("[Backend] Not available — using browser-side ML");
  }
}

function setupModelToggle() {
  const btn = document.getElementById("rfToggleBtn");
  if (!btn) return;
  btn.addEventListener("click", toggleRFMode);
  updateRFToggleButton(rfToggleState);
}

function updateRFToggleButton(state) {
  const btn = document.getElementById("rfToggleBtn");
  const hint = document.getElementById("rfToggleHint");
  if (!btn) return;

  const isOffline = Boolean(state.offline);
  const available = Boolean(state.rf_available);
  const enabled = Boolean(state.rf_enabled);

  btn.classList.toggle("on", enabled);
  btn.textContent = `RF: ${enabled ? "ON" : "OFF"}`;
  if (hint) hint.className = "rf-toggle-hint";

  if (isOffline) {
    btn.disabled = true;
    btn.title = "Backend offline";
    if (hint) {
      hint.textContent = "Backend offline. RF toggle unavailable.";
      hint.classList.add("warn");
    }
    return;
  }

  if (!available) {
    btn.disabled = true;
    btn.title = "RF model file not loaded";
    if (hint) {
      hint.textContent =
        "RF model file not found (ml/rf_model.pkl). Add the file to enable toggle.";
      hint.classList.add("warn");
    }
    return;
  }

  btn.disabled = false;
  btn.title = enabled ? "Click to turn RF off" : "Click to turn RF on";
  if (hint) {
    hint.textContent = enabled
      ? "Random Forest is enabled for ensemble scoring."
      : "Random Forest is available but currently disabled.";
    hint.classList.add(enabled ? "ready" : "warn");
  }
}

async function toggleRFMode() {
  const btn = document.getElementById("rfToggleBtn");
  if (!btn || btn.disabled) return;

  const requested = !rfToggleState.rf_enabled;
  btn.disabled = true;

  try {
    const resp = await fetch(`${API}/model-control`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rf_enabled: requested }),
      signal: AbortSignal.timeout(5000),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Unable to update RF mode");

    rfToggleState = data;
    updateRFToggleButton(rfToggleState);
    await checkBackend();
  } catch (err) {
    console.warn("[RF Toggle]", err.message || err);
    await checkBackend();
  } finally {
    const current = document.getElementById("rfToggleBtn");
    if (current && rfToggleState.rf_available) current.disabled = false;
  }
}

function updateModelBadges(rfReady, lrReady, aiReady) {
  const badgeRF = document.getElementById("badgeRF");
  const badgeLR = document.getElementById("badgeLR");
  const badgeAI = document.getElementById("badgeAI");

  if (badgeRF) {
    badgeRF.className = "mbadge" + (rfReady ? " active" : " off");
    badgeRF.textContent = rfReady ? "RF" : "RF OFF";
    badgeRF.title = rfReady
      ? "Random Forest model loaded"
      : "Random Forest model not loaded (fallback: LR only)";
  }
  if (badgeLR) {
    badgeLR.className = "mbadge" + (lrReady ? " active" : "");
    badgeLR.textContent = "LR";
    badgeLR.title = lrReady
      ? "Logistic Regression model loaded"
      : "Logistic Regression model unavailable";
  }
  if (badgeAI) {
    badgeAI.className = "mbadge ai" + (aiReady ? " active" : "");
    badgeAI.title = aiReady
      ? "AI reasoning available"
      : "AI reasoning fallback mode";
  }
}

function setSidebarStatus(dotId, valId, active, text) {
  const dot = document.getElementById(dotId);
  const val = document.getElementById(valId);
  if (dot) {
    dot.className = "status-dot" + (active ? " active" : " warn");
  }
  if (val && text) val.textContent = text;
}

// ═══════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════
const PAGE_TITLES = {
  scanner: "URL Scanner",
  qr: "QR Analyzer",
  bulk: "Bulk Scanner",
  history: "Scan History",
  model: "ML Model",
  analytics: "Analytics",
};
function setupNavigation() {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      switchPage(link.dataset.page);
      // close sidebar on mobile
      document.getElementById("sidebar").classList.remove("open");
    });
  });
  document.getElementById("hamburger").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });
}
function switchPage(name) {
  document
    .querySelectorAll(".nav-link")
    .forEach((l) => l.classList.toggle("active", l.dataset.page === name));
  document
    .querySelectorAll(".page")
    .forEach((p) => p.classList.toggle("active", p.id === `page-${name}`));
  document.getElementById("pageTitle").textContent = PAGE_TITLES[name] || name;
  if (name === "history") {
    loadHistory();
  }
  if (name === "analytics") {
    loadAnalytics();
  }
}

// ═══════════════════════════════════════════════════
//  FEATURE EXTRACTION (browser-side, mirrors Python)
// ═══════════════════════════════════════════════════
const SUSPICIOUS_KW = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "confirm",
  "bank",
  "paypal",
  "apple",
  "amazon",
  "google",
  "microsoft",
  "password",
  "credential",
  "suspend",
  "urgent",
  "free",
  "prize",
  "winner",
  "claim",
  "signin",
  "billing",
  "support",
  "security",
  "alert",
  "notice",
  "limited",
  "expire",
  "validate",
  "authenticate",
];
const TRUSTED_DOMAINS = [
  "google.com",
  "facebook.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "twitter.com",
  "github.com",
  "linkedin.com",
  "youtube.com",
  "wikipedia.org",
  "reddit.com",
  "instagram.com",
  "netflix.com",
  "ebay.com",
];
const TRUSTED_HOSTS = new Set([
  "ritiktanwar004.github.io",
  "www.snapchat.com",
  "snapchat.com",
  "google.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "twitter.com",
  "linkedin.com",
  "github.com",
  "stackoverflow.com",
  "wikipedia.org",
  "amazon.com",
  "amazon.in",
  "flipkart.com",
  "myntra.com",
  "apple.com",
  "microsoft.com",
  "netflix.com",
  "paypal.com",
  "openai.com",
  "bing.com",
  "yahoo.com",
  "reddit.com",
  "quora.com",
  "bbc.com",
  "cnn.com",
  "nytimes.com",
  "theguardian.com",
  "ndtv.com",
  "thehindu.com",
  "coursera.org",
  "udemy.com",
  "khanacademy.org",
  "edx.org",
  "zoom.us",
  "slack.com",
  "dropbox.com",
  "drive.google.com",
  "docs.google.com",
  "notion.so",
  "canva.com",
  "adobe.com",
  "shopify.com",
  "wordpress.com",
  "medium.com",
  "airbnb.com",
  "uber.com",
  "ola.com",
  "zomato.com",
  "swiggy.com",
  "paytm.com",
  "phonepe.com",
  "razorpay.com",
  "hdfcbank.com",
  "icicibank.com",
  "sbi.co.in",
]);
const PHISHING_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".xyz",
  ".top",
  ".club",
  ".online",
  ".site",
  ".info",
  ".biz",
  ".pw",
  ".cc",
  ".su",
];

function parseUrl(url) {
  try {
    return new URL(url.startsWith("http") ? url : "https://" + url);
  } catch {
    return null;
  }
}

function extractFeatures(url) {
  const urlStr = url.trim();
  const parsed = parseUrl(urlStr);
  const domain = (parsed ? parsed.hostname : urlStr).toLowerCase();
  const path = parsed ? parsed.pathname.toLowerCase() : "";
  const query = parsed ? parsed.search : "";
  const urlLow = urlStr.toLowerCase();

  const feats = {};
  feats.is_https = urlStr.startsWith("https://") ? 1 : 0;
  feats.url_length = Math.min(urlStr.length, 200) / 200;
  feats.domain_length = Math.min(domain.length, 100) / 100;
  feats.is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain.split(":")[0]) ? 1 : 0;
  feats.hyphen_count = Math.min((domain.match(/-/g) || []).length, 10) / 10;
  feats.dot_count = Math.min((domain.match(/\./g) || []).length, 8) / 8;
  feats.subdomain_count =
    Math.min(Math.max(domain.split(".").length - 2, 0), 5) / 5;
  feats.suspicious_tld = PHISHING_TLDS.some((t) => domain.endsWith(t)) ? 1 : 0;
  const kwCount = SUSPICIOUS_KW.filter((k) => urlLow.includes(k)).length;
  feats.keyword_count = Math.min(kwCount, 10) / 10;
  const brandSpoof = TRUSTED_DOMAINS.find((td) => {
    const b = td.split(".")[0];
    return urlLow.includes(b) && !domain.endsWith(td);
  });
  feats.brand_mismatch = brandSpoof ? 1 : 0;
  feats.at_symbol = urlStr.includes("@") ? 1 : 0;
  feats.double_slash = path.includes("//") ? 1 : 0;
  feats.encoded_chars =
    Math.min((urlStr.match(/%[0-9a-fA-F]{2}/g) || []).length, 10) / 10;
  feats.digit_ratio =
    [...domain].filter((c) => /\d/.test(c)).length / Math.max(domain.length, 1);
  feats.path_length = Math.min(path.length, 150) / 150;
  feats.has_port =
    domain.includes(":") && /\d+$/.test(domain.split(":").pop()) ? 1 : 0;
  feats.has_query = query.length > 0 ? 1 : 0;
  feats.special_chars =
    Math.min((urlStr.match(/[!$&'()*+,;=]/g) || []).length, 10) / 10;

  return {
    feats,
    extras: {
      domain,
      kwCount,
      brandSpoof: brandSpoof ? brandSpoof.split(".")[0] : null,
      urlLen: urlStr.length,
      domainLen: domain.length,
    },
  };
}

// Browser-side LR inference
function predictLR(featVec) {
  if (!MODEL_WEIGHTS) return 0.5;
  const { coef, intercept, mean, scale } = MODEL_WEIGHTS;
  const scaled = featVec.map(
    (v, i) => (v - mean[i]) / Math.max(scale[i], 1e-9),
  );
  const logit = scaled.reduce((s, v, i) => s + coef[i] * v, 0) + intercept;
  return 1 / (1 + Math.exp(-logit));
}

function browserPredict(url) {
  const parsed = parseUrl(url);
  const host = (parsed ? parsed.hostname : url).toLowerCase();
  if (TRUSTED_HOSTS.has(host)) {
    const { feats, extras } = extractFeatures(url);
    return {
      verdict: "legitimate",
      risk_score: 0,
      lr_score: 0,
      ml_score: 0,
      extras,
      feats,
    };
  }

  const { feats, extras } = extractFeatures(url);
  const names = MODEL_WEIGHTS
    ? MODEL_WEIGHTS.feature_names
    : Object.keys(feats);
  const featVec = names.map((n) => feats[n] || 0);
  const lrProb = predictLR(featVec);
  const riskScore = Math.round(lrProb * 100);
  const verdict =
    riskScore >= 60
      ? "phishing"
      : riskScore >= 30
        ? "suspicious"
        : "legitimate";
  return {
    verdict,
    risk_score: riskScore,
    lr_score: riskScore,
    ml_score: null,
    extras,
    feats,
  };
}

// ═══════════════════════════════════════════════════
//  BUILD INDICATORS
// ═══════════════════════════════════════════════════
function buildIndicators(feats, extras) {
  const ind = [];
  const add = (label, value, status) => ind.push({ label, value, status });

  add(
    "HTTPS Encryption",
    feats.is_https ? "Enabled" : "Missing",
    feats.is_https ? "safe" : "warn",
  );
  add(
    "IP Address Domain",
    feats.is_ip ? "⚠ Detected" : "Clean",
    feats.is_ip ? "danger" : "safe",
  );
  add(
    "Suspicious TLD",
    feats.suspicious_tld ? "⚠ Detected" : "Clean",
    feats.suspicious_tld ? "danger" : "safe",
  );
  add(
    "Phishing Keywords",
    `${extras.kwCount} found`,
    extras.kwCount > 3 ? "danger" : extras.kwCount > 1 ? "warn" : "safe",
  );
  add(
    "Brand Spoofing",
    extras.brandSpoof ? `⚠ ${extras.brandSpoof}` : "None",
    extras.brandSpoof ? "danger" : "safe",
  );
  const h = Math.round(feats.hyphen_count * 10);
  add(
    "Hyphens in Domain",
    `${h} found`,
    h > 2 ? "danger" : h > 0 ? "warn" : "safe",
  );
  const s = Math.round(feats.subdomain_count * 5);
  add(
    "Subdomain Depth",
    `${s} levels`,
    s > 2 ? "danger" : s > 1 ? "warn" : "safe",
  );
  add(
    "URL Length",
    `${extras.urlLen} chars`,
    extras.urlLen > 100 ? "danger" : extras.urlLen > 60 ? "warn" : "safe",
  );
  add(
    "URL Encoding",
    feats.encoded_chars > 0 ? "⚠ Present" : "None",
    feats.encoded_chars > 0 ? "warn" : "safe",
  );
  add(
    "@ Symbol",
    feats.at_symbol ? "⚠ Found" : "None",
    feats.at_symbol ? "danger" : "safe",
  );

  return ind;
}

function renderIndicators(containerId, indicators) {
  const el = document.getElementById(containerId);
  el.innerHTML = indicators
    .map(
      (ind) => `
    <div class="indicator-chip">
      <div class="ind-dot ${ind.status}"></div>
      <div class="ind-text">
        <strong>${ind.label}</strong>
        <span>${ind.value}</span>
      </div>
    </div>
  `,
    )
    .join("");
}

// ═══════════════════════════════════════════════════
//  AI CHAIN-OF-THOUGHT (3-step thinking animation)
// ═══════════════════════════════════════════════════
function buildThinkingSteps(url, verdict, riskScore, extras) {
  const steps = [];
  const domain = extras.domain || extras.extras?.domain || url;
  const kwCount = extras.kwCount ?? extras.extras?.kwCount ?? 0;
  const brandSpoof = extras.brandSpoof ?? extras.extras?.brandSpoof ?? null;

  // Step 1: Structural analysis
  let s1 = `Analyzing URL structure: domain "${domain}" has ${Math.round((extras.feats?.domain_length || 0) * 100)} chars, `;
  s1 += extras.feats?.is_https
    ? "uses HTTPS encryption, "
    : "NO HTTPS encryption (risk), ";
  s1 += `${Math.round((extras.feats?.subdomain_count || 0) * 5)} subdomain levels detected.`;
  steps.push(s1);

  // Step 2: Threat pattern matching
  let s2 = `Pattern matching: `;
  const threats = [];
  if (brandSpoof) threats.push(`brand impersonation of "${brandSpoof}"`);
  if (kwCount > 0) threats.push(`${kwCount} social engineering keyword(s)`);
  if (extras.feats?.suspicious_tld) threats.push("high-abuse TLD");
  if (extras.feats?.is_ip) threats.push("IP address as domain");
  if (extras.feats?.hyphen_count > 0.2) threats.push("excessive hyphens");
  if (threats.length === 0)
    threats.push("no significant threat patterns found");
  s2 += threats.join(", ") + ".";
  steps.push(s2);

  // Step 3: ML confidence
  let s3 = `Ensemble ML confidence: Risk score ${riskScore}/100 (${riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW"} threat). `;
  s3 +=
    verdict === "phishing"
      ? "Decision threshold exceeded — classifying as PHISHING."
      : verdict === "suspicious"
        ? "Partial indicators present — flagging as SUSPICIOUS."
        : "Insufficient threat markers — URL appears LEGITIMATE.";
  steps.push(s3);

  return steps;
}

function buildConclusion(url, verdict, riskScore, extras, aiText) {
  if (aiText && aiText.length > 30) return aiText;

  // Rule-based fallback
  const domain = extras.domain || extras.extras?.domain || "?";
  const kwCount = extras.kwCount ?? extras.extras?.kwCount ?? 0;
  const brandSpoof = extras.brandSpoof ?? extras.extras?.brandSpoof ?? null;

  if (verdict === "phishing") {
    let c = `🚨 HIGH THREAT: This URL is classified as a phishing attempt with ${riskScore}% confidence. `;
    if (brandSpoof)
      c += `It impersonates "${brandSpoof}" while not residing on the legitimate domain. `;
    if (kwCount > 0)
      c += `${kwCount} social engineering keyword(s) were found that are commonly used in credential theft. `;
    c += `⛔ Do NOT enter any credentials. Do not proceed to this URL. Report to your security team.`;
    return c;
  }
  if (verdict === "suspicious") {
    return `⚠️ CAUTION: This URL scored ${riskScore}/100 on threat indicators — above the safe threshold. The domain "${domain}" shows partial phishing signatures. ${kwCount > 0 ? `Found ${kwCount} sensitive keywords. ` : ""}Independently verify this URL before visiting, especially if received via email or SMS.`;
  }
  return `✅ LOW RISK: URL scored ${riskScore}/100 — below threat thresholds. Domain "${domain}" uses ${extras.feats?.is_https ? "secure HTTPS" : "HTTP (note: no encryption)"} and shows no brand impersonation, suspicious keywords, or anomalous structure. Always verify unexpected links independently.`;
}

async function animateThinkingSteps(steps, conclusion, tsIds, conclusionId) {
  for (let i = 0; i < steps.length; i++) {
    await delay(400 + i * 300);
    const el = document.getElementById(tsIds[i]);
    if (el) {
      el.querySelector(".ts-text").textContent = steps[i];
      el.classList.add("visible");
    }
  }
  await delay(500);
  const concEl = document.getElementById(conclusionId);
  if (concEl) {
    await typeText(concEl, conclusion);
  }
}

async function typeText(el, text, speed = 12) {
  el.innerHTML = "";
  const cursor = document.createElement("span");
  cursor.className = "ai-cursor";
  el.appendChild(cursor);
  for (const char of text) {
    cursor.insertAdjacentText("beforebegin", char);
    await delay(speed);
  }
  cursor.remove();
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// ═══════════════════════════════════════════════════
//  MAIN SCAN FLOW
// ═══════════════════════════════════════════════════
function setupScannerEvents() {
  const btn = document.getElementById("scanBtn");
  const inp = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearUrlBtn");

  btn.addEventListener("click", () => triggerScan());
  inp.addEventListener("keydown", (e) => e.key === "Enter" && triggerScan());
  clearBtn.addEventListener("click", () => {
    inp.value = "";
    inp.focus();
  });

  document
    .getElementById("copyReportBtn")
    .addEventListener("click", copyReport);
  document
    .getElementById("exportJsonBtn")
    .addEventListener("click", exportJson);
  document.getElementById("shareLinkBtn").addEventListener("click", shareLink);
}

window.testUrl = function (url) {
  document.getElementById("urlInput").value = url;
  triggerScan();
};

async function triggerScan() {
  const rawUrl = document.getElementById("urlInput").value.trim();
  if (!rawUrl) return;
  const url = rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl;

  setProgress(true);
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="loader"></span> Scanning…`;

  // Reset AI steps
  ["ts1", "ts2", "ts3"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("visible");
      el.querySelector(".ts-text").textContent = "";
    }
  });
  document.getElementById("aiConclusion").textContent = "";

  try {
    let result;
    try {
      // Try backend first
      const resp = await fetch(`${API}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        const data = await resp.json();
        result = {
          ...data,
          extras: {
            domain: data.domain,
            kwCount: 0,
            brandSpoof: null,
            feats: {},
          },
        };
        // Also run browser-side for indicator data
        const browser = browserPredict(url);
        result.indicators = buildIndicators(browser.feats, browser.extras);
        result.extras = browser.extras;
        result.feats = browser.feats;
      } else throw new Error("Backend error");
    } catch {
      // Fallback: browser-side ML
      const browser = browserPredict(url);
      result = {
        url,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        lr_score: browser.lr_score,
        ml_score: null,
        indicators: buildIndicators(browser.feats, browser.extras),
        extras: browser.extras,
        feats: browser.feats,
        ai_analysis: null,
      };
    }

    lastScanResult = result;
    renderResult(
      result,
      "resultCard",
      "verdictBadge",
      "scoreRingSvg",
      "ringFill",
      "scoreNum",
      "rfBar",
      "rfVal",
      "lrBar",
      "lrVal",
      "ensBar",
      "ensVal",
      "indicatorsGrid",
      "resultUrl",
      result.url,
    );

    // AI thinking animation
    const thinkSteps = buildThinkingSteps(
      url,
      result.verdict,
      result.risk_score,
      result,
    );
    const conclusion = buildConclusion(
      url,
      result.verdict,
      result.risk_score,
      result,
      result.ai_analysis,
    );
    animateThinkingSteps(
      thinkSteps,
      conclusion,
      ["ts1", "ts2", "ts3"],
      "aiConclusion",
    );

    // Update threat ticker
    updateThreatTicker(result.verdict);

    // Save local stats
    saveLocalHistory(result);
  } catch (err) {
    console.error("Scan error:", err);
  }

  setProgress(false);
  btn.disabled = false;
  btn.innerHTML = `<span class="btn-icon">⚡</span> SCAN URL`;
}

function renderResult(
  result,
  cardId,
  badgeId,
  ringSvgId,
  ringFillId,
  scoreNumId,
  rfBarId,
  rfValId,
  lrBarId,
  lrValId,
  ensBarId,
  ensValId,
  gridId,
  urlLabelId,
  url,
) {
  const card = document.getElementById(cardId);
  if (!card) return;
  card.style.display = "block";
  card.className = "result-card card v-" + result.verdict;

  // Verdict badge
  const badge = document.getElementById(badgeId);
  const verdictMap = {
    phishing: "🚨 PHISHING",
    legitimate: "✅ LEGITIMATE",
    suspicious: "⚠ SUSPICIOUS",
  };
  if (badge) {
    badge.textContent = verdictMap[result.verdict] || result.verdict;
    badge.className = "verdict-badge " + result.verdict;
  }

  // URL label
  if (urlLabelId) {
    const urlEl = document.getElementById(urlLabelId);
    if (urlEl)
      urlEl.textContent =
        url && url.length > 70 ? url.substring(0, 70) + "…" : url;
  }

  // Score ring
  const rs = Number(result.risk_score ?? 0);
  const ringFill = document.getElementById(ringFillId);
  const scoreEl = document.getElementById(scoreNumId);
  const colorClass = rs >= 60 ? "r" : rs >= 30 ? "o" : "g";
  if (ringFill) {
    ringFill.setAttribute("class", "ring-fill " + colorClass);
  }
  const circumference = 314;
  const offset = circumference - (rs / 100) * circumference;
  setTimeout(() => {
    if (ringFill) ringFill.style.strokeDashoffset = offset;
  }, 50);
  if (scoreEl) {
    scoreEl.textContent = Number.isFinite(rs) ? String(rs) : "0";
    scoreEl.className =
      "score-num " + (rs >= 60 ? "danger" : rs >= 30 ? "warn" : "safe");
  }

  // Dual model bars
  const mlScore = Number(result.ml_score ?? result.risk_score ?? 0);
  const lrScore = Number(result.lr_score ?? result.risk_score ?? 0);
  const ensScore = Number(result.risk_score ?? 0);
  setTimeout(() => {
    const rfBar = document.getElementById(rfBarId);
    const rfVal = document.getElementById(rfValId);
    const lrBar = document.getElementById(lrBarId);
    const lrVal = document.getElementById(lrValId);
    const ensBar = document.getElementById(ensBarId);
    const ensVal = document.getElementById(ensValId);

    if (rfBar) {
      rfBar.style.width = mlScore + "%";
    }
    if (rfVal) {
      rfVal.textContent = result.ml_score == null ? "N/A" : mlScore + "%";
    }
    if (lrBar) {
      lrBar.style.width = lrScore + "%";
    }
    if (lrVal) {
      lrVal.textContent = lrScore + "%";
    }
    if (ensBar) {
      ensBar.style.width = ensScore + "%";
    }
    if (ensVal) {
      ensVal.textContent = ensScore + "%";
    }
  }, 100);

  // Indicators
  const indicators =
    result.indicators ||
    (result.feats ? buildIndicators(result.feats, result.extras || {}) : []);
  renderIndicators(gridId, indicators);
}

// ═══════════════════════════════════════════════════
//  STATS & PROGRESS
// ═══════════════════════════════════════════════════
async function fetchStats() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      statsData = await r.json();
      updateStatsStrip(statsData);
    }
  } catch {
    // use local storage
    const local = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
    updateStatsStrip({
      total_scans: local.total || 0,
      phishing_found: local.phishing || 0,
      safe_found: local.safe || 0,
      suspicious_found: local.suspicious || 0,
      last_24h: local.total || 0,
    });
  }
}

function updateStatsStrip(data) {
  document.getElementById("st0").textContent = data.total_scans ?? "—";
  document.getElementById("st1").textContent = data.phishing_found ?? "—";
  document.getElementById("st2").textContent = data.safe_found ?? "—";
  document.getElementById("st3").textContent = data.suspicious_found ?? "—";
  document.getElementById("st4").textContent = data.last_24h ?? "—";
}

function setProgress(on) {
  const fill = document.getElementById("scanProgressFill");
  fill.classList.toggle("active", on);
  fill.style.width = on ? "100%" : "0%";
}

function updateThreatTicker(verdict) {
  const el = document.getElementById("tickerVal");
  if (verdict === "phishing") {
    el.textContent = "CRITICAL";
    el.className = "ticker-val critical";
  } else if (verdict === "suspicious") {
    el.textContent = "ELEVATED";
    el.className = "ticker-val elevated";
  } else {
    el.textContent = "NOMINAL";
    el.className = "ticker-val";
  }
}

function saveLocalHistory(result) {
  let hist = JSON.parse(localStorage.getItem("cs_hist") || "[]");
  hist.unshift({
    url: result.url,
    verdict: result.verdict,
    risk_score: result.risk_score,
    time: new Date().toISOString(),
  });
  if (hist.length > 200) hist = hist.slice(0, 200);
  localStorage.setItem("cs_hist", JSON.stringify(hist));

  let s = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
  s.total = (s.total || 0) + 1;
  s[result.verdict] = (s[result.verdict] || 0) + 1;
  localStorage.setItem("cs_local_stats", JSON.stringify(s));

  fetchStats();
}

// ═══════════════════════════════════════════════════
//  REPORT ACTIONS
// ═══════════════════════════════════════════════════
function copyReport() {
  if (!lastScanResult) return;
  const r = lastScanResult;
  const text = [
    "═══ CyberSentinel Threat Report ═══",
    `URL: ${r.url}`,
    `Verdict: ${r.verdict.toUpperCase()}`,
    `Risk Score: ${r.risk_score}/100`,
    r.ml_score ? `Random Forest: ${r.ml_score}%` : "",
    `Logistic Regression: ${r.lr_score}%`,
    `Timestamp: ${new Date().toISOString()}`,
    "═══════════════════════════════════",
  ]
    .filter(Boolean)
    .join("\n");
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copyReportBtn");
    btn.textContent = "✓ Copied!";
    setTimeout(() => (btn.textContent = "📋 Copy Report"), 2000);
  });
}
function exportJson() {
  if (!lastScanResult) return;
  const blob = new Blob([JSON.stringify(lastScanResult, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-report.json";
  a.click();
}
function shareLink() {
  if (!lastScanResult) return;
  const url = `${location.origin}${location.pathname}?scan=${encodeURIComponent(lastScanResult.url)}`;
  navigator.clipboard.writeText(url);
  const btn = document.getElementById("shareLinkBtn");
  btn.textContent = "✓ Link Copied!";
  setTimeout(() => (btn.textContent = "🔗 Share"), 2000);
}

// ═══════════════════════════════════════════════════
//  QR SCANNER
// ═══════════════════════════════════════════════════
function setupQrEvents() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("qrFileInput");

  document
    .getElementById("dzClick")
    .addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("over");
  });
  dropZone.addEventListener("dragleave", () =>
    dropZone.classList.remove("over"),
  );
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("over");
    if (e.dataTransfer.files[0]) handleQrFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", (e) => {
    if (e.target.files[0]) handleQrFile(e.target.files[0]);
  });

  document.getElementById("qrPasteBtn").addEventListener("click", async () => {
    try {
      const items = await navigator.clipboard.read();
      for (const item of items) {
        const imgType = item.types.find((t) => t.startsWith("image/"));
        if (imgType) {
          handleQrFile(await item.getType(imgType));
          return;
        }
      }
      alert("No image in clipboard. Copy a QR image first.");
    } catch {
      alert(
        "Clipboard access denied. Permission is only needed for QR paste. Normal URL scanning works without permission. You can upload the file instead.",
      );
    }
  });

  document.getElementById("qrCamBtn").addEventListener("click", () => {
    document.getElementById("cameraModal").classList.add("open");
    startCamera();
  });

  document
    .getElementById("analyzeQrBtn")
    .addEventListener("click", async () => {
      if (!currentQrUrl) return;
      const btn = document.getElementById("analyzeQrBtn");
      btn.disabled = true;
      btn.innerHTML = `<span class="loader"></span> Analyzing…`;

      const browser = browserPredict(currentQrUrl);
      let result = {
        url: currentQrUrl,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        lr_score: browser.lr_score,
        ml_score: null,
        feats: browser.feats,
        extras: browser.extras,
      };

      try {
        const resp = await fetch(`${API}/predict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: currentQrUrl }),
          signal: AbortSignal.timeout(8000),
        });
        if (resp.ok) Object.assign(result, await resp.json());
      } catch {}

      const indicators = buildIndicators(browser.feats, browser.extras);
      renderResult(
        result,
        "qrScanResult",
        "qrVerdictBadge",
        null,
        "qrRingFill",
        "qrScoreNum",
        null,
        null,
        null,
        null,
        null,
        null,
        "qrIndicatorsGrid",
        "qrResultUrl",
        currentQrUrl,
      );
      document.getElementById("qrScanResult").style.display = "block";

      const conclusion = buildConclusion(
        currentQrUrl,
        result.verdict,
        result.risk_score,
        browser,
        result.ai_analysis,
      );
      const concEl = document.getElementById("qrAiConclusion");
      if (concEl) typeText(concEl, conclusion);
      saveLocalHistory(result);
      btn.disabled = false;
      btn.innerHTML = "⚡ ANALYZE URL";
    });
}

function handleQrFile(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = document.getElementById("qrPreviewImg");
    img.src = e.target.result;
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      canvas.getContext("2d").drawImage(img, 0, 0);
      const imageData = canvas
        .getContext("2d")
        .getImageData(0, 0, canvas.width, canvas.height);
      const code =
        typeof jsQR !== "undefined"
          ? jsQR(imageData.data, imageData.width, imageData.height)
          : null;
      document.getElementById("qrResultPanel").style.display = "block";
      if (code) {
        currentQrUrl = code.data;
        document.getElementById("qrDecodedContent").textContent = code.data;
        document.getElementById("qrType").textContent = code.data.startsWith(
          "http",
        )
          ? "🔗 URL / Link"
          : "📄 Text / Data";
        document.getElementById("qrLength").textContent =
          code.data.length + " chars";
      } else {
        document.getElementById("qrDecodedContent").textContent =
          "⚠ Could not decode — try a clearer image";
        document.getElementById("qrType").textContent = "Unknown";
      }
    };
  };
  reader.readAsDataURL(file);
}

// ═══════════════════════════════════════════════════
//  CAMERA
// ═══════════════════════════════════════════════════
function setupCameraEvents() {
  const close1 = document.getElementById("closeCamBtn");
  const close2 = document.getElementById("closeCamBtn2");
  const capture = document.getElementById("captureCamBtn");
  [close1, close2].forEach((b) => b?.addEventListener("click", stopCamera));
  capture?.addEventListener("click", captureQrFromCamera);
}

async function startCamera() {
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
    });
    document.getElementById("cameraFeed").srcObject = cameraStream;
  } catch {
    alert(
      "Camera access denied. Permission is only needed for QR camera scan. Normal URL scanning works without permission.",
    );
    stopCamera();
  }
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((t) => t.stop());
    cameraStream = null;
  }
  document.getElementById("cameraModal").classList.remove("open");
}

function captureQrFromCamera() {
  const video = document.getElementById("cameraFeed");
  const canvas = document.getElementById("camCanvas");
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext("2d").drawImage(video, 0, 0);
  const imageData = canvas
    .getContext("2d")
    .getImageData(0, 0, canvas.width, canvas.height);
  const code =
    typeof jsQR !== "undefined"
      ? jsQR(imageData.data, imageData.width, imageData.height)
      : null;
  if (code) {
    currentQrUrl = code.data;
    const img = document.getElementById("qrPreviewImg");
    img.src = canvas.toDataURL();
    document.getElementById("qrDecodedContent").textContent = code.data;
    document.getElementById("qrType").textContent = code.data.startsWith("http")
      ? "🔗 URL / Link"
      : "📄 Text";
    document.getElementById("qrLength").textContent =
      code.data.length + " chars";
    document.getElementById("qrResultPanel").style.display = "block";
    stopCamera();
    switchPage("qr");
  } else alert("No QR code detected. Reposition and try again.");
}

// ═══════════════════════════════════════════════════
//  BULK SCANNER
// ═══════════════════════════════════════════════════
let bulkResultsCache = [];
function setupBulkEvents() {
  const ta = document.getElementById("bulkTextarea");
  ta.addEventListener("input", () => {
    const lines = ta.value.split("\n").filter((l) => l.trim());
    document.getElementById("bulkCount").textContent =
      Math.min(lines.length, 30) + " URLs detected";
  });
  document.getElementById("bulkClearBtn").addEventListener("click", () => {
    ta.value = "";
    document.getElementById("bulkResultsContainer").innerHTML = "";
    document.getElementById("bulkCount").textContent = "0 URLs detected";
    bulkResultsCache = [];
  });
  document.getElementById("bulkScanBtn").addEventListener("click", runBulkScan);
  document
    .getElementById("bulkExportBtn")
    .addEventListener("click", exportBulkCsv);
}

async function runBulkScan() {
  const lines = document
    .getElementById("bulkTextarea")
    .value.split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 30);
  if (!lines.length) return;

  const btn = document.getElementById("bulkScanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="loader"></span> Scanning…`;
  setProgress(true);
  bulkResultsCache = [];

  const container = document.getElementById("bulkResultsContainer");
  container.innerHTML = `<div class="card"><div class="card-label">≡ BULK RESULTS</div><div id="bulkRows"></div></div>`;
  const rowsEl = document.getElementById("bulkRows");

  // Try backend bulk endpoint
  let backendResults = null;
  try {
    const resp = await fetch(`${API}/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: lines }),
      signal: AbortSignal.timeout(30000),
    });
    if (resp.ok) backendResults = (await resp.json()).results;
  } catch {}

  for (let i = 0; i < lines.length; i++) {
    const url = lines[i].startsWith("http") ? lines[i] : "https://" + lines[i];
    let r;
    if (backendResults && backendResults[i]) {
      r = backendResults[i];
    } else {
      const browser = browserPredict(url);
      r = {
        url,
        verdict: browser.verdict,
        risk_score: browser.risk_score,
        ml_score: null,
      };
    }
    bulkResultsCache.push(r);
    saveLocalHistory(r);

    const row = document.createElement("div");
    row.className = "bulk-result-row";
    row.innerHTML = `
      <span class="verdict-pill ${r.verdict}">${r.verdict === "phishing" ? "🚨" : r.verdict === "legitimate" ? "✅" : "⚠"} ${r.verdict}</span>
      <span class="br-url" title="${r.url}">${r.url}</span>
      ${r.ml_score !== null ? `<span class="br-rf">RF: ${r.ml_score}%</span>` : ""}
      <span class="br-ens" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
    `;
    rowsEl.appendChild(row);
    await delay(60);
  }

  setProgress(false);
  btn.disabled = false;
  btn.innerHTML = "⚡ SCAN ALL";
  fetchStats();
}

function exportBulkCsv() {
  if (!bulkResultsCache.length) return;
  const csv =
    "URL,Verdict,Risk Score,ML Score\n" +
    bulkResultsCache
      .map((r) => `"${r.url}",${r.verdict},${r.risk_score},${r.ml_score ?? ""}`)
      .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-bulk.csv";
  a.click();
}

// ═══════════════════════════════════════════════════
//  HISTORY
// ═══════════════════════════════════════════════════
function setupHistoryEvents() {
  document
    .getElementById("refreshHistoryBtn")
    .addEventListener("click", loadHistory);
  document
    .getElementById("clearHistoryBtn")
    .addEventListener("click", async () => {
      if (!confirm("Clear all history from database?")) return;
      localStorage.removeItem("cs_hist");
      localStorage.removeItem("cs_local_stats");
      fetchStats();
      loadHistory();
    });
  document
    .getElementById("exportHistoryBtn")
    .addEventListener("click", exportHistoryCsv);
  document
    .getElementById("historySearch")
    .addEventListener("input", renderHistoryList);
  document
    .getElementById("historyFilter")
    .addEventListener("change", renderHistoryList);
}

async function loadHistory() {
  historyData = [];
  // Try backend
  try {
    const r = await fetch(`${API}/history?limit=100`, {
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) {
      const d = await r.json();
      historyData = d.history;
    }
  } catch {}
  // Merge local
  const local = JSON.parse(localStorage.getItem("cs_hist") || "[]");
  if (!historyData.length) historyData = local;
  renderHistoryList();
}

function renderHistoryList() {
  const q = document.getElementById("historySearch").value.toLowerCase();
  const filter = document.getElementById("historyFilter").value;
  const filtered = historyData.filter((r) => {
    if (filter && r.verdict !== filter) return false;
    if (q && !r.url.toLowerCase().includes(q)) return false;
    return true;
  });

  const el = document.getElementById("historyList");
  if (!filtered.length) {
    el.innerHTML = `<div class="empty-state">No records found</div>`;
    return;
  }

  el.innerHTML = filtered
    .map((r) => {
      const time = r.created_at
        ? new Date(r.created_at).toLocaleString()
        : r.time
          ? new Date(r.time).toLocaleString()
          : "—";
      return `<div class="history-row">
      <span class="verdict-pill ${r.verdict}">${r.verdict}</span>
      <span class="hr-url" title="${r.url}">${r.url}</span>
      <span class="hr-score" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
      <span class="hr-time">${time}</span>
    </div>`;
    })
    .join("");
}

function exportHistoryCsv() {
  const csv =
    "URL,Verdict,Risk Score,Timestamp\n" +
    historyData
      .map(
        (r) =>
          `"${r.url}",${r.verdict},${r.risk_score},${r.created_at || r.time || ""}`,
      )
      .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "cybersentinel-history.csv";
  a.click();
}

// ═══════════════════════════════════════════════════
//  MODEL PAGE
// ═══════════════════════════════════════════════════
async function renderModelPage() {
  try {
    const r = await fetch(`${API}/model-info`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      const models = data.models || [];
      const rf = models.find((m) => m.name.includes("Forest"));
      const lr = models.find((m) => m.name.includes("Logistic"));
      if (rf) {
        document.getElementById("rfAcc").textContent =
          (rf.accuracy * 100).toFixed(2) + "%";
        document.getElementById("rfF1").textContent = rf.f1.toFixed(4);
      }
      if (lr) {
        document.getElementById("lrAcc").textContent =
          (lr.accuracy * 100).toFixed(2) + "%";
        document.getElementById("lrF1").textContent = lr.f1.toFixed(4);
      }
      if (data.features?.length) {
        document.getElementById("featuresGrid").innerHTML = data.features
          .map((f) => `<div class="feat-tag">${f}</div>`)
          .join("");
      }
    }
  } catch {
    // Use local weights
    if (MODEL_WEIGHTS) {
      document.getElementById("lrAcc").textContent =
        (MODEL_WEIGHTS.accuracy * 100).toFixed(2) + "%";
      document.getElementById("lrF1").textContent = MODEL_WEIGHTS.f1.toFixed(4);
      document.getElementById("featuresGrid").innerHTML =
        MODEL_WEIGHTS.feature_names
          .map((f) => `<div class="feat-tag">${f}</div>`)
          .join("");
    }
  }
}

// ═══════════════════════════════════════════════════
//  ANALYTICS
// ═══════════════════════════════════════════════════
async function loadAnalytics() {
  try {
    const r = await fetch(`${API}/stats`, {
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      const data = await r.json();
      renderDonut(data.distribution || {});
      renderBarChart(data);
    }
  } catch {
    const local = JSON.parse(localStorage.getItem("cs_local_stats") || "{}");
    renderDonut({
      phishing: local.phishing || 0,
      legitimate: local.legitimate || 0,
      suspicious: local.suspicious || 0,
    });
  }
  renderFeedList();
}

function renderDonut(dist) {
  const canvas = document.getElementById("donutChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  if (total === 0) {
    ctx.clearRect(0, 0, 200, 200);
    return;
  }

  const colors = {
    phishing: "#ff3355",
    legitimate: "#00ff9d",
    suspicious: "#ff9500",
  };
  const labels = Object.keys(dist);
  let startAngle = -Math.PI / 2;
  ctx.clearRect(0, 0, 200, 200);

  labels.forEach((label) => {
    const slice = (dist[label] / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(100, 100);
    ctx.arc(100, 100, 80, startAngle, startAngle + slice);
    ctx.fillStyle = colors[label] || "#5a7a96";
    ctx.fill();
    startAngle += slice;
  });

  // Hole
  ctx.beginPath();
  ctx.arc(100, 100, 50, 0, 2 * Math.PI);
  ctx.fillStyle = "#0f1720";
  ctx.fill();

  // Legend
  document.getElementById("donutLegend").innerHTML = labels
    .map(
      (l) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${colors[l] || "#5a7a96"}"></div>
      <span>${l}: ${dist[l]}</span>
    </div>
  `,
    )
    .join("");
}

function renderBarChart(data) {
  const wrap = document.getElementById("barChartWrap");
  const ranges = [
    { label: "0-20", key: "low", color: "var(--green)" },
    { label: "21-40", key: "med-low", color: "#a0e080" },
    { label: "41-60", key: "med", color: "var(--orange)" },
    { label: "61-80", key: "med-high", color: "#ff6633" },
    { label: "81-100", key: "high", color: "var(--red)" },
  ];
  const dist = data.distribution || {};
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  if (total === 0) return;

  wrap.innerHTML = ranges
    .map((r) => {
      // approximate distribution from verdict counts
      const pct =
        r.key === "low"
          ? Math.round(((dist.legitimate || 0) / total) * 100)
          : r.key === "high"
            ? Math.round(((dist.phishing || 0) / total) * 100)
            : r.key === "med"
              ? Math.round(((dist.suspicious || 0) / total) * 40)
              : 5;
      return `<div class="bar-chart-row">
      <span class="bcr-label">${r.label}</span>
      <div class="bcr-bar-wrap">
        <div class="bcr-bar" style="width:${pct}%;background:${r.color};">${pct > 5 ? pct + "%" : ""}</div>
      </div>
      <span class="bcr-val">${pct}%</span>
    </div>`;
    })
    .join("");
}

function renderFeedList() {
  const local = JSON.parse(localStorage.getItem("cs_hist") || "[]").slice(
    0,
    20,
  );
  const el = document.getElementById("feedList");
  if (!local.length) {
    el.innerHTML = `<div class="empty-state">No scan data yet</div>`;
    return;
  }
  el.innerHTML = local
    .map(
      (r) => `
    <div class="feed-row">
      <div class="feed-dot" style="background:${r.verdict === "phishing" ? "var(--red)" : r.verdict === "suspicious" ? "var(--orange)" : "var(--green)"};box-shadow:0 0 6px ${r.verdict === "phishing" ? "var(--red)" : r.verdict === "suspicious" ? "var(--orange)" : "var(--green)"}"></div>
      <span class="feed-time">${r.time ? new Date(r.time).toLocaleTimeString() : "—"}</span>
      <span class="feed-url">${r.url}</span>
      <span class="verdict-pill ${r.verdict}" style="font-size:0.62rem;">${r.verdict}</span>
      <span class="feed-score" style="color:${r.risk_score >= 60 ? "var(--red)" : r.risk_score >= 30 ? "var(--orange)" : "var(--green)"};">${r.risk_score}/100</span>
    </div>
  `,
    )
    .join("");
}

// ═══════════════════════════════════════════════════
//  LIVE FEED ANIMATION (threat ticker page)
// ═══════════════════════════════════════════════════
function startFeedAnimation() {
  // Continuous demo feed for when no real data exists — updates every 4s
}

// ═══════════════════════════════════════════════════
//  URL PARAM — auto-scan from share link
// ═══════════════════════════════════════════════════
const urlParams = new URLSearchParams(window.location.search);
const autoScan = urlParams.get("scan");
if (autoScan) {
  setTimeout(() => {
    document.getElementById("urlInput").value = autoScan;
    triggerScan();
  }, 800);
}
