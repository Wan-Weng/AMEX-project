// ✅ Quick sanity log (you should see this in DevTools Console)
console.log("Scam Guard injected on:", window.location.href);

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// ✅ Your improved scoring function (from your file)
function computeRisk(url, text) {
  let score = 0;
  const reasons = [];

  const lowerText = (text || "").toLowerCase();
  const lowerUrl = (url || "").toLowerCase();

  // --- Signals ---
  const hasPasswordField = !!document.querySelector('input[type="password"]');
  const isHttps = (() => {
    try { return new URL(url).protocol === "https:"; } catch { return false; }
  })();

  // Suspicious content signals
  const urgency = /(account|payment|profile).{0,30}(suspended|locked|restricted|expiring)/.test(lowerText);  const paymentPressure = /(send|pay|transfer|buy).{0,20}(gift card|bitcoin|crypto|wire|fee)/.test(lowerText);  const sensitiveIdentity = /(enter|provide|submit|confirm|verify).{0,20}(ssn|social security|routing number|bank account|cvv|credit card)/.test(lowerText);
  // Suspicious URL signals
  const suspiciousUrl = /verify|secure-login|update-account|confirm/.test(lowerUrl);
  // Legitimacy signals (reduce false positives)
  const hasPolicyLinks = /privacy|terms of service|terms & conditions/.test(lowerText);
  const looksLikeNormalAuth = /sign in|log in|create account|forgot password/.test(lowerText);

  // --- Base scoring (suspicious signals) ---
  let suspiciousCount = 0;

  if (urgency) {
    score += 20;
    reasons.push("Urgency/threat language detected");
    suspiciousCount++;
  }
  if (paymentPressure) {
    score += 30;
    reasons.push("Payment pressure / unusual payment method detected");
    suspiciousCount++;
  }
  if (sensitiveIdentity) {
    score += 35;
    reasons.push("Requests highly sensitive identity/financial info (SSN/bank/card)");
    suspiciousCount++;
  }
  if (suspiciousUrl) {
    score += 15;
    reasons.push("Suspicious wording in URL path");
    suspiciousCount++;
  }

  // --- Password field logic (conditional) ---
  // Only treat a password field as high risk if other suspicious signals exist.
  if (hasPasswordField) {
    if (suspiciousCount >= 1) {
      score += 25;
      reasons.push("Password field present along with other suspicious signals");
    } else {
      // Normal login pages shouldn't be heavily penalized.
      score += 5;
      reasons.push("Login form detected (common on legitimate sites)");
    }
  }

  // --- Reduce score for legitimacy signals ---
  if (isHttps) score -= 10;
  if (hasPolicyLinks) score -= 10;
  if (looksLikeNormalAuth) score -= 5;

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Tier
  let tier = "Safe";
  if (score >= 60) tier = "High Risk";
  else if (score >= 30) tier = "Caution";

  return { score, tier, reasons };
}

function showBanner(score, reasons) {
  // Only show if suspicious (adjust threshold if you want)
  if (score < 0) return;

  // Prevent duplicates
  if (document.getElementById("scam-guard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "scam-guard-banner";

  banner.innerHTML = `
    <strong>Scam Guard Warning</strong><br/>
    Risk Score: ${score}/100
    <ul>${reasons.map(r => `<li>${r}</li>`).join("")}</ul>
    <button id="sg-close" style="margin-top:8px; padding:6px 10px; border-radius:8px; border:none; cursor:pointer;">
      Close
    </button>
  `;

  document.body.appendChild(banner);

  document.getElementById("sg-close").addEventListener("click", () => banner.remove());
}

// Run after page loads
setTimeout(() => {
  const url = window.location.href;
  const text = document.body ? document.body.innerText : "";
  const { score, reasons } = computeRisk(url, text);

  console.log("Scam Guard score:", score, reasons);
  showBanner(score, reasons);
}, 800);