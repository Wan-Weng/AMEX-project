console.log("Scam Guard injected on:", window.location.href);

function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function computeRisk(url, text) {
  let score = 0;
  const reasons = [];

  const lowerText = (text || "").toLowerCase();
  const lowerUrl = (url || "").toLowerCase();
  const hostname = getHostname(url);
  let suspiciousCount = 0;
  // trusted sites
  const trustedDomains = [
    "phishtank.org",
    "google.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "amazon.com",
    "facebook.com",
    "paypal.com",
    "apple.com",
    "netflix.com",
    "ufl.edu"
  ];

  if (trustedDomains.some(d => hostname.endsWith(d))) {
    return {
      score: 0,
      tier: "Safe",
      reasons: ["Trusted domain"]
    };
  }

  // DOM signals
  const hasPasswordField = !!document.querySelector('input[type="password"]');
  const hasEmailField = !!document.querySelector('input[type="email"]');
  const hasForm = !!document.querySelector("form");
  const hasSubmitButton = !!document.querySelector(
    'button, input[type="submit"], input[type="button"]'
  );

  const isHttps = (() => {
    try {
      return new URL(url).protocol === "https:";
    } catch {
      return false;
    }
  })();

  // declare BEFORE using it


  // URL/domain signals
  const riskyTlds = [".xyz", ".top", ".site", ".ru", ".tk", ".ml", ".ga", ".cf"];
  const hasRiskyTld = riskyTlds.some((tld) => hostname.endsWith(tld));
  const suspiciousUrlWords =
    /verify|secure-login|update-account|confirm|billing|suspended|locked|auth|signin|login/.test(lowerUrl);
  const hasAtSymbol = lowerUrl.includes("@");
  const isLongUrl = lowerUrl.length > 90;

  // content signals
  const urgency =
    /(account|payment|profile|identity).{0,30}(suspended|locked|restricted|expiring|disabled)/.test(lowerText) ||
    /(urgent|immediately|act now|verify now)/.test(lowerText);

  const paymentPressure =
    /(send|pay|transfer|buy).{0,20}(gift card|bitcoin|crypto|wire|fee)/.test(lowerText);

  const sensitiveIdentity =
    /(enter|provide|submit|confirm|verify|insira).{0,25}(ssn|social security|routing number|bank account|cvv|credit card|cpf|cnpj)/.test(lowerText) ||
    /\b(cpf|cnpj|ssn|social security|bank account|credit card|cvv)\b/.test(lowerText);

  const accountVerificationFlow =
    /(identifica[cç][aã]o|verification|verify your account|confirm your identity|log in|sign in|entrar)/.test(lowerText);

  const thirdPartyLoginReference =
    /(facebook|google|apple|paypal)/.test(lowerText);

  const hasPolicyLinks =
    /privacy|pol[ií]tica de privacidade|terms of service|terms & conditions/.test(lowerText);

  const looksLikeNormalAuth =
    /sign in|log in|create account|forgot password|forgot your password/.test(lowerText);

  // first: score base suspicious signals
  if (hasRiskyTld) {
    score += 15;
    reasons.push("Uses a higher-risk domain extension");
    suspiciousCount++;
  }

  if (suspiciousUrlWords) {
    score += 12;
    reasons.push("Suspicious wording detected in the URL");
    suspiciousCount++;
  }

  if (hasAtSymbol) {
    score += 20;
    reasons.push("URL contains an @ symbol");
    suspiciousCount++;
  }

  if (isLongUrl) {
    score += 5;
    reasons.push("URL is unusually long");
    suspiciousCount++;
  }

  if (urgency) {
    score += 20;
    reasons.push("Urgency or threat language detected");
    suspiciousCount++;
  }

  if (paymentPressure) {
    score += 30;
    reasons.push("Payment pressure or unusual payment method detected");
    suspiciousCount++;
  }

  if (sensitiveIdentity) {
    score += 25;
    reasons.push("Requests sensitive personal or financial information");
    suspiciousCount++;
  }

  // brand mismatch should happen AFTER suspiciousCount exists and after some signals were checked
  const knownBrands = [
    "magalu",
    "amazon",
    "paypal",
    "facebook",
    "google",
    "netflix",
    "apple",
    "bank of america",
    "chase",
    "wells fargo"
  ];

  let mismatchedBrand = null;
  for (const brand of knownBrands) {
    const normalizedBrand = brand.replace(/\s+/g, "");
    if (
      lowerText.includes(brand) &&
      !hostname.includes(normalizedBrand) &&
      suspiciousCount >= 1
    ) {
      mismatchedBrand = brand;
      break;
    }
  }

  if (accountVerificationFlow && suspiciousCount >= 1) {
    score += 8;
    reasons.push("Account verification flow combined with other suspicious signals");
  }

  if (mismatchedBrand) {
    score += 25;
    reasons.push(`Possible impersonation of ${mismatchedBrand}`);
  }

  if (
    thirdPartyLoginReference &&
    suspiciousCount >= 2 &&
    !hostname.includes("facebook.com") &&
    !hostname.includes("google.com") &&
    !hostname.includes("apple.com") &&
    !hostname.includes("paypal.com")
  ) {
    score += 6;
    reasons.push("Third-party login used on a suspicious page");
  }

  if (hasPasswordField) {
    if (suspiciousCount >= 1) {
      score += 25;
      reasons.push("Password field present along with other suspicious signals");
    } else {
      score += 5;
      reasons.push("Login form detected");
    }
  }

  if (!hasPasswordField && (hasEmailField || hasForm || hasSubmitButton) && suspiciousCount >= 2) {
    score += 10;
    reasons.push("Form or credential capture elements detected on a suspicious page");
  }

  const collectingInput =
    hasPasswordField ||
    hasEmailField ||
    sensitiveIdentity ||
    hasForm;

  if (!collectingInput) {
    score -= 15;
    reasons.push("No credential or sensitive input fields detected");
  }

  if (isHttps) score -= 8;
  if (hasPolicyLinks) score -= 8;
  if (looksLikeNormalAuth && suspiciousCount === 0) score -= 5;

  score = Math.max(0, Math.min(100, score));

  let tier = "Safe";
  if (score >= 80) tier = "Dangerous";
  else if (score >= 60) tier = "High Risk";
  else if (score >= 30) tier = "Caution";

  return { score, tier, reasons };
}

function showBanner(score, tier, reasons) {
  
  if (document.getElementById("scam-guard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "scam-guard-banner";

  let tierClass = "sg-safe";
  let icon = "✅";

  if (tier === "Caution") {
    tierClass = "sg-caution";
    icon = "⚠️";
  } else if (tier === "High Risk") {
    tierClass = "sg-high-risk";
    icon = "🚨";
  } else if (tier === "Dangerous") {
    tierClass = "sg-dangerous";
    icon = "⛔";
  }

  banner.className = tierClass;

  banner.innerHTML = `
    <div class="sg-header">
      <div class="sg-header-top">
        <div class="sg-header-left">
          <div class="sg-icon-box">${icon}</div>

          <div>
            <div class="sg-title">Scam Guard</div>
            <div class="sg-subtitle">Page safety analysis</div>
          </div>
        </div>

        <div class="sg-actions">
          <button id="sg-minimize" class="sg-icon-btn">−</button>
          <button id="sg-close" class="sg-icon-btn">✕</button>
        </div>
      </div>

      <div class="sg-status-row">
        <span class="sg-badge">${tier}</span>
        <div class="sg-score">
          Risk Score:
          <span class="sg-score-value">${score}/100</span>
        </div>
      </div>

      <div class="sg-progress">
        <div class="sg-progress-track">
          <div class="sg-progress-fill" style="width: ${score}%"></div>
        </div>
      </div>
    </div>

    <div id="sg-body" class="sg-body">
      <div class="sg-body-label">Why this page was flagged:</div>

      <div class="sg-reasons">
        ${
          reasons.length
            ? reasons
                .map(
                  (r) => `
              <div class="sg-reason-card">
                <div class="sg-reason-dot"></div>
                <div class="sg-reason-text">${r}</div>
              </div>
            `
                )
                .join("")
            : `
              <div class="sg-empty">
                No major suspicious signals were detected.
              </div>
            `
        }
      </div>
    </div>
  `;

  document.body.appendChild(banner);

  requestAnimationFrame(() => {
    banner.classList.add("sg-show");
  });

  const closeBtn = document.getElementById("sg-close");
  const minimizeBtn = document.getElementById("sg-minimize");
  const body = document.getElementById("sg-body");

  closeBtn.addEventListener("click", () => banner.remove());

  let minimized = false;
  minimizeBtn.addEventListener("click", () => {
    minimized = !minimized;
    body.style.display = minimized ? "none" : "block";
    minimizeBtn.textContent = minimized ? "+" : "−";
  });
}

// Run after page loads
setTimeout(() => {
  const url = window.location.href;
  const text = document.body ? document.body.innerText : "";
  const { score, tier, reasons } = computeRisk(url, text);

  console.log("Scam Guard score:", score, tier, reasons);
  showBanner(score, tier, reasons);
}, 800);