"use strict";

/* =====================================================================
   SafeCheck AI: front-end prototype
   All checks run in the browser. Nothing is sent to a server or stored.
   Sections:  1 data  |  2 rules  |  3 analyze()  |  4 draft  |  5 UI
   ===================================================================== */

const $ = (id) => document.getElementById(id);

/* ---------- 1. DATA: platforms, reporting steps, labels ---------- */

const PLATFORMS = {
  instagram: {
    name: "Instagram",
    steps: [
      "Open the profile and tap the three dots at the top right.",
      "Tap Report and choose the reason closest to scam, fraud or pretending to be someone else.",
      "Follow the prompts, then block the account once your evidence is saved."
    ]
  },
  facebook: {
    name: "Facebook",
    steps: [
      "Open the profile and tap the three dots under the cover photo.",
      "Choose Find support or report profile, then pick fake account, scam or harassment.",
      "Submit the report and block the profile."
    ]
  },
  whatsapp: {
    name: "WhatsApp",
    steps: [
      "Open the chat and tap the contact's name at the top.",
      "Scroll down and tap Report, then choose to also block the contact.",
      "Do not click links or send money, OTPs or photos."
    ]
  },
  telegram: {
    name: "Telegram",
    steps: [
      "Open the chat and tap the contact's name or the three dots.",
      "Tap Report and choose the reason closest to scam or fake account.",
      "Block the account after saving your evidence."
    ]
  },
  snapchat: {
    name: "Snapchat",
    steps: [
      "Press and hold the person's name or Snap, or open their profile.",
      "Tap Report and choose the reason that fits.",
      "Block the account afterwards."
    ]
  },
  x: {
    name: "X (Twitter)",
    steps: [
      "Open the profile and tap the three dots.",
      "Tap Report and choose the reason closest to spam, scam or impersonation.",
      "Block the account after you have saved your evidence."
    ]
  },
  linkedin: {
    name: "LinkedIn",
    steps: [
      "Open the profile and tap the More or three-dots button.",
      "Choose Report / Block and pick fake profile or scam.",
      "Do not share documents, bank details or pay any 'registration fee'."
    ]
  },
  dating: {
    name: "Dating app",
    steps: [
      "Open the profile and use the Report, flag or three-dots option.",
      "Pick the reason closest to fake profile, scam or harassment, then unmatch and block.",
      "Do not move to another app or send money, however convincing the story."
    ]
  },
  matrimonial: {
    name: "Matrimonial site",
    steps: [
      "Use the Report profile option on the profile, or write to the site's support team.",
      "Share the profile ID and your screenshots with them.",
      "Never transfer money, gold or 'customs fees' before you have met the person and their family."
    ]
  },
  other: {
    name: "Other platform",
    steps: [
      "Look for a Report, Flag or Help option on the profile or in the app's help centre.",
      "Describe the warning signs and attach your screenshots.",
      "Block the account after your evidence is saved."
    ]
  }
};

const COMMON_STEPS = [
  "Take screenshots of the profile, the chat and any payment details before you block or report.",
  "Do not delete the chat. Keep it as evidence.",
  "Report the profile on the platform using the steps above.",
  "File a complaint on cybercrime.gov.in. Your report draft below can be pasted into it.",
  "If you lost money, call 1930 straight away. Reporting quickly gives the best chance of stopping the transfer."
];

const AGE_LABELS = {
  unknown: "Not known",
  lt7: "Less than 1 week",
  "7to30": "1 week to 1 month",
  "30to90": "1 to 3 months",
  "90to365": "3 months to 1 year",
  gt365: "More than 1 year"
};

const LEVEL_TEXT = {
  HIGH: "Several strong warning signs. Do not send money, photos or personal details to this person.",
  MEDIUM: "Some warning signs. Verify this person properly before you trust them.",
  LOW: "Few warning signs in what you entered. This does not prove the profile is real."
};

/* ---------- 2. RULES: add or tune rules here ----------
   points   = how much the signal adds to the warning score
   critical = forces the result to HIGH on its own
   pattern  = regular expression, matched against lower-case text
   Hinglish phrases (paise, kharab, dahej...) are included. */

const AGE_RULES = {
  lt7:     { points: 25, title: "Account is less than a week old", why: "Scam and fake accounts are cheap to create and are often replaced quickly." },
  "7to30": { points: 15, title: "Account is under a month old", why: "Very new accounts are more likely to be fake or made for a scam." },
  "30to90":{ points: 5,  title: "Account is only a few months old", why: "A young account is a small warning sign on its own." }
};

const HANDLE_RULES = [
  { points: 10, title: "Username has many digits",
    why: "Auto-generated or throwaway usernames often end in long number strings.",
    test: (h) => (h.match(/\d/g) || []).length >= 4 && !/^\+?\d+$/.test(h) },
  { points: 10, title: "Username claims to be official or verified",
    why: "Fake accounts often add words like official, real, support or verified to look trustworthy.",
    test: (h) => /official|real|verified|support|care|admin|helpdesk/.test(h) }
];

const BIO_RULES = [
  { points: 15, title: "Bio pushes you to contact them elsewhere or to make money",
    why: "Phone numbers, 'DM for...' lines and talk of investments or easy earning are common in scam profiles.",
    pattern: /(?:\+?91[\s-]?)?[6-9]\d{9}\b|\b(?:dm|inbox)\s+(?:me\s+)?for\b|\b(?:whatsapp|telegram)\b|\b(?:crypto|forex|investment|earn|loan)\b/gi },
  { points: 5, title: "Bio uses a backstory common in romance scams",
    why: "Living abroad or having a hard-to-verify job (army, pilot, oil rig) is a frequent cover story.",
    pattern: /\b(?:nri|abroad|usa|dubai|canada|surgeon|army officer|navy|pilot|oil rig)\b/gi }
];

const MESSAGE_RULES = [
  { points: 30, title: "Asks for money or a payment",
    why: "Requests for money, gift cards, UPI transfers or 'fees' are the most common sign of a scam.",
    pattern: /\b(?:send money|need money|transfer|gift ?card|western union|paytm|gpay|google pay|phonepe|upi|bank details|payment|fees?|paise|paisa|loan)\b/gi },
  { points: 30, critical: true, title: "Threatens to leak or share your content",
    why: "Threats to leak photos or messages are blackmail. This is a crime. Do not pay and do not delete the chat.",
    pattern: /\b(?:i\s+will|i'll|i am going to|gonna)\s+(?:leak|post|expose|share|upload)\b|\bleak\s+your\b|\bviral\s+kar\b|\bblackmail\b|\bexpose\s+you\b/gi },
  { points: 15, title: "Asks for your photos",
    why: "Scammers collect photos to build trust or to use them for blackmail later.",
    pattern: /\b(?:send|share|show)\s+(?:me\s+)?(?:your\s+)?(?:private\s+|nude\s+|hot\s+)?(?:photos?|pics?|pictures?|selfies?)\b|\bnudes?\b|\bpic\s+bhej\b|\bphoto\s+bhej\b/gi },
  { points: 15, title: "Asks you to keep it secret",
    why: "Secrecy stops friends and family from spotting the scam or the pressure.",
    pattern: /don't tell (?:anyone|your (?:family|parents|friends))|dont tell anyone|keep (?:this|it) (?:a )?secret|between us|kisi ko mat batana/gi },
  { points: 15, title: "Mentions prizes, jobs or guaranteed returns",
    why: "Lotteries, 'work from home' offers and guaranteed income are classic fraud hooks.",
    pattern: /\b(?:lottery|you (?:have )?won|winner|prize|guaranteed (?:job|income|returns?)|registration fee|work from home|double your|investment|crypto|forex)\b/gi },
  { points: 10, title: "Creates urgency",
    why: "Pressure to act immediately leaves you no time to think or check.",
    pattern: /\b(?:urgent(?:ly)?|emergency|immediately|right now|asap|hurry|last chance|jaldi)\b/gi },
  { points: 10, title: "Avoids video calls",
    why: "Fake profiles avoid live video because the face would not match the photos.",
    pattern: /\b(?:can't|cannot|won't|unable to)\s+(?:do\s+|have\s+|take\s+)?(?:a\s+)?video\s*call\b|\bcamera\s+(?:is\s+)?(?:broken|not working|kharab)\b|\bvideo\s*call\s+nahi\b/gi },
  { points: 10, title: "Wants to move the chat to another app", skipPlatforms: ["whatsapp", "telegram"],
    why: "Scammers move chats to private apps where the platform cannot see or stop them.",
    pattern: /\b(?:whatsapp|telegram|signal)\b|\btext me on\b|\badd me on\b/gi },
  { points: 10, title: "Contains a link",
    why: "Links in unexpected messages can lead to phishing or fake payment pages. Do not open them.",
    pattern: /https?:\/\/\S+|\b(?:bit\.ly|tinyurl\.com|t\.me|wa\.me)\/\S+/gi },
  { points: 10, title: "Very fast, intense affection",
    why: "Love-bombing builds emotional pressure quickly so you drop your guard.",
    pattern: /\b(?:soulmate|love at first sight|can't live without you|never felt this way|meant to be|you are my everything)\b/gi },
  { points: 10, title: "Marriage or dowry pressure",
    why: "Rushing into marriage, or raising dowry or jewellery, is a red flag on matrimonial and dating platforms.",
    pattern: /\b(?:dowry|dahej|marry me (?:now|soon)|shaadi jaldi|jewell?ery)\b/gi }
];

/* ---------- 3. ANALYZE: turns the form values into a result ---------- */

function extractHandle(raw) {
  let s = (raw || "").trim();
  if (!s) return "";
  const looksLikeUrl = /^https?:\/\//i.test(s) || /^[\w.-]+\.[a-z]{2,}\//i.test(s);
  if (looksLikeUrl) {
    try {
      const u = new URL(/^https?:\/\//i.test(s) ? s : "https://" + s);
      const parts = u.pathname.split("/").filter(Boolean);
      s = parts.length ? parts[parts.length - 1] : u.hostname;
    } catch (e) { /* keep s as typed */ }
  }
  return s.replace(/^@/, "").split(/[?#]/)[0].toLowerCase();
}

function uniqueMatches(text, pattern) {
  const found = text.match(pattern);
  if (!found) return null;
  return [...new Set(found.map((m) => m.trim().toLowerCase()))].slice(0, 3);
}

function analyze(input) {
  const handle = extractHandle(input.profile);
  const bio = (input.bio || "").replace(/[’‘]/g, "'");
  const message = (input.message || "").replace(/[’‘]/g, "'");
  const signals = [];
  let score = 0;
  let critical = false;

  const add = (source, rule, matched) => {
    signals.push({ source, title: rule.title, why: rule.why, matched: matched || null });
    score += rule.points;
    if (rule.critical) critical = true;
  };

  const ageRule = AGE_RULES[input.age];
  if (ageRule) add("Profile", ageRule);

  if (handle) {
    HANDLE_RULES.forEach((r) => { if (r.test(handle)) add("Profile", r, [handle]); });
  }
  BIO_RULES.forEach((r) => {
    const m = uniqueMatches(bio, r.pattern);
    if (m) add("Bio", r, m);
  });
  MESSAGE_RULES.forEach((r) => {
    if (r.skipPlatforms && r.skipPlatforms.includes(input.platform)) return;
    const m = uniqueMatches(message, r.pattern);
    if (m) add("Message", r, m);
  });

  score = Math.min(score, 100);
  let level = score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
  if (critical) level = "HIGH";
  return { level, score, signals, handle };
}

/* ---------- 4. REPORT DRAFT: built only from the user's own facts ---------- */

function buildDraft(input, result) {
  const when = new Date().toLocaleString("en-IN");
  const platform = PLATFORMS[input.platform] ? PLATFORMS[input.platform].name : "Not given";
  const lines = [];
  lines.push("To,");
  lines.push("The Officer, Cyber Crime Cell");
  lines.push("(National Cyber Crime Reporting Portal: cybercrime.gov.in)");
  lines.push("");
  lines.push("Subject: Complaint about a suspected fake or fraudulent profile");
  lines.push("");
  lines.push("Respected Sir/Madam,");
  lines.push("");
  lines.push("I wish to report a suspected fake or fraudulent profile.");
  lines.push("");
  lines.push("Platform: " + platform);
  lines.push("Profile username / link: " + (input.profile.trim() || "Not given"));
  lines.push("Account age (as seen by me): " + (AGE_LABELS[input.age] || "Not known"));
  if (input.bio.trim()) lines.push('Bio: "' + input.bio.trim() + '"');
  lines.push("Date and time of this note: " + when);
  lines.push("");
  lines.push("Warning signs I noticed:");
  if (result.signals.length) {
    result.signals.forEach((s, i) => lines.push((i + 1) + ". " + s.title));
  } else {
    lines.push("1. [Describe what made you suspicious]");
  }
  if (input.message.trim()) {
    const msg = input.message.trim();
    lines.push("");
    lines.push("Message I received:");
    lines.push('"' + (msg.length > 600 ? msg.slice(0, 600) + " [...]" : msg) + '"');
  }
  lines.push("");
  lines.push("[If you lost money, add the amount, date, transaction ID and UPI/bank details here.]");
  lines.push("");
  lines.push("Screenshots of the profile and chat are attached.");
  lines.push("This note is my own preliminary assessment, not proof. I request you to look into this and take appropriate action.");
  lines.push("");
  lines.push("Name: [Your name]");
  lines.push("Contact: [Your phone number / email]");
  return lines.join("\n");
}

/* ---------- 5. UI: wires everything to the page ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function readForm() {
  return {
    platform: $("platform").value,
    profile: $("profile").value,
    bio: $("bio").value,
    age: $("age").value,
    message: $("message").value
  };
}

let generatedDraft = "";
let previewUrl = null;

function renderResult(result, input) {
  $("result").className = "result card " + result.level.toLowerCase();
  $("levelBadge").textContent = result.level + " RISK";
  $("levelText").textContent = LEVEL_TEXT[result.level];

  const n = result.signals.length;
  $("signalCount").textContent = n === 0
    ? "No warning signs found in what you entered."
    : n + (n === 1 ? " warning sign found." : " warning signs found.");

  const list = $("signalList");
  list.replaceChildren();
  if (n === 0) {
    list.appendChild(el("li", "", "Nothing flagged. Stay careful with people you have not met, and check the photo yourself with a reverse image search."));
  }
  result.signals.forEach((s) => {
    const li = el("li");
    const head = el("div", "sig-head");
    head.append(el("strong", "", s.title), el("span", "tag", s.source));
    li.append(head, el("p", "", s.why));
    if (s.matched && s.matched.length) {
      li.appendChild(el("p", "found", "Found: " + s.matched.map((m) => "\u201C" + m + "\u201D").join(", ")));
    }
    list.appendChild(li);
  });

  // Reporting steps
  const platform = PLATFORMS[input.platform] || PLATFORMS.other;
  $("platformHeading").textContent = "On " + platform.name;
  const steps = $("platformSteps");
  steps.replaceChildren();
  platform.steps.forEach((t) => steps.appendChild(el("li", "", t)));
  const common = $("commonSteps");
  common.replaceChildren();
  COMMON_STEPS.forEach((t) => common.appendChild(el("li", "", t)));

  // Draft
  generatedDraft = buildDraft(input, result);
  $("draft").value = generatedDraft;
  $("copyStatus").textContent = "";

  $("results").hidden = false;
  $("resultTitle").focus();
  $("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showFormError(message) {
  const box = $("formError");
  box.textContent = message;
  box.hidden = !message;
}

function onSubmit(event) {
  event.preventDefault();
  const input = readForm();
  if (!input.profile.trim()) {
    showFormError("Please enter the username or profile link.");
    $("profile").focus();
    return;
  }
  showFormError("");
  renderResult(analyze(input), input);
}

/* Screenshot: preview only. Never uploaded or stored. */
function clearPreview() {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  $("shot").value = "";
  $("shotImg").removeAttribute("src");
  $("shotPreview").hidden = true;
}

function onShotChange() {
  const file = $("shot").files[0];
  const err = $("shotError");
  err.hidden = true;
  if (!file) { clearPreview(); return; }
  if (!file.type.startsWith("image/")) {
    clearPreview();
    err.textContent = "Please choose an image file.";
    err.hidden = false;
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    clearPreview();
    err.textContent = "That image is larger than 10 MB. Please choose a smaller one.";
    err.hidden = false;
    return;
  }
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file);
  $("shotImg").src = previewUrl;
  $("shotName").textContent = file.name;
  $("shotPreview").hidden = false;
}

/* Draft buttons */
async function copyDraft() {
  const box = $("draft");
  try {
    await navigator.clipboard.writeText(box.value);
  } catch (e) {
    box.select();
    document.execCommand("copy");
  }
  $("copyStatus").textContent = "Copied to clipboard.";
}

function downloadDraft() {
  const blob = new Blob([$("draft").value], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "safecheck-report-draft.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  $("copyStatus").textContent = "Draft downloaded.";
}

function resetDraft() {
  $("draft").value = generatedDraft;
  $("copyStatus").textContent = "Draft reset.";
}

/* Demo helper: fills the form with a made-up scam so you can show the tool quickly */
function fillExample() {
  $("platform").value = "instagram";
  $("profile").value = "@priya_official_88231";
  $("bio").value = "Doctor in Dubai. DM for investment tips.";
  $("age").value = "lt7";
  $("message").value =
    "Hi dear, you are my soulmate. I have an emergency, please send money by UPI today. " +
    "My camera is broken so no video call. Don't tell anyone. Otherwise I will leak your photos.";
  showFormError("");
}

function init() {
  const select = $("platform");
  Object.keys(PLATFORMS).forEach((key) => {
    const opt = el("option", "", PLATFORMS[key].name);
    opt.value = key;
    select.appendChild(opt);
  });

  $("checkForm").addEventListener("submit", onSubmit);
  $("checkForm").addEventListener("reset", () => {
    clearPreview();
    showFormError("");
    $("shotError").hidden = true;
    $("results").hidden = true;
  });
  $("shot").addEventListener("change", onShotChange);
  $("shotRemove").addEventListener("click", clearPreview);
  $("example").addEventListener("click", fillExample);
  $("copy").addEventListener("click", copyDraft);
  $("download").addEventListener("click", downloadDraft);
  $("resetDraft").addEventListener("click", resetDraft);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyze, extractHandle, buildDraft };  // for quick tests in Node
} else {
  init();
}
