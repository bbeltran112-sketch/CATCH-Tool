// ══════════════════════════════════════════════════════════════════════════════
// SECURITY LAYER — Feature 1: XSS Fix · 2: PII Scrubber · 3: Session-Only
//                  Feature 4: Inactivity Auto-Clear · 5: Export Warning
//                  Feature 6: History TTL (7-day auto-expire)
// ══════════════════════════════════════════════════════════════════════════════

// ── Feature 1: HTML escaping helper (XSS prevention) ─────────────────────────
// All user-supplied data rendered via innerHTML must go through escHtml().
// The existing esc() in the library editor is extended here for global use.
function escHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function hasMojibake(str) {
  return /[ÃÂâï]/.test(String(str || ''));
}

function removeDuplicateIdNodes(id) {
  var nodes = Array.prototype.slice.call(document.querySelectorAll('#' + id));
  if (nodes.length < 2) return;
  var keep = nodes.find(function(node) {
    return !hasMojibake(node.textContent) &&
      !hasMojibake(node.getAttribute('placeholder')) &&
      !hasMojibake(node.getAttribute('title'));
  }) || nodes[0];
  nodes.forEach(function(node) {
    if (node !== keep) node.remove();
  });
}

function removeCorruptedAdjacentDuplicates(selector) {
  Array.prototype.slice.call(document.querySelectorAll(selector)).forEach(function(node) {
    var next = node.nextElementSibling;
    if (!next) return;
    if (next.tagName !== node.tagName) return;
    if ((next.id || '') !== (node.id || '')) return;
    if (!hasMojibake(next.textContent) &&
        !hasMojibake(next.getAttribute('placeholder')) &&
        !hasMojibake(next.getAttribute('title'))) return;
    next.remove();
  });
}

function setNodeText(selector, value) {
  var node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function setNodeHtml(selector, value) {
  var node = document.querySelector(selector);
  if (node) node.innerHTML = value;
}

function setNodeAttr(selector, attr, value) {
  var node = document.querySelector(selector);
  if (node) node.setAttribute(attr, value);
}

function normalizeCorruptedUiShell() {
  [
    'settings-btn',
    'settings-cap-badge',
    'envelope-override',
    'run-btn',
    'log-search',
    'catalog-search',
    'history-filter',
    'history-filter-clear',
    'reader-modal-close'
  ].forEach(removeDuplicateIdNodes);

  [
    '#settings-btn',
    '#envelope-override',
    '#run-btn',
    '#log-search',
    '#catalog-search',
    '#reader-modal-close'
  ].forEach(removeCorruptedAdjacentDuplicates);

  document.title = 'CATCH / TX OCA';

  setNodeHtml(
    '#main-title',
    'CATCH / TX OCA <span style="font-size:10px;font-weight:400;color:var(--text3);margin-left:6px;">v3.0</span>'
  );

  Array.prototype.slice.call(document.querySelectorAll('#state-select option')).forEach(function(option) {
    var val = option.value || '';
    if (val === 'TX') option.textContent = 'TX / OCA Community';
    if (val === 'IL') option.textContent = 'IL / AOIC';
  });

  setNodeAttr('#settings-btn', 'title', 'Settings - Schema Manager, Error Log cap, Error Library');
  setNodeHtml('#settings-btn', '&#9881; Settings<span id="settings-cap-badge" style="display:none;background:var(--orange);color:#000;font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;margin-left:2px;"></span>');
  setNodeAttr(
    '#input-area',
    'placeholder',
    [
      'Paste one payload or envelope here...',
      '',
      'Accepts all formats:',
      '',
      '  - Full D&I envelope (Events[].Entities[].EntityData)',
      '  - Simple envelope',
      '  - Array of entities  [ {...}, {...} ]',
      '  - Single entity  { "entityType": "...", "county": "...", ... }',
      '',
      'Validates: entityType, county enum, publisher enum,',
      'required fields, type violations (string vs number|null),',
      'wrong field names, enum violations, and contract mismatches'
    ].join('\n')
  );
  setNodeAttr('#envelope-override', 'placeholder', 'Auto-detected from payload - override here');
  setNodeText('#run-btn', 'Run Validation');
  setNodeAttr('#log-search', 'placeholder', 'Search envelope ID, cause, field, county...');
  setNodeAttr('#catalog-search', 'placeholder', 'Filter by field, message, publisher, entity type...');
  setNodeAttr('#history-filter', 'placeholder', 'Filter by EnvelopeId, publisher, county, or entity type...');
  setNodeText('#history-filter-clear', 'x');
  setNodeText('#reader-modal-close', 'x');

  Array.prototype.slice.call(document.querySelectorAll('[title], [placeholder]')).forEach(function(node) {
    if (hasMojibake(node.getAttribute('title'))) node.removeAttribute('title');
    if (hasMojibake(node.getAttribute('placeholder'))) node.removeAttribute('placeholder');
  });

  Array.prototype.slice.call(document.querySelectorAll('button, span, div, label, option')).forEach(function(node) {
    if (!node.children.length && hasMojibake(node.textContent)) {
      node.textContent = node.textContent
        .replace(/[ÃÂâï][^ ]*/g, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
    }
  });
}

// ── Feature 2: PII Scrubber ───────────────────────────────────────────────────
// Strips likely PII from history/error-log entries before they touch localStorage.
// Targets: SSN patterns, DOB-like dates embedded in field values, defendant names
// in known name fields. Operates on the errors array inside a run object.
const PII_FIELDS = new Set([
  'defendant_name','defendant_first_name','defendant_last_name','defendant_middle_name',
  'party_name','party_first_name','party_last_name','party_middle_name',
  'attorney_name','appointee','case_style','victim_name'
]);
const SSN_RE   = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;
const DATE_RE  = /\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](\d{2}|\d{4})\b/g;

function scrubPII(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(SSN_RE,  '[SSN-REDACTED]')
    .replace(DATE_RE, '[DATE-REDACTED]');
}

function scrubRunPII(run) {
  // Deep-clone so we never mutate the in-memory run
  const r = JSON.parse(JSON.stringify(run));
  if (Array.isArray(r.errors)) {
    r.errors = r.errors.map(function(e) {
      // Scrub PII field names
      if (PII_FIELDS.has(e.field)) {
        e.msg         = '[PII-REDACTED]';
        e.translation = '[PII-REDACTED]';
      }
      // Scrub SSN / dates from all string values
      e.msg         = scrubPII(e.msg);
      e.translation = scrubPII(e.translation);
      return e;
    });
  }
  return r;
}

// ── Feature 3: Session-Only mode ─────────────────────────────────────────────
// When enabled, history/error-log writes go to sessionStorage only (cleared
// when the tab closes). Persists the toggle preference itself in localStorage.
const SESSION_ONLY_KEY = 'catch_session_only_mode';

function isSessionOnly() {
  const toggle = document.getElementById('session-only-toggle');
  return toggle ? toggle.checked : false;
}

function getStorage() {
  return isSessionOnly() ? sessionStorage : localStorage;
}

function loadSessionOnlyPref() {
  try {
    const pref = localStorage.getItem(SESSION_ONLY_KEY);
    const toggle = document.getElementById('session-only-toggle');
    if (toggle && pref === '1') {
      toggle.checked = true;
      updateSessionOnlyLabel();
    }
  } catch(e) {}
}

function onSessionOnlyToggle() {
  try {
    localStorage.setItem(SESSION_ONLY_KEY, isSessionOnly() ? '1' : '0');
  } catch(e) {}
  updateSessionOnlyLabel();
}

function updateSessionOnlyLabel() {
  const lbl = document.getElementById('session-only-label');
  if (!lbl) return;
  lbl.textContent = isSessionOnly()
    ? 'Session-Only ON — nothing will persist after tab close'
    : 'Session-Only OFF — history saved to browser storage';
  lbl.style.color = isSessionOnly() ? 'var(--orange)' : 'var(--text3)';
}

// ── Feature 4: Inactivity Auto-Clear ─────────────────────────────────────────
// Clears the validate textarea and results after 30 minutes of no user action.
// Resets on any keypress, mouse move, or click. Shows a countdown warning at 25m.
const INACTIVITY_MS     = 30 * 60 * 1000; // 30 minutes
const INACTIVITY_WARN_MS = 25 * 60 * 1000; // warn at 25 minutes
let inactivityTimer  = null;
let inactivityWarnTimer = null;
let inactivityWarnEl = null;

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  clearTimeout(inactivityWarnTimer);
  if (inactivityWarnEl) { inactivityWarnEl.remove(); inactivityWarnEl = null; }

  inactivityWarnTimer = setTimeout(function() {
    showInactivityWarning();
  }, INACTIVITY_WARN_MS);

  inactivityTimer = setTimeout(function() {
    autoClearOnInactivity();
  }, INACTIVITY_MS);
}

function showInactivityWarning() {
  if (inactivityWarnEl) return;
  inactivityWarnEl = document.createElement('div');
  inactivityWarnEl.id = 'inactivity-warn';
  inactivityWarnEl.style.cssText = [
    'position:fixed','bottom:16px','right:16px','z-index:9999',
    'background:var(--orange-bg)','border:1px solid var(--orange)',
    'color:var(--orange)','font-family:var(--mono)','font-size:10px',
    'padding:8px 12px','border-radius:5px','max-width:320px','line-height:1.6'
  ].join(';');
  inactivityWarnEl.innerHTML =
    '⚠ Inactivity detected — workspace will auto-clear in 5 minutes to protect sensitive data. ' +
    '<span style="cursor:pointer;text-decoration:underline" onclick="resetInactivityTimer()">Keep active</span>';
  document.body.appendChild(inactivityWarnEl);
}

function autoClearOnInactivity() {
  // Clear the validation input and results (not history — just the live workspace)
  const inputArea = document.getElementById('input-area');
  const resultsArea = document.getElementById('results-area');
  const summaryBar = document.getElementById('summary-bar');
  const resultCount = document.getElementById('result-count');
  if (inputArea)   inputArea.value = '';
  if (resultsArea) resultsArea.innerHTML = '<div class="results-empty">Auto-cleared after 30 minutes of inactivity.</div>';
  if (summaryBar)  summaryBar.style.display = 'none';
  if (resultCount) resultCount.textContent = '';
  if (inactivityWarnEl) { inactivityWarnEl.remove(); inactivityWarnEl = null; }
  // Show cleared notice
  const notice = document.createElement('div');
  notice.style.cssText = [
    'position:fixed','bottom:16px','right:16px','z-index:9999',
    'background:var(--bg2)','border:1px solid var(--border2)',
    'color:var(--text3)','font-family:var(--mono)','font-size:10px',
    'padding:8px 12px','border-radius:5px'
  ].join(';');
  notice.textContent = 'Workspace auto-cleared after 30 min inactivity.';
  document.body.appendChild(notice);
  setTimeout(function() { notice.remove(); }, 4000);
  resetInactivityTimer();
}

// Attach inactivity listeners after DOM ready
document.addEventListener('DOMContentLoaded', function() {
  ['mousemove','keydown','click','scroll'].forEach(function(evt) {
    document.addEventListener(evt, resetInactivityTimer, { passive: true });
  });
  resetInactivityTimer();
  loadSessionOnlyPref();
  // Check if a previous session hit the storage quota
  _checkStorageWarning();
  // Initialize reference panel for default market (TX)
  updateSchemaReferencePanel();
  // Ctrl+Enter / Cmd+Enter to run validation from the input textarea
  const inputArea = document.getElementById('input-area');
  if (inputArea) {
    inputArea.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        runValidation();
      }
    });
    inputArea.addEventListener('input', updateEntityPreview);
    inputArea.addEventListener('paste', function() { setTimeout(updateEntityPreview, 50); });
  }
  updateTabBadges();
  try { updateLogCapUI(); } catch(e) {}
  // Pre-seed catalog seen-key set so first-run only notifies about genuinely new patterns
  try {
    var existingCatalog = buildCatalogData();
    existingCatalog.forEach(function(e) {
      _catalogSeenKeys.add(e.field + '|||' + e.errorCategory);
    });
  } catch(e) {}
});

// ── Feature 5: Export Warning Modal ──────────────────────────────────────────
// Any function that triggers a file download calls confirmExport() first.
// Returns a Promise that resolves true (proceed) or false (cancel).
function confirmExport(label) {
  return new Promise(function(resolve) {
    const overlay = document.createElement('div');
    overlay.style.cssText = [
      'position:fixed','inset:0','background:rgba(0,0,0,0.6)',
      'z-index:10000','display:flex','align-items:center','justify-content:center'
    ].join(';');
    const box = document.createElement('div');
    box.style.cssText = [
      'background:var(--bg1)','border:1px solid var(--border2)','border-radius:6px',
      'padding:20px 24px','max-width:400px','width:90%','font-family:var(--mono)'
    ].join(';');
    box.innerHTML =
      '<div style="font-size:12px;font-weight:700;color:var(--text);margin-bottom:10px">⚠ Export Confirmation</div>' +
      '<div style="font-size:10.5px;color:var(--text2);line-height:1.7;margin-bottom:16px">' +
        'You are about to export <strong>' + escHtml(label) + '</strong>.<br>' +
        'This file may contain court record data. Ensure you are saving it to an approved, secure location.' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end">' +
        '<button id="export-cancel-btn" style="background:transparent;border:1px solid var(--border2);color:var(--text3);padding:5px 14px;border-radius:4px;font-family:var(--mono);font-size:10px;cursor:pointer">Cancel</button>' +
        '<button id="export-confirm-btn" style="background:var(--blue);color:#fff;border:none;padding:5px 14px;border-radius:4px;font-family:var(--mono);font-size:10px;cursor:pointer">Export</button>' +
      '</div>';
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    box.querySelector('#export-confirm-btn').onclick = function() { overlay.remove(); resolve(true); };
    box.querySelector('#export-cancel-btn').onclick  = function() { overlay.remove(); resolve(false); };
    overlay.addEventListener('click', function(e) { if (e.target === overlay) { overlay.remove(); resolve(false); } });
  });
}

// ── Feature 6: History TTL ────────────────────────────────────────────────────
// Runs expire after 7 days. Called once during loadHistory() to silently prune
// stale entries before they are ever displayed. No data is exported — expired
// entries are simply discarded (they are old enough to not be actionable).
const HISTORY_TTL_DAYS = 7;
const HISTORY_TTL_MS   = HISTORY_TTL_DAYS * 24 * 60 * 60 * 1000;

function pruneExpiredRuns(runs) {
  const cutoff = Date.now() - HISTORY_TTL_MS;
  return runs.filter(function(run) {
    if (!run.timestamp) return true; // keep if no timestamp (legacy entries)
    const parsed = new Date(run.timestamp);
    if (isNaN(parsed.getTime())) return true; // keep unparseable timestamps
    return parsed.getTime() > cutoff;
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// END SECURITY LAYER
// ══════════════════════════════════════════════════════════════════════════════

const VALID_V3 = [
  "di-texas-oca-court-appointments",
  "di-texas-oca-court-attorney",
  "di-texas-oca-court-case-events",
  "di-texas-oca-court-case-status",
  "di-texas-oca-court-charges",
  "di-texas-oca-court-dispositions-criminal",
  "di-texas-oca-court-dispositions-non-criminal",
  "di-texas-oca-court-party"
];
const VALID_V01 = [
  "di-texas-oca-court-criminal-attorneys",
  "di-texas-oca-court-criminal-case-events",
  "di-texas-oca-court-criminal-charges",
  "di-texas-oca-court-criminal-defendants",
  "di-texas-oca-court-criminal-sanctions"
];
const ALL_VALID = [...VALID_V3, ...VALID_V01];
// ── Market tracking ───────────────────────────────────────────────────────────
var _currentMarket = 'TX';

// ── IL · AOIC Schema Data (v3.1.0) ───────────────────────────────────────────
const IL_VALID_ENTITY_TYPES = ["di-aoic-pretrial-active-status","di-aoic-pretrial-court-appearance-and-judicial-decisions","di-aoic-pretrial-courts-and-charges","di-aoic-pretrial-disposition-and-release","di-aoic-pretrial-drug-screening","di-aoic-pretrial-individual-background","di-aoic-pretrial-intake-and-assessment","di-aoic-pretrial-jail","di-aoic-pretrial-offense-charges","di-aoic-pretrial-offenses","di-aoic-pretrial-violations","di-aoic-probation-active-status","di-aoic-probation-ancillary-assessment","di-aoic-probation-drug-testing","di-aoic-probation-individual-background","di-aoic-probation-intake","di-aoic-probation-offenses","di-aoic-probation-programming-and-treatment","di-aoic-probation-supervision-and-sentencing","di-aoic-probation-termination","di-aoic-probation-violations-and-sanctions","di-aoic-trialcourt-adr","di-aoic-trialcourt-case-status","di-aoic-trialcourt-documents","di-aoic-trialcourt-financial","di-aoic-trialcourt-hearings","di-aoic-trialcourt-ja","di-aoic-trialcourt-party","di-aoic-trialcourt-party-hearing","di-aoic-trialcourt-pretrial","di-aoic-reviewingcourt-administration","di-aoic-reviewingcourt-case-status","di-aoic-reviewingcourt-financial","di-aoic-reviewingcourt-hearings","di-aoic-reviewingcourt-party","di-aoic-reviewingcourt-party-hearing","di-aoic-reviewingcourt-reviewing-courts"];

const IL_SOURCE_ID_MAP = {"Journal Technologies":"833tgmurNEpY7bPfKoZxeY","Goodin & Associates":"xnBe24mSP2YH4zfNSc5HSK","DuPage County":"4YYU6PVzSFE7mEJkuCBbFd","JANO Justice Systems":"8ZMMrB2L323qGcCPViu1qJ","Tyler Technologies (Enterprise Justice)":"81e7K4fPBnxDHAqQNyVND2","Justice Systems":"dVEWjdnqgsE8Kj2rb3YXGk","Tracker - Solution Specialties":"xgodrPpqbrDJjCKi6wrw2R"};
const IL_SOURCE_IDS = new Set(Object.values(IL_SOURCE_ID_MAP));
const IL_COMMUNITY_ID = "01H52Q833B501P4WG6DGDPNHX9";

// IL entity rules: required fields, enums, number fields
const IL_ENTITY_RULES = {"di-aoic-pretrial-individual-background":{"required":[],"enums":{"benefits":["Yes","No"],"benefitsaabd":["Yes","No"],"benefitsfca":["Yes","No"],"benefitssnap":["Yes","No"],"benefitsssi":["Yes","No"],"benefitstanf":["Yes","No"],"benefitsta":["Yes","No"],"benefitsssdi":["Yes","No"],"benefitsmedicaid":["Yes","No"],"benefitsmedicare":["Yes","No"],"benefitswic":["Yes","No"],"clientrepresentedcr":["Yes","No"],"whorepresentedcr":["Public","Private"],"accommodationneededcr":["Yes","No"],"accomodationreceivedcr":["Yes","No"],"interpreterneededcr":["Yes","No"],"interpretertypeneededcr":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"interpreterreceivedcr":["Yes","No"],"clientrepresentedcp":["Yes","No"],"whorepresentedcp":["Public","Private"],"accommodationneededcp":["Yes","No"],"accomodationreceivedcp":["Yes","No"],"interpreterneededcp":["Yes","No"],"interpretertypeneededcp":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"interpreterreceivedcp":["Yes","No"],"insurance12mo":["Yes","No"],"insurancecurrently":["Yes","No"],"insurancethrough":["Current or Former Employer (Self)","Current or Former Employer (Spouse)","Dependent on Parent(s) Insurance","Government Program","Self-Funded","Other"],"insurancetype":["Single","Limited Family (Employee + Spouse or Employee + Children)","Full Family (Employee, Spouse + Children)"],"noinsurancebelieve":["Yes","No"],"noinsurancerefuse":["Yes","No"],"noinsuranceeligible":["Yes","No"],"noinsuranceemployernopay":["Yes","No"],"noinsurancecantafford":["Yes","No"],"noinsurancedissatisfied":["Yes","No"],"noinsurancenotqualified":["Yes","No"],"noinsuranceother":["Yes","No"],"validildl":["Yes - Active","No - Inactive","Never acquired a driver's license","Not Applicable - Under 16"],"addresstype":["Known","Unknown/Homeless"],"state":["AK","AL","AR","AS","AZ","CA","CO","CT","DC","DE","FL","GA","GU","HI","IA","ID","IL","IN","KS","KY","LA","MA","MD","ME","MI","MN","MO","MP","MS","MT","NC","ND","NE","NH","NJ","NM","NV","NY","OH","OK","OR","PA","PR","RI","SC","SD","TN","TX","UM","UT","VA","VI","VT","WA","WI","WV","WY"],"educationalattainment":["8th grade or less","9th grade","10th grade","11th grade","Diploma/GED","Attended College","Technical degree","4 year degree","Post-graduate"],"studentstatus":["Yes - Full-time Student","Yes - Part-time Student","No - Not Enrolled"],"employmentstatus":["Unemployed/Looking","Part-time","Full-time","Not Employed - Stay at Home Parent","Not Employed - Full-time Student","Not Employed - Disability","Not Employed - Retired"],"selfemployed":["Yes","No"],"maritalstatus":["Married","Widowed","Divorced","Separated","Never Married","Other"],"housingtype":["Incarcerated","Facility","Home/Apartment","Temporary/Foster","Transient (or Homeless)"],"livingsituation":["Alone","Children Only","Family","Partner (or Boyfriend/Girlfriend)","Partner (or Boyfriend/Girlfriend) & Children","Roommate(s) & Spouse","Roommate(s), Spouse, & Children","Roommate(s) Only","Roommate(s) & Children","Spouse Only","With Parents/Guardian Only","With Parents/Guardian & Children","With Parents/Guardian & Family","With Parents/Guardian & Spouse","Other Relatives"],"children":["Yes","No"],"childrensupport":["Yes","No","Not Applicable"],"military":["Yes","No"],"airforce":["Yes","No"],"army":["Yes","No"],"coastguard":["Yes","No"],"marincorps":["Yes","No"],"navy":["Yes","No"],"spaceforce":["Yes","No"],"reserves":["Yes","No"],"nationalguard":["Yes","No"],"rotc":["Yes","No"],"jrotc":["Yes","No"],"militaryactive":["Yes","No"],"militarydischarged":["Yes","No"],"militaryretired":["Yes","No"],"militaryveteran":["Yes","No"],"militaryrank":["Enlisted","Non-Commissioned Officer","Warrant Officer","Officer"],"militarydischargetype":["Bad Conduct Discharge","Dishonorable Discharge","Entry-Level Separation Discharge","General Discharge Under Honorable Conditions","Honorable Discharge","Medical Discharge","Other than Honorable Conditions Discharge","Separation for the Convenience of the Government Discharge","Separation for the Convenience of the Government Discharge"],"initsupervisionlevel":["OHIO - Low","OHIO - Moderate","OHIO - High","PSA - Dark Green","PSA - Light Green","PSA - Yellow","PSA - Amber","PSA - Light Orange","PSA - Dark Orange","PSA - Red","VPRAI - Low (0-1)","VPRAI - Below Average (2)","VPRAI - Average (3)","VPRAI - Above Average (4)","VPRAI - High (5-9)","VPRAI M - Green","VPRAI M - Yellow","VPRAI M - Orange","VPRAI M - Red","VPRAI R - Risk Level 1","VPRAI R - Risk Level 2","VPRAI R - Risk Level 3","VPRAI R - Risk Level 4","VPRAI R - Risk Level 5","VPRAI R - Risk Level 6","VPRAI RM - Green","VPRAI RM - Yellow","VPRAI RM - Orange","VPRAI RM - Red","VPRAI RM - Light Blue","VPRAI RM - Medium Blue","VPRAI RM - Dark Blue","VPRAI RM - Blue (DeKalb Model)","VPRAI RM - White"]},"numOrNull":["householdsize","childrennum","militaryyearsserved"],"dateFields":["supervisionstartdate","supervisionintakedate"]},"di-aoic-pretrial-jail":{"required":[],"enums":{"arrestwithwarrant":["Yes","No"],"released":["Yes","No"],"whyreleased":["Delegated Release by Pretrial Department","No Charges Filed","Posted Statutory Bond","Prosecutor Authorized Release","Released on Bond Previously Set","Released on Jail Recognizance (I-Bond)","Released to Another Jurisdiction","Released to Department of Human Services","Released to Illinois Department of Corrections","Released to Mental Health Facility","Released to Physical Health Facility","Released to Substance Abuse Facility","Other","Offense (Initial Index)"]},"numOrNull":["initoffenseaoiccode","initoffensecounts"],"dateFields":["arrestdate","jailadmindate","initoffensedate","countydatereleased"]},"di-aoic-pretrial-intake-and-assessment":{"required":[],"enums":{"interviewcompleted":["Yes","No"],"nointerviewcompletedreason":["Defendant Did Not Consent","Defendant Elected to Stop","Defendant Requested an Attorney to be Present","Intoxication","Jail Did Not Allow","Medical","Mental Health","Safety Concerns","Time Constraints"],"rightsform":["Yes","No"],"norightsformwhy":["Defendant Did Not Consent","Defendant Elected to Stop","Defendant Requested an Attorney to be Present","Intoxication","Jail Did Not Allow","Medical","Mental Health","Safety Concerns","Time Constraints","Type of bond report completed for initial bond hearing"],"risktool":["Yes","No"],"interview":["Yes","No"],"pretrialriskassessment":["Yes","No"],"releaserecommendations":["Yes","No"],"recordcheck":["Yes","No"],"verificationcollateralcontact":["Yes","No"],"offenseclassbondreport":["M","X","1","2","3","4","A","B","C"],"assessbondreportverified":["Yes","No"],"pretrialassesstool":["Yes","No"],"pat":["Yes","No"],"patfirstarrestage":["32 or older","Under 32"],"patfta":["None","One Warrant for FTA","Two or More FTA Warrants"],"patpriorincarcerations":["Yes","No"],"patemployed":["Yes, Full-time","Yes, Part-time","Not Employed"],"patresstability":["Lived at Current Residence Past Six Months","Not Lived at Same Residence"],"patillegaldruguse":["Yes","No"],"patseveredruguse":["Yes","No"],"patriskscore":["0","1","2","3","4","5","6","7","8","9"],"patsupervisionlevel":["Low","Moderate","High"],"patoverride":["Up","Down","Not Applicable"],"patoveerridereason":["Professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other (Explain)"],"psa":["Yes","No"],"psaage":["Age 20 or less","Age 21-22","Age 23 or greater"],"psaviolentoffense":["Yes","No"],"psaviolentoffenseyoung":["Yes","No"],"psapendingcharge":["Yes","No"],"psapriormis":["Yes","No"],"psapriorfel":["Yes","No"],"psapriorconviction":["Yes","No"],"psapriorftaover2yr":["Yes","No"],"psapriorsentence":["Yes","No"],"psaviolenceflag":["Yes","No"],"psanewcriminalactivity":["1","2","3","4","5","6"],"psafta":["1","2","3","4","5","6"],"psasupervisionlevel":["Dark Green","Light Green","Yellow","Amber","Light Orange","Dark Orange","Red"],"psaoverride":["Up","Down","Not Applicable"],"psaoverridereason":["Professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other (Explain)"],"vprai":["Yes","No"],"vpraifel":["Yes","No"],"vpraipendcharge":["Yes","No"],"vpraicrimhist":["Yes","No"],"vpraifta":["Yes","No"],"vpraiviolentconvictions":["Yes","No"],"vpraicurrentres":["Yes","No"],"vprainotemployed":["Yes","No"],"vpraidrugabuse":["Yes","No"],"vprairiskscore":["0","1","2","3","4","5","6","7","8","9"],"vpraisupervisionlevel":["Low (0-1)","Below Average (2)","Average (3)","Above Average (4)","High (5-9)"],"vpraimatrix":["Yes","No"],"vpraimatrixriskscore":["0","1","2","3","4","5","6","7","8","9"],"vpraimatrixsupervisionlevel":["Green","Yellow","Orange","Red"],"vpraioverride":["Up","Down","Not Applicable"],"vpraioverridereason":["Professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other (Explain)"],"vprair":["Yes","No"],"vprairsupervision":["Yes","No"],"vprairfel":["Yes","No"],"vprairpendingcharge":["Yes","No"],"vpraircrimhist":["Yes","No"],"vprairfta":["Yes","No"],"vprairviolentconvictions":["Yes","No"],"vprairunemployed":["Yes","No"],"vprairdrugabuse":["Yes","No"],"vprairriskscore":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14"],"vprairsupervisionlevel":["Risk Level 1","Risk Level 2","Risk Level 3","Risk Level 4","Risk Level 5","Risk Level 6"],"vprairmatrix":["Yes","No"],"vprairmatrixriskscore":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14"],"vprairmatrixsupervisionlevel":["Green","Yellow","Orange","Red","Baby Blue","Medium Blue","Dark Blue","Blue","White"],"vprairoverride":["Up","Down","Not Applicable"],"vprairoverridereason":["Professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other (Explain)"],"ancillarytools":["Yes","No"],"dale":["Yes","No"],"dalewhoadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer/Pretrial Officer","Partner Abuse Intervention Program (PAIP)"],"daleriskscore":["0","1","2","3","4","5","6","7","8","9","10","11"],"dvsi":["Yes","No"],"dvsiwhoadministered":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer/Pretrial Officer","Partner Abuse Intervention Program (PAIP)"],"dvsiriskscore":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24"],"odara":["Yes","No"],"odarawhoadministered":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer/Pretrial Officer","Partner Abuse Intervention Program (PAIP)"],"odarariskscore":["0","1","2","3","4","5","6","7","8","9","10","11","12","13"],"otherancillary":["Yes","No"],"otherancillarywhoadministered":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer/Pretrial Officer","Partner Abuse Intervention Program (PAIP)"],"clientprobation":["Yes","No"],"clientmsr":["Yes","No"],"clientaddress":["Known","Unknown/Homeless"],"state":["AK","AL","AR","AS","AZ","CA","CO","CT","DC","DE","FL","GA","GU","HI","IA","ID","IL","IN","KS","KY","LA","MA","MD","ME","MI","MN","MO","MP","MS","MT","NC","ND","NE","NH","NJ","NM","NV","NY","OH","OK","OR","PA","PR","RI","SC","SD","TN","TX","UM","UT","VA","VI","VT","WA","WI","WV","WY"]},"numOrNull":["psapriorviolentconviction","psapriorftaunder2yr"],"dateFields":["backgroundcheckdate","interviewdate","assessbondreportdatesubmitted","assessbondreportdatefiled","riskassessmentdate"]},"di-aoic-pretrial-courts-and-charges":{"required":[],"enums":{"citationissued":["Yes","No"],"offenseclassification":["Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony"],"clientdefensecounsel":["Yes","No"],"clientdcpublicprivate":["Public","Private"],"clientaccommodation":["Yes","No"],"clientaccomacquired":["Yes","No"],"clientinterpreter":["Yes","No"],"clientinterpretertype":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"clientinterpreterlanguage":["Yes","No"]},"numOrNull":["offensecounts"],"dateFields":["offensedate","subbondcalldate"]},"di-aoic-pretrial-court-appearance-and-judicial-decisions":{"required":[],"enums":{"crdefensecounsel":["Yes","No"],"crdefensecounselpublicprivate":["Public","Private"],"craccommodation":["Yes","No"],"craccommodationaquired":["Yes","No"],"craccommodationinterpreter":["Yes","No"],"craccommodationinterpretertype":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"craccommodationinterpreterlanguage":["Yes","No"],"cpdefensecounsel":["Yes","No"],"cpdefensecounselpublicprivate":["Public","Private"],"cpaccommodation":["Yes","No"],"cpaccommodationaquired":["Yes","No"],"cpaccommodationinterpreter":["Yes","No"],"cpaccommodationinterpretertype":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"cpaccommodationinterpreterlanguage":["Yes","No"],"judgeorderdefendantdetained":["Yes","No"],"judgeorderdefendantdetainedwhy":["Threat to safety of person(s)","Threat to intentionally evade prosecution"],"judgeorderdefendantdetainedmonetarycondition":["Yes","No"],"judgeorderdefendantdetainedcashbondtype":["Release with a Cash Bond (D-Bond)","Release with a Cash Bond (C-Bond)"],"judgeorderdefendantdetainedreleasetype":["Released on Recognizance (I-Bond)"],"judgeorderdefendantdetainednotordered":["No pretrial supervision, no special conditions","No pretrial supervision, with special conditions","Pretrial supervision, no special conditions","Pretrial supervision, with special conditions"],"courtorderedspecialconditions":["Yes","No"],"surrenderfirearms":["Yes","No"],"drugandalcoholtesting":["Yes","No"],"curfew":["Yes","No"],"elecmonitortype":["Yes","No"],"bischofdiane":["Yes","No"],"alcoholmonitoringdevice":["Yes","No"],"amignitioninterlock":["Yes","No"],"amrbhm":["Yes","No"],"amcamtrans":["Yes","No"],"amother":["Yes","No"],"gpsmonitoring":["Yes","No"],"exclusionzones":["Yes","No"],"noexclusionzones":["Yes","No"],"inclusionzones":["Yes","No"],"noinclusionzones":["Yes","No"],"gpsmonitoringactivepassive":["Active","Passive"],"emother":["Yes","No"],"homeconfinement":["Yes","No"],"nocontactnv":["Yes","No"],"nocontactv":["Yes","No"],"otherfinancialobligation":["Yes","No"],"drugtestingpay":["Yes","No"],"empay":["Yes","No"],"restitutionpay":["Yes","No"],"supervisionpay":["Yes","No"],"prohibitedactivity":["Yes","No"],"prohibitedarea":["Yes","No"],"publicserviceworkhours":["Yes","No"],"referraldrugscreening":["Yes","No"],"referralduiscreening":["Yes","No"],"referralmentalhealthscreening":["Yes","No"],"referralveteransscreening":["Yes","No"],"referralotherscreening":["Yes","No"],"shoplifteralt":["Yes","No"],"speclevelreporting":["Yes","No"],"passportsurrender":["Yes","No"],"victimimpact":["Yes","No"],"apologyletter":["Yes","No"],"angermanage":["Yes","No"],"cbt":["Yes","No"],"cbtdbt":["Yes","No"],"cbtmrt":["Yes","No"],"cbtt4c":["Yes","No"],"cbtother":["Yes","No"],"cbtspecifyother":["Yes","No"],"domviolenceeval":["Yes","No"],"drugalcoholeval":["Yes","No"],"duieval":["Yes","No"],"gamblingeval":["Yes","No"],"initindividualtherapy":["Yes","No"],"medeval":["Yes","No"],"medicationmanag":["Yes","No"],"mentalhealtheval":["Yes","No"],"parantingeducation":["Yes","No"],"initselfhelpgroup":["Yes","No"],"shopliftertreatment":["Yes","No"],"traumaeval":["Yes","No"],"pretrialdeemedtreatment":["Yes","No"],"othertreatment":["Yes","No"],"specialconditionother":["Yes","No"],"judicialriskassessmentrecommendation":["Yes","No"],"judicialoverride":["Higher","Lower"],"bondreportcollateralcontacts":["Yes","No"],"courtrecorddefensecounsel":["Yes","No"],"courtrecorddcpublicprivate":["Public","Private"],"courtrecordaccommodation":["Yes","No"],"courtrecordaccomacquired":["Yes","No"],"courtrecordinterpreter":["Yes","No"],"courtrecordinterpretertype":["Mandarin","Spanish","Bengali","Hindi","Portuguese","Russian","Japanese","German","Wu,Javanese","Korean","French","Vietnamese","Telugu","Yue","Marathi","Tamil","Turkish","Urdu","Min Nan","Jinyu","Gujarati","Polish","Arabic","Ukrainian","Italian","Xiang","Malayalam","Hakka","Kannada","Oriya","Panjabi","Sunda","Romanian","Bhojpuri","Farsi","Maithili","Hausa","Burmese","Serbocroatian","Gan","Awadhi","Thai","Dutch","Yoruba","Sindhi","Uzbek","Malay","Amharic","Indonesian","Igbo","Tagalor","Nepali","Saraiki","Cebuano","Thai","Assamese","Hungarian","Chittagonian","Madura","Sinhala","Haryanvi","Marwari","Czech","Greek","Magahi","Chhattisgarhi","Deccan","Min Bei","Belarusan","Pashto","Somali","Malagasy","Rwanda","Zulu","Bulgarian","Swedish","Lombard","Oromo","Pashto","Kazakh","Ilocano","Tatar","Fulfulde","Uyghur","Haitian Creole French","Azerbaijani","Napoletanocalabrese","Khmer","Farsi","Akan","Hiligaynon","Kurmanji","Shona","American Sign Language"],"courtrecordinterpreterlanguage":["Yes","No"],"defendantdetained":["Yes","No"],"defendantdetainedwhy":["Threat to safety of person(s)","Threat to intentionally evade prosecution"],"monetaryconditionrelease":["Yes","No"],"cashbondreleasetype":["Release with a Cash Bond (D-Bond)","Release with a Cash Bond (C-Bond)"],"nocashbondrelease":["Released on Recognizance (I-Bond)"],"pretrialsupervision":["No pretrial supervision, no special conditions","No pretrial supervision, with special conditions","Pretrial supervision, no special conditions","Pretrial supervision, with special conditions"],"subbondhearingcondition":["Yes","No"],"scdrugalcoholtesting":["Yes","No"],"sccurfew":["Yes","No"],"scem":["Yes","No"],"scdianeslaw":["Yes","No"],"scalcoholmonitoring":["Yes","No"],"alcoholmonitoringignition":["Yes","No"],"alcoholmonitoringremote":["Yes","No"],"alcoholmonitoringcam":["Yes","No"],"alcoholmonitoringother":["Yes","No"],"scgps":["Yes","No"],"scgpsexclusion":["Yes","No"],"scgpsnoexclusion":["Yes","No"],"scgpsinclusion":["Yes","No"],"scgpsnoinclusion":["Yes","No"],"scgpsactivepassive":["Active","Passive"],"scemother":["Yes","No"],"schomeconfinement":["Yes","No"],"scnocontactnonvic":["Yes","No"],"scnocontactvic":["Yes","No"],"scotherobligation":["Yes","No"],"scdrugtestpay":["Yes","No"],"scempay":["Yes","No"],"screstitutionpay":["Yes","No"],"scsupervisionpay":["Yes","No"],"scprohibitedactivity":["Yes","No"],"scprohibitedarea":["Yes","No"],"scpublicservice":["Yes","No"],"scdrugcourtreferral":["Yes","No"],"scduicourtreferral":["Yes","No"],"scmentalhealthreferral":["Yes","No"],"scvetreferral":["Yes","No"],"scotherreferral":["Yes","No"],"scshoplifter":["Yes","No"],"screportinglevel":["Yes","No"],"scpassport":["Yes","No"],"scvictimimpact":["Yes","No"],"scapologyletter":["Yes","No"],"scprogrammingtreatment":["Yes","No"],"courtangermanage":["Yes","No"],"courtcbt":["Yes","No"],"courtcbtdbt":["Yes","No"],"courtcbtmrt":["Yes","No"],"courtcbtt4c":["Yes","No"],"courtcbtother":["Yes","No"],"courtcbtotherspecify":["Yes","No"],"courtdomviolenceeval":["Yes","No"],"courtdrugalcoholeval":["Yes","No"],"courtduieval":["Yes","No"],"courtgamblingeval":["Yes","No"],"courtgenderservice":["Yes","No"],"courtmedeval":["Yes","No"],"courtmedicationmanag":["Yes","No"],"courtmentalhealtheval":["Yes","No"],"courtinitparentinged":["Yes","No"],"courtinitselfhelpgroup":["Yes","No"],"courtshopliftertreatment":["Yes","No"],"courttraumaeval":["Yes","No"],"courtpsctreatment":["Yes","No"],"courttreatmentother":["Yes","No"],"scother":["Yes","No"],"judicialadherenceriskassess":["Yes","No"],"judicialadherenceoverride":["Higher","Lower"]},"numOrNull":["publicserviceworkhoursordered","scpublicserviceordered"],"dateFields":["saochargefiledate","cpcourtapperancedate","bondreportpretrialdate","bondreportpretrialfiledate"]},"di-aoic-pretrial-active-status":{"required":[],"enums":{"asawol":["Yes","No"],"asidoc":["Yes","No"],"asjail":["Yes","No"],"aswarrant":["Yes","No"],"astransferout":["Yes","No"]},"numOrNull":[],"dateFields":[]},"di-aoic-pretrial-disposition-and-release":{"required":[],"enums":{"releasecustody":["Yes","No"],"custodyotheragency":["Yes","No"],"custodyaltres":["Yes","No"],"custodydv":["Yes","No"],"custodyfinccost":["Yes","No"],"custodyotherheld":["Yes","No"],"custodyem":["Yes","No"],"custodysurrpassport":["Yes","No"],"custodydrugtreat":["Yes","No"],"custodymhtreat":["Yes","No"],"custodyothertermsunmet":["Yes","No"],"custodyfincbond":["Yes","No"],"custodyother":["Yes","No"],"empayee":["Client","County","Court","Pretrial","Probation","State's Attorney Office","Sheriff's Department","Other"],"compreportssubmitted":["Yes","No"],"remindernotificationmethod":["E-Mail","Letter in Mail/Post","Phone Call","Text Message","In Person Contact with Pretrial Officer","Other"],"defendantattendance":["Yes","No"],"nodefendantoutcome":["Continuance","Warrant","Other"],"defendantwarranttype":["No Bond","Cash Bond","Recognizance Bond"],"officerattemptcontact":["Yes","No"],"contactsuccessful":["Yes","No"],"reasonclientreportedmissing":["Death of Defendant","Death of Friend/Family Member","Did not want to attend/absconded","Forgot","Had to work","Illness","No childcare","No ride","Was in treatment/under medical care","Other"],"warrantagencyintervention":["Yes","No"],"agencyinterventionresolved":["Defendant appeared late","Defendant contacted defense attorney","Defendant contacted pretrial service","Defendant issued new court date","Defendant turned self in","Other"],"releasebenefits":["Yes","No"],"releasebenefitsaabd":["Yes","No"],"releasebenefitsfca":["Yes","No"],"releasebenefitssnap":["Yes","No"],"releasebenefitsssi":["Yes","No"],"releasebenefitstanf":["Yes","No"],"releasebenefitsta":["Yes","No"],"releasebenefitsssdi":["Yes","No"],"releasebenefitsmedicaid":["Yes","No"],"releasebenefitsmedicare":["Yes","No"],"releasebenefitswic":["Yes","No"],"releaseinsurance12mo":["Yes","No"],"releaseinsurancecurrent":["Yes","No"],"releaseinsurancethrough":["Current or Former Employer (Self)","Current or Former Employer (Spouse)","Dependent on Parent(s) Insurance","Government Program","Self-Funded","Other"],"releaseinsurancetype":["Single","Limited Family (Employee + Spouse or Employee + Children)","Full Family (Employee, Spouse + Children)"],"releasenoinsurancebelieve":["Yes","No"],"releasenoinsurancerefuse":["Yes","No"],"releasenoinsuranceeligible":["Yes","No"],"releasenoinsuranceemployernopay":["Yes","No"],"releasenoinsurancecantafford":["Yes","No"],"releasenoinsurancedissatisfied":["Yes","No"],"releasenoinsurancenotqualified":["Yes","No"],"releasesentencedtypeother":["Yes","No"],"releasevalidildl":["Yes - Active","No - Inactive","Never acquired a driver's license","Not Applicable - Under 16"],"releaseaddresstype":["Known","Unknown/Homeless"],"releasedlstate":["AK","AL","AR","AS","AZ","CA","CO","CT","DC","DE","FL","GA","GU","HI","IA","ID","IL","IN","KS","KY","LA","MA","MD","ME","MI","MN","MO","MP","MS","MT","NC","ND","NE","NH","NJ","NM","NV","NY","OH","OK","OR","PA","PR","RI","SC","SD","TN","TX","UM","UT","VA","VI","VT","WA","WI","WV","WY"],"releaseeducationalattainment":["8th grade or less","9th grade","10th grade","11th grade","Diploma/GED","Attended College","Technical degree","4 year degree","Post-graduate"],"releasestudentstatus":["Yes - Full-time Student","Yes - Part-time Student","No - Not Enrolled"],"releaseemploymentstatus":["Unemployed/Looking","Part-time","Full-time","Not Employed - Stay at Home Parent","Not Employed - Full-time Student","Not Employed - Disability","Not Employed - Retired"],"releaseselfemployed":["Yes","No"],"releasemaritalstatus":["Married","Widowed","Divorced","Separated","Never Married","Other"],"releasehousingtype":["Incarcerated","Facility","Home/Apartment","Temporary/Foster","Transient (or Homeless)"],"releaselivingsituation":["Alone","Children Only","Family","Partner (or Boyfriend/Girlfriend)","Partner (or Boyfriend/Girlfriend) & Children","Roommate(s) & Spouse","Roommate(s), Spouse, & Children","Roommate(s) Only","Roommate(s) & Children","Spouse Only","With Parents/Guardian Only","With Parents/Guardian & Children","With Parents/Guardian & Family","With Parents/Guardian & Spouse","Other Relatives"],"releasechildren":["Yes","No"],"releasechildsupportcurrent":["Yes","No","Not Applicable"],"termmilitaryservice":["Yes","No"],"termairforce":["Yes","No"],"termarmy":["Yes","No"],"termcoastguard":["Yes","No"],"termmarinecorps":["Yes","No"],"termnavy":["Yes","No"],"termspaceforce":["Yes","No"],"termreserves":["Yes","No"],"termnationalguard":["Yes","No"],"termrotc":["Yes","No"],"termjrotc":["Yes","No"],"termmilitarystatusactive":["Yes","No"],"termmilitarystatusdischarged":["Yes","No"],"termmilitarystatusretired":["Yes","No"],"termmilitarystatusveteran":["Yes","No"],"termmilitaryrank":["Enlisted","Non-Commissioned Officer","Warrant Officer","Officer"],"termmilitarydischargetype":["Bad Conduct Discharge","Dishonorable Discharge","Entry-Level Separation Discharge","General Discharge Under Honorable Conditions","Honorable Discharge","Medical Discharge","Other than Honorable Conditions Discharge","Separation for the Convenience of the Government Discharge","Separation for the Convenience of the Government Discharge"],"terminationreason":["Charges Dropped","Death","Nolle Prossed","Revoked by Judge","Sentenced","Stricken on Leave to Reinstate (SOL)","Closed by Court Order/Non-Revocation","Other"],"trialtype":["Bench Trial","Jury Trial"],"casedisposition":["101","102","103","104","105","106","107","108","109","110","201","202","203","204","205","206","207","208","209","210","211","212","213","214","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","301","302","303","304","305","307","350","352","351","353","354","355","356","357","358","359","360","401","402","403","405","407","408","409","410","411","412","413","414","415","416","501","502","503","504","505","506","507","508","509","510","511","601","602","603","604","605","606","607","608","610","613","615","616","617","618","650","651","652","653","654","701","702","704","705","706","707","708","709","710","801","802","803","804","888"],"guiltytype":["Defendant Plea","Finding by Trial","Offense (Initial Index)"],"releaseoffenseclassification":["M","X","1","2","3","4","A","B","C","P","U","O"],"sentencefees":["Yes","No"],"sentencerestitution":["Yes","No"],"sentencedischarge":["Yes","No"],"sentencesupervision":["Yes","No"],"sentencedoc":["Yes","No"],"sentenceidjj":["Yes","No"],"sentencejail":["Yes","No"],"sentenceprobation":["1st Offender","1st Offender Program","2nd Chance","410 Probation","550","Child Endangerment Probation","Conditional Discharge","Continued Under Supervision (CUS) - Adult","Continued Under Supervision (CUS) - Juvenile","Informal Supervision","Juvenile Diversion","Probation","Probation/Problem-Solving Court (Drug Court)","Probation/Problem-Solving Court (DUI Court)","Probation/Problem-Solving Court (Family Treatment Court)","Probation/Problem-Solving Court (Mental Health Court)","Probation/Problem-Solving Court (Veteran)","Probation/Problem-Solving Court (Hybrid/Mixed)","Other"]},"numOrNull":["custodydays","emdays","releasehouseholdsize","releasechildrennum","termmilitaryyearsserved","supervisiondurationdays","aoiccode","releaseoffensecounts","sentencedischargelength","sentencesupervisionlength","sentencedoclength","sentenceidjjlength","sentencejaillength"],"dateFields":["emstartdate","emenddate","pretrialrecordcheckdate","courtreminderdate","scheduledcourtdate","supervisionenddate","casedispositiondate","sentencedate"]},"di-aoic-pretrial-drug-screening":{"required":[],"enums":{"results":["Positive","Negative"],"drugscreenamphetamines":["Yes","No"],"drugscreenbarbituates":["Yes","No"],"drugscreenbenzodiazepines":["Yes","No"],"drugscreencrackcocaine":["Yes","No"],"drugscreenhallucinogens":["Yes","No"],"drugscreenheroin":["Yes","No"],"drugscreeninhalants":["Yes","No"],"drugscreenmarijuana":["Yes","No"],"drugscreenmethamphetamine":["Yes","No"],"drugscreenopiates":["Yes","No"],"drugscreensynthetics":["Yes","No"],"drugscreencollectionmethod":["Blood","Hair","Urine","Saliva","Transdermal"],"drugscreenverification":["Yes","No"],"drugscreenverificationfalsepos":["Yes","No"]},"numOrNull":[],"dateFields":["drugscreendate"]},"di-aoic-pretrial-violations":{"required":[],"enums":{"violationsubmitted":["Yes","No"],"technicalviolations":["Yes","No"],"technicalnewoffense":["Yes","No"],"technicalftacourt":["Yes","No"],"absconding":["Yes","No"],"curfew":["Yes","No"],"techviolationemtamp":["Yes","No"],"techviolationpayfail":["Yes","No"],"finesfees":["Yes","No"],"homeconfinement":["Yes","No"],"missedappt":["Yes","No"],"nocontactorder":["Yes","No"],"posdrugscreen":["Yes","No"],"pubservhours":["Yes","No"],"restitution":["Yes","No"],"treatnoncomp":["Yes","No"],"otherviol":["Yes","No"],"defendantnewoffense":["Yes","No"],"newoffenseclassification":["M","X","1","2","3","4","A","B","C","P","U","O"],"revocationfiled":["Yes","No"],"revocationtechviolation":["Yes","No"],"revocationnewoffense":["Yes","No"],"revocationfta":["Yes","No"],"revocationmodifcations":["Yes","No"],"revocationsanctions":["Yes","No"],"revocationtechpay":["Yes","No"],"warrantissue":["Yes","No"],"warrantissuetechviolation":["Yes","No"],"warrantissuenewoffense":["Yes","No"],"warrantissuefta":["Yes","No"],"defendantreturnedcustody":["Yes","No"],"defendantreturnedtech":["Yes","No"],"defendantreturnednewoffense":["Yes","No"],"defendantreturnedfta":["Yes","No"],"defendantreturnedtechpayemfees":["Yes","No"],"defendantsupervisionrevoke":["Yes","No"],"defendantsupervisiontech":["Yes","No"],"defendantsupervisionnewoffense":["Yes","No"],"defendantsupervisionfta":["Yes","No"],"defendantem":["Yes","No"],"defendantemtech":["Yes","No"],"defendantemnewoffense":["Yes","No"],"defendantemfta":["Yes","No"]},"numOrNull":["abscondingnum","curfewnum","emnumtampering","emnumpayfailure","sanctionfinesnum","homeconfinum","missedappoitnum","nocontactnum","drugscreennum","servicehoursnum","restitutionnum","treatmentnum","othernum","newoffensecount","warrantissuetime"],"dateFields":["violationsubmitteddate","newoffensedate","revocationdate","warrantissuedate","defendantreturnedcustodydate","defendantsupervisionrevokedate","defendantemdate"]},"di-aoic-pretrial-offenses":{"required":[],"enums":{"offenseclassification":["Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony","Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Petty Offense","Unclassified","Other"],"offensestatus":["Active","Amended","Dismissed","Disposed","Reduced","Other"]},"numOrNull":["offensesequence"],"dateFields":["offensedate","offensestatusdate"]},"di-aoic-pretrial-offense-charges":{"required":[],"enums":{"chargeclassification":["Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony","Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Petty Offense","Unclassified","Other"],"chargefiled":["Yes","No"],"chargestatus":["Pending","Filed","Amended","Reduced","Dismissed","Disposed","Nolle Prosequi","Other"],"chargedisposition":["Guilty","Not Guilty","Dismissed","Nolle Prosequi","Reduced","Amended","Pending","Other"]},"numOrNull":["offensesequence","chargesequence"],"dateFields":["chargefiledate","chargestatusdate","chargedispositiondate"]},"di-aoic-probation-individual-background":{"required":[],"enums":{"benefitsaabd":["Yes","No"],"benefitsfca":["Yes","No"],"benefitssnap":["Yes","No"],"benefitsssi":["Yes","No"],"benefitstanf":["Yes","No"],"benefitsta":["Yes","No"],"benefitswic":["Yes","No"],"benefitsssdi":["Yes","No"],"benefitsmedicaid":["Yes","No"],"benefitsmedicare":["Yes","No"],"benefitsqualaabd":["Yes","No"],"benefitsqualfca":["Yes","No"],"benefitsqualsnap":["Yes","No"],"benefitsqualssi":["Yes","No"],"benefitsqualtanf":["Yes","No"],"benefitsqualta":["Yes","No"],"benefitsqualwic":["Yes","No"],"benefitsqualssdi":["Yes","No"],"benefitsqualmedicaid":["Yes","No"],"benefitsqualmedicare":["Yes","No"],"individualrepresentedcr":["Yes","No"],"whorepresentedcr":["Public","Private"],"accommodationneededcr":["Yes","No"],"accomodationreceivedcr":["Yes","No"],"interpreterneededcr":["Yes","No"],"interpretertypeneededcr":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterreceivedcr":["Yes","No"],"individualrepresentedcp":["Yes","No"],"whorepresentedcp":["Public","Private"],"accommodationneededcp":["Yes","No"],"accomodationreceivedcp":["Yes","No"],"interpreterneededcp":["Yes","No"],"interpretertypeneededcp":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterreceivedcp":["Yes","No"],"insurance12mo":["Yes","No"],"insurancecurrently":["Yes","No"],"insurancethrough":["Current or Former Employer (Self)","Current or Former Employer (Spouse)","Dependent on Parent(s) Insurance","Government Program","Self-Funded","Other"],"insurancetype":["Single","Limited Family (Employee + Spouse or Employee + Children)","Full Family (Employee, Spouse + Children)","No"],"noinsurancebelieve":["Yes","No"],"noinsurancerefuse":["Yes","No"],"noinsuranceeligible":["Yes","No"],"noinsuranceemployernopay":["Yes","No"],"noinsurancecantafford":["Yes","No"],"noinsurancedissatisfied":["Yes","No"],"noinsurancenotqualified":["Yes","No"],"noinsuranceother":["Yes","No"],"validildl":["Yes - Active","No - Inactive","Never acquired a driver's license","Not Applicable - Under 16"],"addresstype":["Known","Unknown","Homeless"],"state":["AK","AL","AR","AS","AZ","CA","CO","CT","DC","DE","FL","GA","GU","HI","IA","ID","IL","IN","KS","KY","LA","MA","MD","ME","MI","MN","MO","MP","MS","MT","NC","ND","NE","NH","NJ","NM","NV","NY","OH","OK","OR","PA","PR","RI","SC","SD","TN","TX","UM","UT","VA","VI","VT","WA","WI","WV","WY"],"educationalattainment":["8th grade or less","9th grade","10th grade","11th grade","Diploma/GED","Attended College","Technical degree","4 year degree","Post-graduate"],"studentstatus":["Full-time Student","Part-time Student","Not Enrolled"],"employmentstatus":["Unemployed/Looking","Part-time","Full-time","Not Employed - Stay at Home Parent","Not Employed - Full-time Student","Not Employed - Disability","Not Employed - Retired"],"selfemployed":["Yes","No"],"maritalstatus":["Married","Widowed","Divorced","Separated","Never Married","Other"],"housingtype":["Incarcerated","Facility","Home/Apartment","Temporary/Foster","Transient (or Homeless)"],"livingsituation":["Alone","Children Only","Family","Partner (or Boyfriend/Girlfriend)","Partner (or Boyfriend/Girlfriend) & Children","Roommate(s) & Spouse","Roommate(s), Spouse, & Children","Roommate(s) Only","Roommate(s) & Children","Spouse Only","With Parents/Guardian Only","With Parents/Guardian & Children","With Parents/Guardian & Family","With Parents/Guardian & Spouse","Other Relatives"],"children":["Yes","No"],"parentalrightsterminated":["Yes","No"],"childsupportcurrent":["Yes","No","Not Applicable"],"military":["Yes","No"],"airforce":["Yes","No"],"army":["Yes","No"],"coastguard":["Yes","No"],"marinescorps":["Yes","No"],"navy":["Yes","No"],"spaceforce":["Yes","No"],"reserves":["Yes","No"],"nationalguard":["Yes","No"],"rotc":["Yes","No"],"jrotc":["Yes","No"],"militaryactive":["Yes","No"],"militarydischarged":["Yes","No"],"militaryretired":["Yes","No"],"militaryveteran":["Yes","No"],"militaryrank":["Enlisted","Non-Commissioned Officer","Warrant Officer","Officer"],"militarydischargetype":["Bad Conduct Discharge","Dishonorable Discharge","Entry-Level Separation Discharge","General Discharge Under Honorable Conditions","Honorable Discharge","Medical Discharge","Other than Honorable Conditions Discharge","Separation for the Convenience of the Government Discharge"]},"numOrNull":["householdsize","childrennum","parentalrightsterminatednum","parentalrightsterminatedinv","parentalrightsterminatedvol","militaryyearsserved"],"dateFields":[]},"di-aoic-probation-active-status":{"required":[],"enums":{"curroffenseclassification":["Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony"],"curroffenseadultjuvenile":["Adult","Juvenile"],"sentencedtype":["1st Offender Methamphetamine","1st Time Weapon Offender","2nd Chance","410 Probation","550","Child Endangerment Probation","Conditional Discharge","Supervision","Continued Under Supervision (CUS)","Informal Supervision","Juvenile Diversion","Probation","Public Service Work Only","Other"],"risklevel":["Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"sentencingstatus":["Active","Administrative","In Full"],"sentencingadminreason":["County Jail","IDOC/IDJJ","Low Assessment Level","Outstanding Financial Obligation","Problem-Solving Court","Transfer Out (Inter)","Transfer Out (Intra)","Warrant"],"supervisingcourt":["Cook","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23"],"transfertype":["Instanter","NonInstanter","In Full","N/A"],"supervisingstatus":["Active","Administrative"],"supervisingadminreason":["County Jail","IDOC/IDJJ","Low Assessment Level","Outstanding Financial Obligation","Problem-Solving Court","Transfer Out (Inter)","Transfer Out (Intra)","Warrant"]},"numOrNull":["individualcell","supervisingofficercell"],"dateFields":["transferdate"]},"di-aoic-probation-supervision-and-sentencing":{"required":[],"enums":{"conviction3yr":["Yes","No"],"conddrugtesting":["Yes","No"],"condcurfew":["Yes","No"],"condelecmonitoring":["Yes","No"],"condbdlawmonitoring":["Yes","No"],"condalcmonitoringdevice":["Yes","No"],"condalcmonitoringignition":["Yes","No"],"condalcmonitoringhome":["Yes","No"],"condalcmonitoringcam":["Yes","No"],"condalcmonitoringother":["Yes","No"],"condgpsmonitoring":["Yes","No"],"condgpsexclzones":["Yes","No"],"condgpsnoexclzones":["Yes","No"],"condgpsinclzones":["Yes","No"],"condgpsnoinclzones":["Yes","No"],"condgpsactivepassive":["Active","Passive"],"condotherelec":["Yes","No"],"condhomeconfine":["Yes","No"],"condnocontactnonvictim":["Yes","No"],"condnocontactvictim":["Yes","No"],"condotherfincob":["Yes","No"],"condpaydrugtesting":["Yes","No"],"condpayem":["Yes","No"],"condpayfines":["Yes","No"],"condpayrestitution":["Yes","No"],"condpayprobationfees":["Yes","No"],"condprohibitedactivity":["Yes","No"],"condprohibitedarea":["Yes","No"],"condpublicservice":["Yes","No"],"condregarson":["Yes","No"],"condregsexoff":["Yes","No"],"condregmvoay":["Yes","No"],"condregcombdna":["Yes","No"],"condswap":["Yes","No"],"condshoplifter":["Yes","No"],"condspeclevelofreporting":["Yes","No"],"condsurrfirearms":["Yes","No"],"condsurrpassport":["Yes","No"],"condtrafficschool":["Yes","No"],"condvictimimpactpanel":["Yes","No"],"condwriteletter":["Yes","No"],"condother":["Yes","No"]},"numOrNull":["convfelil","convmisil","convfelother","convmisoutstate","condjailtime","condpublicservicehrs","condswapdays","compofficecontacts","missedofficecontacts","compfieldcontacts","missedfieldcontacts","comphomecontacts","missedhomecontacts","compcollateralfieldcontacts","missedcollateralfieldcontacts","compcollaterialhomecontacts","missedcollaterialhomecontacts","compvirtualcontacts","missedvirtualcontacts"],"dateFields":["supervisionstartdate","firsthomecontactdate","initcaseplandevelopdate","initcaseplanenterdate"]},"di-aoic-probation-intake":{"required":[],"enums":{"arrestwarrant":["Yes","No"],"initoffenseclassification":["Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony"],"initoffenseadultjuvenile":["Adult","Juvenile"],"initsentencetype":["1st Offender","1st Offender Program","2nd Chance","410 Probation","550","Child Endangerment Probation","Conditional Discharge","Supervision","Continued Under Supervision (CUS)","Informal Supervision","Probation","Public Service Work Only","Other"],"firstaralevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"firstaraoverridereason":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"firstaraoverridelevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"firstjralevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"firstjraoverridereason":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"firstjraoverridelevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"firstlsirlevel":["N/A","Low","Low/Moderate","Moderate","Medium/High","High"],"firstlsiroverridereason":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"firstlsiroverridelevel":["N/A","Low","Low/Moderate","Moderate","Medium/High","High"],"firstyasilevel":["N/A","Low","Moderate","High","Very High"],"firstyasioverridereason":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"firstyasioverridelevel":["N/A","Low","Moderate","High","Very High"],"usealcohol":["Yes","No"],"useamphetamines":["Yes","No"],"usebarbituates":["Yes","No"],"usebenzodiazepines":["Yes","No"],"usecrackcocaine":["Yes","No"],"usehallucinogens":["Yes","No"],"useheroin":["Yes","No"],"useinhalants":["Yes","No"],"usemarijuana":["Yes","No"],"usemethamphetamine":["Yes","No"],"useopiates":["Yes","No"],"usesynthetics":["Yes","No"],"useother":["Yes","No"],"prescriptionalcohol":["Yes","No"],"prescriptionamphetamines":["Yes","No"],"prescriptionbarbituates":["Yes","No"],"prescriptionbenzodiazepines":["Yes","No"],"prescriptioncrackcocaine":["Yes","No"],"prescriptionhallucinogens":["Yes","No"],"prescriptioninhalants":["Yes","No"],"prescriptionheroin":["Yes","No"],"prescriptionmarijuana":["Yes","No"],"prescriptionmethamphetamine":["Yes","No"],"prescriptionopiates":["Yes","No"],"prescriptionsynthetics":["Yes","No"],"prescriptionother":["Yes","No"]},"numOrNull":["initoffensecounts"],"dateFields":["arrestdate","initoffensedate","adjudicationdate","intakestartdate","orientationdate","preliminaryreviewdate","juvdiversionscreendate","ucciselfreportdate","screenercompletedate","firstassessmentdate","feedbackdate","intakeenddate"]},"di-aoic-probation-programming-and-treatment":{"required":[],"enums":{"courtangermanagement":["Yes","No"],"courtcbt":["Yes","No"],"courtcbtart":["Yes","No"],"courtcbtdbt":["Yes","No"],"courtcbtmrt":["Yes","No"],"courtcbtt4c":["Yes","No"],"courtcbtother":["Yes","No"],"courtdomviolenceeval":["Yes","No"],"courtdomviolenceevaltreatment":["Yes","No"],"courtdrugalcoholeval":["Yes","No"],"courtdrugalcoholevaltreatment":["Yes","No"],"courtduieval":["Yes","No"],"courtduievaltreatment":["Yes","No"],"courtgamblingeval":["Yes","No"],"croutgamblingevaltreatment":["Yes","No"],"courtgenderservice":["Yes","No"],"courtinitindividualtherapy":["Yes","No"],"courtmedeval":["Yes","No"],"courtmedevaltreatment":["Yes","No"],"courtmedicationmanag":["Yes","No"],"courtmentalhealtheval":["Yes","No"],"courtmentalhealthevaltreatment":["Yes","No"],"courtinitparentinged":["Yes","No"],"courtinitselfhelpgroup":["Yes","No"],"courtsexoffender":["Yes","No"],"courtsexoffendereval":["Yes","No"],"courtshopliftertreatment":["Yes","No"],"courttraumaeval":["Yes","No"],"courttraumaevaltreatment":["Yes","No"],"courtpsctreatment":["Yes","No"],"courttreatmentother":["Yes","No"],"probationangermanage":["Yes","No"],"probationcbt":["Yes","No"],"probationcbtart":["Yes","No"],"probationcbtdbt":["Yes","No"],"probationcbtmrt":["Yes","No"],"probationcbtt4c":["Yes","No"],"probationcbtother":["Yes","No"],"probationdomviolenceeval":["Yes","No"],"probationdomviolenceevaltreatment":["Yes","No"],"probationdrugalcoholeval":["Yes","No"],"probationdrugalcoholevaltreatment":["Yes","No"],"probationduieval":["Yes","No"],"probationduievaltreatment":["Yes","No"],"probationgamblingeval":["Yes","No"],"probationgamblingevaltreatment":["Yes","No"],"probationgenderservice":["Yes","No"],"proabtioninitindividualtherapy":["Yes","No"],"probationmedeval":["Yes","No"],"probationmedevaltreatment":["Yes","No"],"probationmedicationmanag":["Yes","No"],"probationmentalhealtheval":["Yes","No"],"probationmentalhealthevaltreatment":["Yes","No"],"probationinitparentinged":["Yes","No"],"probationinitselfhelpgroup":["Yes","No"],"probationsexoffender":["Yes","No"],"probationsexoffendereval":["Yes","No"],"probationshopliftertreatment":["Yes","No"],"probationtraumaeval":["Yes","No"],"probationtraumaevaltreatment":["Yes","No"],"probationpsctreatment":["Yes","No"],"treattype":["ART","Anger Management","CBT","DBT","Domestic Violance Offender Treatment","Drug & Alcohol (or Substance Use Disorder) Treatment","Out-Patient Individual Therapy/Self Help","In-Patient Treatment","DUI Education & Treatment","Gambling Addiction Treatment","Gender Specific Services","Individual Therapy","Medical Treatment","Medication Management","Mental Health Treatment","Moral Reconation Therapy (MRT)","Parenting Education","Self Help Groups","Sex Offender Treatment","Shoplifting Treatment","T4C","Trauma Treatment","Other"],"ptart":["Yes","No"],"orderedby":["Court","Probation"],"ptanger":["Yes","No"],"ptcbt":["Yes","No"],"ptdbt":["Yes","No"],"ptdomviolence":["Yes","No"],"ptdrugalcohol":["Yes","No"],"ptsubstancegroupsupport":["Yes","No"],"ptsubstanceselfhelp":["Yes","No"],"ptsubstanceinpatienttreat":["Yes","No"],"ptduieducation":["Yes","No"],"ptgamblingaddic":["Yes","No"],"ptgenderspecifservice":["Yes","No"],"ptindividualtherapy":["Yes","No"],"ptmedicaltreatment":["Yes","No"],"ptmedicationmanagement":["Yes","No"],"mentalhealthtreatment":["Yes","No"],"ptmhgroupsupport":["Yes","No"],"ptmhoutpatienttreatment":["Yes","No"],"ptmhinpatienttreatment":["Yes","No"],"ptmrt":["Yes","No"],"ptparentinged":["Yes","No"],"ptselfhelpgroup":["Yes","No"],"ptsexoffender":["Yes","No"],"ptshoptreatment":["Yes","No"],"ptt4c":["Yes","No"],"pttrauma":["Yes","No"],"ptprogrammingother":["Yes","No"]},"numOrNull":["referralnum","numtimesstart","numsuccess","numsuccessfulinhouse","numsuccessfulagency","numsuccessfulboth","numterminated","numunsuccessfulinhouse","numunsuccessfulagency","numunsuccessfulboth","treatmentdaystotal"],"dateFields":["firstreferraldate","firststartdate","laststartdate"]},"di-aoic-probation-ancillary-assessment":{"required":[],"enums":{"initialacesoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialacesadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialacute2007override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialacute2007admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer"],"initialasamoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialasamadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialbaddsrational":["Low","Moderate","High"],"initialbaddslenient":["Low","Moderate","High"],"initialbaddslikelihood":["Low","Moderate","High"],"initialbaddsdrinking":["Low","Moderate","High"],"initialbaddsriding":["Low","Moderate","High"],"initialbaddsoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialbaddsadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialcgassoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialcgassadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialcestmotivation":["Not a Problem","About Average","Maybe a Problem Area for You"],"initialcestpsychological":["Not a Problem","About Average","Maybe a Problem Area for You"],"initialcestsocial":["Not a Problem","About Average","Maybe a Problem Area for You"],"initialcestengagement":["Not a Problem","About Average","Maybe a Problem Area for You"],"initialcestoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialcestadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialcolumbiascaleoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialcolumbiascaleadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialdastscore":["0","1","2","3","4","5","6","7","8","9","10"],"initialdastoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialdastoverridescore":["0","1","2","3","4","5","6","7","8","9","10"],"initialdastadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialerasorscore":["Low","Moderate","High"],"initialerasoroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialerasoroverridescore":["Low","Moderate","High"],"initialerasoradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialgainioverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialgainiadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialgainq3override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialgainq3admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialgainssoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialgainssadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialansaoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialansaadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialimcansoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialimcansadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialidascore":["Low","Low-Medium","High-Medium","High"],"initialidaoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialidaoverridescore":["Low","Low-Medium","High-Medium","High"],"initialidaadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initiallocusoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initiallocusadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialmastoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialmastadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialpcesoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialpcesadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialprofesoroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialprofesoradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialpcptsdoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialpcptsdadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialrantscore":["High Risk/High Need","Low Risk/High Need","High Risk/Low Need","Low Risk/Low Need"],"initialrantoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialrantoverridescore":["High Risk/High Need","Low Risk/High Need","High Risk/Low Need","Low Risk/Low Need"],"initialrantadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialstaroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialstaradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialsassi3score":["High","Low"],"initialsassi3override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialsassi3overridescore":["High","Low"],"initialsassi3admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialsbqroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialsbqradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialstable2007override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialstable2007admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialstatic99override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialstatic99admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialtcuvoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialtcuvadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"initialotheroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"initialotheradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"]},"numOrNull":["initialacesscore","initialacesoverridescore","initialacute2007score","initialacute2007overridescore","initialasamscore","initialasamoverridescore","initialcgasscore","initialcgassoverridescore","initialcolumbiascalescore","initialcolumbiascaleoverridescore","initialansascore","initialansaoverridescore","initialimcansscore","initialimcansoverridescore","initiallocusscore","initiallocusoverridescore","initialmastscore","initialmastoverridescore","initialpcesscore","initialpcesoverridescore","initialprofesorscore","initialprofesoroverridescore","initialpcptsdscore","initialpcptsdoverridescore","initialstarscore","initialstaroverridescore","initialsbqrscore","initialsbqroverridescore","initialstable2007score","initialstable2007overridescore","initialstatic99score","initialstatic99overridescore","initialtcuvscore","initialtcuvoverridescore"],"dateFields":["initialaces","initialacute2007","initialasam","initialbadds","initialcgas","initialcest","initialcolumbiaimpairscale","initialdast","initialerasor","initialgaini","initialgainq3","initialgainss","initialansa","initialimcans","initialida","initiallocus","initialmast","initialpces","initialprofesor","initialpcptsd","initialrant","initialstar","initialsassi3","initialsbqr","initialstable2007","initialstatic99","initialtcuv","initialother","firstassessmentsummarydate"]},"di-aoic-probation-drug-testing":{"required":[],"enums":{"drugscreenresult":["Positive","Negative"],"drugscreenalcohol":["Yes","No"],"drugscreenamphetamines":["Yes","No"],"drugscreenbarbituates":["Yes","No"],"drugscreenbenzodiazepines":["Yes","No"],"drugscreencrackcocaine":["Yes","No"],"drugscreenhallucinogens":["Yes","No"],"drugscreenheroin":["Yes","No"],"drugscreeninhalants":["Yes","No"],"drugscreenmarijuana":["Yes","No"],"drugscreenmethamphetamine":["Yes","No"],"drugscreenopiates":["Yes","No"],"drugscreensynthetics":["Yes","No"],"drugscreenother":["Yes","No"],"drugscreenmethod":["Blood","Hair","Urine","Saliva","Transdermal"],"drugscreenverify":["Yes","No"],"drugscreenfalsepositive":["Yes","No"]},"numOrNull":[],"dateFields":["drugscreendate"]},"di-aoic-probation-violations-and-sanctions":{"required":[],"enums":{"techviolationnoted":["Yes","No"],"absconding":["Yes","No"],"curfew":["Yes","No"],"elecmonitoring":["Yes","No"],"finesfees":["Yes","No"],"homeconfinement":["Yes","No"],"missedappt":["Yes","No"],"nocontactorder":["Yes","No"],"posdrugscreen":["Yes","No"],"pubservhours":["Yes","No"],"restitution":["Yes","No"],"treatnoncomp":["Yes","No"],"otherviol":["Yes","No"],"violationsentsao":["Yes","No"],"saooutcome":["Violation","No Violation","SAO Withdrew PTR"],"ptrfinding":["Revoke Resentence","Modification","PTR No Finding","PTR Dismissed"],"modification":["Extension of Probation","Serve Stayed Jail Time, Terminate","Serve Stayed Jail Time, Continue on Probation","Termination of Probation"]},"numOrNull":["dayreporting","confmonitoring","confnomonitoring","inccommrestrictions","incsupreqs","interventionprogs","lifeskillsints","pubservwork","verbaladmon","otherassignments","othersanctions","abscondingnum","curfewnum","emnum","sanctionfinesnum","homeconfinum","missedappoitnum","nocontactnum","drugscreennum","servicehoursnum","restitutionnum","treatmentnum","othernum"],"dateFields":["violationdate","violationsentsaodate","ptrsentdate"]},"di-aoic-probation-offenses":{"required":[],"enums":{"newoffenseclassification":["Class A Misdemeanor","Class B Misdemeanor","Class C Misdemeanor","Class M Felony","Class X Felony","Class 1 Felony","Class 2 Felony","Class 3 Felony","Class 4 Felony"],"newoffenseadultjuvenile":["Adult","Juvenile"],"newoffensearrestwarrant":["Yes","No"],"newoffenseviolation":["Yes","No"],"newoffenseviolationsent":["Yes","No"],"newoffensesentoutcome":["Violation","No Violation","SAO Withdrew PTR"],"newoffenseptrfinding":["Revoke Resentence","Modification","PTR No Finding","PTR Dismissed"],"newoffenseptrmod":["Extension of Probation","Serve Stayed Jail Time, Terminate","Serve Stayed Jail Time, Continue on Probation","Termination of Probation"]},"numOrNull":["newoffensecounts"],"dateFields":["newoffensedate","newoffensearrestdate","newoffenseadjudicationdate","newoffenseviolationdate","newoffenseviolationsentdate","newoffenseptrsent"]},"di-aoic-probation-termination":{"required":[],"enums":{"pscreferral":["Yes","No"],"psc":["Referral to Drug Court Screening","Referral to DUI Court Screening","Referral to Mental Health Court Screening","Referral to Veteran's Court Screening","Referral to Other Specialty Court Screening"],"pscaccepted":["Yes","No"],"finalaralevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"finalaraoverride":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"finalaraoverridescore":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"finaljralevel":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"finaljraoverride":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"finaljraoverridescore":["N/A","Low","Low-Moderate","Moderate","Moderate-High","High","Very High"],"finallsirlevel":["N/A","Low","Low/Moderate","Moderate","Medium/High","High"],"finallsiroverride":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"finallsiroverridescore":["N/A","Low","Low/Moderate","Moderate","Medium/High","High"],"finalyasilevel":["N/A","Low","Moderate","High","Very High"],"finalyasioverride":["Probation Officer's professional experience","Ancillary Assessment Tool","Office Policy","Gaps in Information","Barriers","Other"],"finalyasioverridescore":["N/A","Low","Moderate","High","Very High"],"finalacesoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalacesadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalacuteoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalacuteadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalasamoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalasamadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalbaddsrational":["Low","Moderate","High"],"finalbaddslenient":["Low","Moderate","High"],"finalbaddslike":["Low","Moderate","High"],"finalbaddsdrink":["Low","Moderate","High"],"finalbaddsriding":["Low","Moderate","High"],"finalbaddsoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalbaddsadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalcgasoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalcgasadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalcestscoremotivation":["Not a Problem","About Average","Maybe a Problem Area for You"],"finalcestscorepsychological":["Not a Problem","About Average","Maybe a Problem Area for You"],"finalcestscoresocial":["Not a Problem","About Average","Maybe a Problem Area for You"],"finalcestscoreengagement":["Not a Problem","About Average","Maybe a Problem Area for You"],"finalcestoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalcestadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalcolumbiascaleoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalcolumbiascaleadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finaldastoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finaldastadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalerasorscore":["Low","Moderate","High"],"finalerasoroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalerasoroverridescore":["Low","Moderate","High"],"finalerasoradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalgainioverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalgainiadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalgainq3override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalgainq3admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer"],"finalgainssoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalgainssadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalansaoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalansaadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalimcansoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalimcansadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalidascore":["Low","Low-Medium","High-Medium","High"],"finalidaoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalidaoverridescore":["Low","Low-Medium","High-Medium","High"],"finalidaadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finallocusoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finallocusadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalmastoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalmastadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalpcesoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalpcesadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalprofesoroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalprofesoradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalpcptsdoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalpcptsdadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalrantscore":["High Risk/High Need","Low Risk/High Need","High Risk/Low Need","Low Risk/Low Need"],"finalrantoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalrantoverridescore":["High Risk/High Need","Low Risk/High Need","High Risk/Low Need","Low Risk/Low Need"],"finalrantadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalstaroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalstaradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalsassi3score":["High","Low"],"finalsassi3override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalsassi3overridescore":["High","Low"],"finalsassi3admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalsbqroverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalsbqradmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalstableoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalstableadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalstatic99override":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finalstatic99admin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finaltcuvoverride":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"finaltcuvadmin":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"finalatotheroverridereason":["Clinician Professional Statement","Probation Officer's professional experience","Office Policy","Gaps in Information","Barriers","Other"],"fianlatotheradministered":["In-House Treatment Provider","Private Entity/Community Based Provider","Probation Officer","Treatment Alternatives for Safe Communities (TASC)"],"redeployaccept":["Yes","No"],"redeployacceptviol":["Yes","No"],"redeploytermreason":["AWOL","Completed Program","Conditional Release","Deceased","Declined After Intake","Dropped Out of Program","Probation Ended Before Program Completion","Program Interrupted","Program Terminated","Re-Sentenced to Other Probation","Re-Sentenced to Other Specialty Court","Revoked to IDOC/IDJJ","Revoked to Jail","Seriously Ill","Status Pending","Transferred - Other County","Transferred - Other Program","Other Outcome"],"noredeployreason":["Accepted - Participant Declined","Rejected - Criteria Based","Rejected - Capacity Based","State's Attorney Declined Enrollment"],"juvplacena":["Yes","No"],"juvplacefosterrel":["Yes","No"],"juvplacefostertrad":["Yes","No"],"juvplacefosterspec":["Yes","No"],"juvplacegroup":["Yes","No"],"juvplaceres":["Yes","No"],"juvplacefailed":["Yes","No"],"dcfsterm":["Yes","No"],"dcfsatintake":["Yes","No"],"dcfsfosterrel":["Yes","No"],"dcfsfostertrad":["Yes","No"],"dcfsfosterspec":["Yes","No"],"dcfsgrouphome":["Yes","No"],"dcfshotline":["Yes","No"],"dcfsinhomevol":["Yes","No"],"dcfsinhomecourt":["Yes","No"],"dcfsindicatedreport":["Yes","No"],"dcfsinvestigation":["Yes","No"],"dcfsresplacement":["Yes","No"],"dcfssinceintake":["Yes","No"],"dcfssinceintakelevelrelative":["Yes","No"],"dcfssinceintakeleveltraditional":["Yes","No"],"dcfssinceintakelevelspecialized":["Yes","No"],"dcfssinceintakelevelgroup":["Yes","No"],"dcfssinceintakelevelhotline":["Yes","No"],"dcfssinceintakelevelvoluntary":["Yes","No"],"dcfssinceintakelevelcourt":["Yes","No"],"dcfssinceintakelevelreport":["Yes","No"],"dcfssinceintakelevelinvestigation":["Yes","No"],"dcfssinceintakelevelresidential":["Yes","No"],"dcfsever":["Yes","No"],"dcsflevelrelative":["Yes","No"],"dcsfleveltraditional":["Yes","No"],"dcsflevelspecialized":["Yes","No"],"dcsflevelgrouphome":["Yes","No"],"dcsflevelhotline":["Yes","No"],"dcsflevelhomevoluntary":["Yes","No"],"dcsflevelhomecourt":["Yes","No"],"dcsflevelreport":["Yes","No"],"dcsflevelinvestigation":["Yes","No"],"dcsflevelrediential":["Yes","No"],"terminationtype":["Early","Scheduled"],"terminationreason":["Death","Neutral","Successful","Termination without Adverb/Unknown","Unsuccessful"],"unsuccessfulreason":["Both (Technical Violation and New Arrest)","New Arrest","Technical Violation","Other"],"unsuccessfuloutcomeconviction":["Yes","No"],"unsuccessfuloutcomeidjj":["Yes","No"],"unsuccessfuloutcomeidoc":["Yes","No"],"unsuccessfuloutcomejail":["Yes","No"],"unsuccessfuloutcomeother":["Yes","No"],"termbenefitsaabd":["Yes","No"],"termbenefitsfca":["Yes","No"],"termbenefitssnap":["Yes","No"],"termbenefitsssi":["Yes","No"],"termbenefitstanf":["Yes","No"],"tembenefitswic":["Yes","No"],"termbenefitsta":["Yes","No"],"termbenefitsssdi":["Yes","No"],"termbenefitsmedicaid":["Yes","No"],"termbenefitsmedicare":["Yes","No"],"termbenefitsqualaabd":["Yes","No"],"termbenefitsqualfca":["Yes","No"],"termbenefitsqualsnap":["Yes","No"],"termbenefitsqualssi":["Yes","No"],"termbenefitsqualtanf":["Yes","No"],"tembenefitsqualwic":["Yes","No"],"termbenefitsqualta":["Yes","No"],"termbenefitsqualssdi":["Yes","No"],"termbenefitsqualmedicaid":["Yes","No"],"termbenefitsqualmedicare":["Yes","No"],"terminsurance12mo":["Yes","No"],"terminsurancecurrent":["Yes","No"],"terminsurancethrough":["Current or Former Employer (Self)","Current or Former Employer (Spouse)","Dependent on Parent(s) Insurance","Government Program","Self-Funded","Other"],"terminsurancetype":["Single","Limited Family (Employee + Spouse or Employee + Children)","Full Family (Employee, Spouse + Children)","No"],"termnoinsurancebelieve":["Yes","No"],"termnoinsurancerefuse":["Yes","No"],"termnoinsuranceeligible":["Yes","No"],"termnoinsuranceemployernopay":["Yes","No"],"termnoinsurancecantafford":["Yes","No"],"termnoinsurancedissatisfied":["Yes","No"],"termnoinsurancenotqualified":["Yes","No"],"termnoinsuranceother":["Yes","No"],"termvalidildl":["Yes - Active","No - Inactive","Never acquired a driver's license","Not Applicable - Under 16"],"termaddresstype":["Known","Unknown","Homeless"],"termstate":["AK","AL","AR","AS","AZ","CA","CO","CT","DC","DE","FL","GA","GU","HI","IA","ID","IL","IN","KS","KY","LA","MA","MD","ME","MI","MN","MO","MP","MS","MT","NC","ND","NE","NH","NJ","NM","NV","NY","OH","OK","OR","PA","PR","RI","SC","SD","TN","TX","UM","UT","VA","VI","VT","WA","WI","WV","WY"],"termeducationalattainment":["8th grade or less","9th grade","10th grade","11th grade","Diploma/GED","Attended College","Technical degree","4 year degree","Post-graduate"],"termstudentstatus":["Full-time Student","Part-time Student","Not Enrolled"],"termemploymentstatus":["Unemployed/Looking","Part-time","Full-time","Not Employed - Stay at Home Parent","Not Employed - Full-time Student","Not Employed - Disability","Not Employed - Retired"],"termselfemployed":["Yes","No"],"termmaritalstatus":["Married","Widowed","Divorced","Separated","Never Married","Other"],"termhousingtype":["Incarcerated","Facility","Home/Apartment","Temporary/Foster","Transient (or Homeless)"],"termlivingsituation":["Alone","Children Only","Family","Partner (or Boyfriend/Girlfriend)","Partner (or Boyfriend/Girlfriend) & Children","Roommate(s) & Spouse","Roommate(s), Spouse, & Children","Roommate(s) Only","Roommate(s) & Children","Spouse Only","With Parents/Guardian Only","With Parents/Guardian & Children","With Parents/Guardian & Family","With Parents/Guardian & Spouse","Other Relatives"],"termchildren":["Yes","No"],"termparentalrightsterminated":["Yes","No"],"termchildsupportcurrent":["Yes","No","Not Applicable"],"termmilitaryservice":["Yes","No"],"termairforce":["Yes","No"],"termarmy":["Yes","No"],"termcoastguard":["Yes","No"],"termmarinecorps":["Yes","No"],"termnavy":["Yes","No"],"termspaceforce":["Yes","No"],"termreserves":["Yes","No"],"termnationalguard":["Yes","No"],"termrotc":["Yes","No"],"termjrotc":["Yes","No"],"termmilitaryactive":["Yes","No"],"termmilitarydischarged":["Yes","No"],"termmilitaryretired":["Yes","No"],"termmilitaryveteran":["Yes","No"],"termmilitaryrank":["Enlisted","Non-Commissioned Officer","Warrant Officer","Officer"],"termmilitarydischargetype":["Bad Conduct Discharge","Dishonorable Discharge","Entry-Level Separation Discharge","General Discharge Under Honorable Conditions","Honorable Discharge","Medical Discharge","Other than Honorable Conditions Discharge","Separation for the Convenience of the Government Discharge"],"empayee":["Individual","County","Court","Pretrial","Probation","State's Attorney Office","Sheriff's Department","Other"],"pswfineshours":["Yes","No"]},"numOrNull":["finalacesscore","finalacesoverridescore","finalacutescore","finalacuteoverridescore","finalasamscore","finalasamoverridescore","finalcgasscore","finalcgasoverridescore","finalcolumbiascalescore","finalcolumbiascaleoverridescore","finaldastscore","finaldastoverridescore","finalansascore","finalansaoverridescore","finalimcansscore","finalimcansoverridescore","finallocusscore","finallocusoverridescore","finalmastscore","finalmastoverridescore","finalpcesscore","finalpcesoverridescore","finalprofesorscore","finalprofesoroverridescore","finalpcptsdscore","finalpcptsdoverridescore","finalstarscore","finalstaroverridescore","finalsbqrscore","finalsbqroverridescore","finalstablescore","finalstableoverridescore","finalstatic99score","finalstatic99overridescore","finaltcuvscore","finaltcuvoverridescore","juvplacefailednum","dcfsfirstage","termhouseholdsize","termchildrennum","termparentalrightsterminatednum","termparentalrightsterminatedinv","termparentalrightsterminatedvol","termmilitaryyearsserved","emdays","swapdays","pswhours","pswhoursconverted","pswhourscompleted","jailtimedays"],"dateFields":["termucciselfreportdate","termfinalassessmentdate","finalaces","finalacute","finalasam","finalbadds","finalcgas","finalcest","finalcolumbiaimspirscale","finaldast","finalerasor","finalgaini","finalgainq3","finalgainss","finalansa","finalimcans","finalida","finallocus","finalmast","finalpces","finalprofesor","finalpcptsd","finalrant","finalstar","finalsassi3","finalsbqr","finalstable","finalstatic99","finaltcuv","finalassessmenttoolother","finalassessmentsummarydate","redeployacceptdate","redeployvioldate","redeploytermdate","juvplaceadmindate","juvplacedischargedate","dcfsstartdate","dcfsenddate","dcfssinceintakestartdate","dcfssinceintakeenddate","terminationdate","fileterminationdate","emstartdate","emenddate"]},"di-aoic-trialcourt-adr":{"required":["casecategorycode","casegroup","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","chargedisposition","chargedispositiondate","chargedispositiontype","chargepenaltyclass","chargesequencenumber","chargesourcelevelofgovernment","chargestatuscode","circuitcourtncicnumber","datesentenced","defendantaddress1","defendantaddress2","defendantaliasfirstname","defendantaliaslastname","defendantaliasmiddlename","defendantaliastitlesuffix","defendantbonddate","defendanteyecolor","defendantfirstname","defendantgender","defendanthaircolor","defendantlastname","defendantmiddlename","defendantplea","defendantrace","defendantresidencecity","defendantresidencestate","defendantresidencezipforeignpostalcode","defendantsequencenumber","docmaximumtime","docminimumtime","inchoateoffensecode","injurydeathindicator","motorvehicleinvolvement","offensechargedescription","offensecodetable","recordid","vendorname"],"enums":{"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"chargedisposition":["101","102","103","104","105","106","107","108","109","110","201","202","203","204","205","206","207","208","209","210","211","212","213","214","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","301","302","303","304","305","307","350","352","351","353","354","355","356","357","358","359","360","401","402","403","405","407","408","409","410","411","412","413","414","415","416","501","502","503","504","505","506","507","508","509","510","511","601","602","603","604","605","606","607","608","610","613","615","616","617","618","650","651","652","653","654","701","702","704","705","706","707","708","709","710","801","802","803","804","888"],"chargedispositiontype":["1","2","3","4","5","6"],"chargepenaltyclass":["M","X","1","2","3","4","A","B","C","P","U","O"],"chargesourcelevelofgovernment":["1","2","3","4"],"chargestatuscode":["1","2","3","4"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"defendantaliastitlesuffix":["Sr.","Jr.","I","II","III","IV","V"],"defendantbondtype1":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","25"],"defendantbondtype2":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","25"],"defendantgender":["Male","Female","X","Unknown"],"defendantplea":["0 Admit/Consent","1 Not Guilty","2 Guilty","3 Not Guilty/Insanity Defense","4 Guilty but Mentally Ill","5 No Contest","6 No Plea Entered","7 Admission to Delinquency Petition","8 Denial of Delinquency Petition","9 Electronic Plea of Guilty"],"defendantrace":["American Indian or Alaskan Native","Asian or Pacific Islander","Black or African American","White or Caucasian","Hispanic or Latino","Unknown"],"defendantethnicity":["Hispanic/Latinx/Latino/Latina","Non-Hispanic/Latinx/Latino/Latina"],"driverpassenger":["D Driver","P Passenger","U Unknown"],"inchoateoffensecode":["C","S","A","D","E","M","O"],"injurydeathindicator":["I-Driver injury only","P-Personal injury","D-Death","V-Vehicle or other property damage"],"motorvehicleinvolvement":["Yes","No","Unknown"],"relationshiptovictim":["NA","01-Current or former spouse","02-Parent/step-parent","03-Guardian","04-Child in common","05-Person is cohabitating or has cohabitated as spouse","06-Person is cohabitating or has cohabitated as parent","07-Person is cohabitating or has cohabitated as guardian","08-Person similarly situated to spouse","09-Person similarly situated to parent","10-Person similarly situated to guardian"],"sentencestatus1":["1-Sentence in Force","2-Waived","3-Suspended","4-Suspended in Part","5-Concurrent","6-Consecutive","7-Stayed"],"sentencetype1":["102","103","201","202","203","204","205","206","207","208","209","210","211","212","213","214","215","216","217","218","219","220","221","222","223","224","225","226","227","301","302","303","304","401","402","403","404","405","406","407","408","409","410","411","412","413","414","415","416","417","418"],"vehicletype1":["000-Pedestrian","001-Passenger Car","002-Recreation Vehicle","003-Bus","004-Truck Tractor","005-Trailer or Semi Trailer","006-Motorcycle","007-Other"],"vehicletype2":["000-Pedestrian","001-Passenger Car","002-Recreation Vehicle","003-Bus","004-Truck Tractor","005-Trailer or Semi Trailer","006-Motorcycle","007-Other"],"vehicletype3":["000-Pedestrian","001-Passenger Car","002-Recreation Vehicle","003-Bus","004-Truck Tractor","005-Trailer or Semi Trailer","006-Motorcycle","007-Other"],"vehicletype4":["000-Pedestrian","001-Passenger Car","002-Recreation Vehicle","003-Bus","004-Truck Tractor","005-Trailer or Semi Trailer","006-Motorcycle","007-Other"],"vehicletype5":["000-Pedestrian","001-Passenger Car","002-Recreation Vehicle","003-Bus","004-Truck Tractor","005-Trailer or Semi Trailer","006-Motorcycle","007-Other"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury","civilpenaltyamount","defendantbonddepositamount","defendantbondfaceamount","defendantsocialsecuritynumber","docmaximumtime","docminimumtime","fineamount","publicservicehours","registrationyear","restitutionamount","sentencelength1","speedactual","speedposted","totaljudgmentamount","vehicleyear","victimage"],"dateFields":["chargedispositiondate","dateofoffense","datesentenced","defendantbonddate","defendantdateofarrest","defendantdateofbirth","driverslicenseissuancedate","feecollectiondate"]},"di-aoic-trialcourt-case-status":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casestatus","casetype","caseyear","circuitcourtncicnumber","datecaseinitiated","defendantsequencenumber","recordid","statusdate","timecaseinitiated","vendorname"],"enums":{"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casestatus":["Open","Reinstated","Reactivated","Inactive","Closed"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"civilcaseclosuremethod":["1 Jury Trial","2 Bench Trial","3 Judgment","4 Dismissal"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"reasoninactive":["Warrant","Unfit to stand trial","Pre-Trial Diversion Specialty Court","Interlocutory Appeal","Failure to Appear","Judgment Bond Forfeiture","Bankruptcy Petition","Other","Mentally Disabled","Offender Initiative Program","Sexually Dangerous"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury"],"dateFields":["datecaseinitiated","statusdate"]},"di-aoic-trialcourt-documents":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","dateorderofprotectionfiled","orderofprotectionname","orderofprotectiontype","recordid","vendorname"],"enums":{"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"civilinitiatinginsturmentpleading":["Petition (Juvenile only)","Complaint (Excluding Uniform Citations)","Uniform Citation and Complaint Form","Information","Indictment","Transfer from other jurisdiction/level of court"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"orderofprotectionname":["Civil No Contact Order","Firearms Restraining Order","Orders of Protection","Stalking No Contact Orders"],"orderofprotectiontype":["Emergency","Interim","Plenary"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury"],"dateFields":["dateorderofprotectionfiled"]},"di-aoic-trialcourt-financial":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","feeamount","recordid","vendorname"],"enums":{"assessmentschedule":["1","2","3","4","5","6","7","8","9","10","10.5","11","12","13"],"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"conditionalassessmenttype":["Arson Assessment","Child Pornography Assessment","Crime Laboratory Drug Analysis","DNA Analysis Assessment","DUI Analysis Assessment","Street Value Drug Related Assessment - Controlled Substances","Kane or Will County 5-1101.3 Assessment","Street Value Drug Related Assessment - Methamphetamines","Order of Protection violations - Domestic Violence Surveillance Programs","Order of Protection violations - Domestic Violence Abuser Services","State's Attorney Records Automation Assessment","Public Defender Records Automation Assessment","Speeding Construction Zone - Transportation Safety Highway Hire-back Funds","IVC Supervision - Prisoner Review Board Vehicle and Equipment Fund","Domestic Violence family/household members - Domestic Violence Shelter and Service Fund","Domestic Violence family/household members - Sexual Assault Services Fund","Emergency Response - DUI/OUI","Emergency Response - Drug Response","Emergency Response - Speed/Reckless Driving Response","Human Trafficking Assessment","Weapons related violation - Trauma Center Fund","Other"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"distributioncategory":["Maintenance and Child Support","Fines, Penalties, Assessments, Charges and Forfeitures (non-state)","Fines, Penalties, Assessments, Charges and Forfeitures (state)","Fees of Others","Miscellaneous Disbursements"],"distributionfund":["CLERK'S OFFICE","STATE DISBURSEMENT UNIT","MUNICIPALITIES-ALL EXCEPT DRUG FINES","MUNICIPALITIES-DRUG FINES","MUNICIPALITIES-CRIME LABORATORY FUND","MUNICIPALITIES-CRIME LABORATORY DUI FUND","DRUG TASK FORCE","TOWNSHIPS AND DISTRICTS-ALL EXCEPT DRUG FINES","TOWNSHIPS AND DISTRICTS-DRUG FINES","COUNTY-CRIMINAL FINES","COUNTY-TRAFFIC FINES","COUNTY-DRUG FINES","COUNTY-CRIME LABORATORY FUND","COUNTY-CRIME LABORATORY DUI FUND","COUNTY-COUNTY BOATING FUND","STATE-DNR FUNDS TOTAL","STATE-ROAD FUND (OVERWEIGHTS)","STATE-STATE TOLL HIGHWAY AUTHORITY FUND","STATE-DRUG TRAFFIC PREVENTION FUND","STATE-STATE CRIME LABORATORY FUND","STATE-STATE POLICE DUI FUND","STATE-VIOLENT CRIME VICTIMS ASSISTANCE FUND","STATE-TRAFFIC AND CRIMINAL CONVICTION SURCHARGE","STATE-DRIVERS EDUCATION FUND","STATE-DOMESTIC VIOLENCE SHELTER AND SERVICE FUND","STATE-DRUG TREATMENT FUND","STATE-CHILD ABUSE PREVENTION FUND","STATE-SEXUAL ASSAULT SERVICES FUND","STATE-TRAUMA CENTER FUND","STATE-PERCENTAGE DISTRIBUTION: UNDER $55 FUND","STATE-PERCENTAGE DISTRIBUTION: $55 AND OVER FUND","STATE-GENERAL REVENUE FUND","STATE-EMS ASSISTANCE FUND","STATE-YOUTH DRUG ABUSE PREVENTION FUND","STATE-SECRETARY OF STATE EVIDENCE FUND","STATE-ILLINOIS CHARITY BUREAU FUND","STATE-TRANSPORTATION REGULATORY FUND","STATE-PROFESSIONAL REGULATION EVIDENCE FUND","STATE-GENERAL PROFESSIONS DEDICATED FUND","STATE-LOBBYIST REGISTRATION ADMINISTRATION FUND","STATE-DESIGN PROFESSIONAL ADMIN. AND INVESTIGATION FUND","STATE-REAL ESTATE RECOVERY FUND","STATE-AGGREGATE OPERATIONS REGULATORY FUND","STATE-EDUCATION ASSISTANCE FUND","STATE-DEPARTMENT OF PUBLIC HEALTH","STATE-USED TIRE MANAGEMENT FUND","STATE-EMERGENCY PLANNING AND TRAINING FUND","STATE-FEED CONTROL FUND","STATE-PESTICIDE CONTROL FUND","STATE-SPINAL CORD INJURY PARALYSIS CURE RESEARCH TRUST FUND","STATE-FIRE PREVENTION FUND","STATE-WIC PROGRAM","STATE-OFFENDER REGISTRATION FUND","STATE-SECURITIES AUDIT AND ENFORCEMENT FUND","STATE-SPECIAL ADMINISTRATIVE FUND","STATE-LEADS MAINTENANCE FUND","STATE-STATE OFFENDER DNA IDENTIFICATION SYSTEM FUND","STATE-DOMESTIC VIOLENCE ABUSER SERVICES FUND","STATE-ABANDONED RESIDENTIAL PROPERTY MUNICIPALITY RELIEF FUND","STATE-LUMP SUM SURCHARGE*","STATE-MENTAL HEALTH REPORTING FUND","STATE-ARSONIST REGISTRATION FUND","STATE-CAPITAL PROJECTS FUND","STATE-MURDERER & VIOLENT OFF. AGAINST YOUTH REG. FUND","STATE-CORPORATE CRIME FUND","STATE-DIESEL EMISSIONS TESTING FUND","STATE-PERFORMANCE-ENHANCING SUBSTANCE TESTING","STATE-FIRE TRUCK REVOLVING LOAN FUND","STATE-FORECLOSURE PREVENTION PROGRAM FUND","STATE-FORECLOSURE PREVENTION \"GRADUATED\" FUND","STATE-ILLINOIS ANIMAL ABUSE FUND","STATE-IDOC PAROLE DIVISION OFFENDER SUPERVISION FUND","STATE-ILLINOIS RACING BOARD","STATE-LEAD POISON SCREENING, PREVENTION AND ABATEMENT FUND","STATE-METHAMPHETAMINE LAW ENFORCEMENT FUND","STATE-MILITARY FAMILY RELIEF FUND","STATE-PRISONER REVIEW BOARD VEHICLE & EQUIPMENT FUND","STATE-ROADSIDE MEMORIAL FUND","STATE-TRUCKING ENVIRONMENTAL & EDUCATION FUND","STATE-SECRETARY OF STATE POLICE DUI FUND","STATE-SECRETARY OF STATE POLICE SERVICES FUND","STATE-SECRETARY OF STATE POLICE VEHICLE FUND","STATE-SEX OFFENDER INVESTIGATION FUND","STATE-STATE ASSET FORFEITURE FUND","STATE-STATE POLICE OPERATIONS ASSISTANCE FUND","STATE-STATE POLICE STREETGANG-RELATED CRIME FUND","STATE-STATE POLICE VEHICLE FUND","STATE-TRANSPORTATION SAFETY HIGHWAY HIRE-BACK FUND","STATE-VEHICLE INSPECTION FUND","STATE-CONSERVATION POLICE OPERATIONS ASSISTANCE FUND","STATE-PRESCRIPTION PILL AND DRUG DISPOSAL FUND","STATE-CRIMINAL JUSTICE INFORMATION PROJECTS FUND","STATE-STATE POLICE SERVICES FUND","STATE-STATE POLICE MERIT BOARD PUBLIC SAFETY FUND","STATE-GUARDIANSHIP AND ADVOCACY FUND","STATE-SPECIALIZED SERVICES FOR SURVIVORS OF HUMAN TRAFFICKING FUND","STATE-ACCESS TO JUSTICE FUND","STATE-STATE'S ATTORNEYS APPELLATE PROSECUTOR","STATE-SUPREME COURT SPECIAL PURPOSES FUND","STATE-GEORGE BAILEY MEMORIAL FUND","STATE-STATE POLICE LAW ENFORCEMENT ADMINISTRATIVE FUND","STATE-COMMERCE COMMISION PUBLIC UTILITY FUND","STATE-SCOTT'S LAW FUND (effective 1/1/2020)","STATE-LAW ENFORCEMENT CAMERA GRANT FUND","STATE'S ATTORNEY-FEES","STATE'S ATTORNEY-RECORDS AUTOMATION FUND","SHERIFF-FEES (e.g. SERVICE OF PROCESS*)","SHERIFF-COUNTY GENERAL FUND FOR COURT SECURITY","COUNTY LAW LIBRARY FUND","MARRIAGE FUND OF THE CIRCUIT COURT","COUNTY FUND TO FINANCE THE COURT SYSTEM","COURT-APPOINTED COUNSEL-DEFENSE COUNSEL","COURT-APPOINTED COUNSEL-JUVENILE REPRESENTATION","COURT-APPOINTED COUNSEL: STATE APPELLATE DEFENDER","MUNICIPAL ATTORNEY PROSECUTION FEE","PROBATION AND COURT SERVICES FUND","DISPUTE RESOLUTION FUND","MANDATORY ARBITRATION FUND-ARBITRATION FEE","MANDATORY ARBITRATION FUND-REJECTION OF AWARD","DRUG/ALCOHOL TESTING & ELECTRONIC MONITORING FEE","ELECTRONIC MONITORING DEVICE FEE-SUBSTANCE ABUSE SERVICES FUND","ELECTRONIC MONITORING DEVICE FEE-WORKING CASH FUND","COUNTY GENERAL FUND TO FINANCE EDUCATION PROGRAMS (DUI)","COUNTY HEALTH FUND","TRAFFIC SAFETY PROGRAM SCHOOL","COUNTY JAIL MEDICAL COSTS FUND","SEXUALLY TRANSMITTED DISEASE TEST FUND","DOMESTIC RELATIONS LEGAL FUND","CHILDREN'S WAITING ROOM FUND","NEUTRAL SITE CUSTODY EXCHANGE FUND","MORTGAGE FORECLOSURE MEDIATION PROGRAM FEES","CHILDREN'S ADVOCACY CENTER","COURT APPOINTED SPECIAL ADVOCATE (CASA)","DRUG COURT","JUDICIAL FACILITIES FEE","MENTAL HEALTH/DRUG/VETERANS AND SERVICE MEMBERS COURT","YOUTH DIVERSION PROGRAM","PUBLIC DEFENDER RECORDS AUTOMATION FUND","COUNTY DRUG ADDICTION SERVICES","RESTITUTION TO VICTIMS OF CRIME (INCLUDES JUVENILE)","\"WORK RELEASE\" / GAINFULLY EMPLOYED OFFENDER-TOTAL PAID TO COUNTY FOR ROOM AND BOARD","\"WORK RELEASE\" / GAINFULLY EMPLOYED OFFENDER-TOTAL PAID TO OTHER INDIVIDUALS AND AGENCIES","EXPENSES NECESSARY FOR MINOR'S NEEDS UNDER THE JUVENILE ACT","ABANDONED (UNCLAIMED) BAIL TO COUNTY (No longer applicable per Public Act 100-22, effective 1/1/2018)","ABANDONED (UNCLAIMED) PROPERTY TO STATE","DEPOSITS WITH CLERK DISBURSED DURING THE YEAR-FROM JUDICIAL SALES","DEPOSITS WITH CLERK DISBURSED DURING THE YEAR-FROM ALL OTHER CASE CATEGORIES","REIMBURSEMENTS/CONTRIBUTIONS TO A \"LOCAL ANTI-CRIME PROGRAM\"","REFUND AND RETURNS-BAIL","REFUND AND RETURNS-OTHER","OTHER"],"feewaived":["100%","75%","50%","25%","0%"],"waiverdecisionreason":["Granted in Full - Means based government assistance","Granted in Full - Income equal or less of 125% current poverty level","Granted in Full - Hardship","Granted in Part - Income based","Not Granted"],"waiverrequestmethod":["Court Document","Statutory"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["appearancefeescollected","casenumbercentury","civilpenaltyamount","conditionalassessmentamount","disbursementamount","drugtestingfeeordered","drugtestingfeepaid","feeamount","filingfeescollected","fineamount","monetaryconditionamount","pretrialfeeordered","pretrialfeepaid","restitutionamount","totaljudgmentamount"],"dateFields":["datedisbursement","datefeewaiverdecided","datefeewaiverfiled","feecollectiondate","recorddate"]},"di-aoic-trialcourt-hearings":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","civilandotherhearingtype","defendantattendance","hearingdate","recordid","vendorname"],"enums":{"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"civilandotherhearingtype":["Emergency Hearing","Post-Trial Motion","Hearing on Motion-Other","Bench Trial","Jury Trial","Administrative (show cause, review, competency)","Fee Waiver Eligibility","Dispositive","Other Hearing"],"continuancepostponementreason":["Transportation","Evaluation","Illness","Court closed","Party/witness not available/Failure to appear","Lack of notice","Insufficient time","Incomplete Discovery/Crime lab delay","Other","Unknown"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"hearingprogress":["Held","Continued","Cancelled","Postponed/rescheduled","Other","Unknown"],"hearingoutcomesupervision":["No pretrial supervision, no special conditions","No pretrial supervision, with special conditions","Pretrial supervision, no special conditions","Pretrial supervision, with special conditions"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"],"defendantattendance":["Defendant Appeared With Counsel","Defendant Appeared Without Counsel","Defendant Did Not Appear"]},"numOrNull":["casenumbercentury"],"dateFields":["hearingdate"]},"di-aoic-trialcourt-ja":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casestatus","casetype","caseyear","childdob","circuitcourtncicnumber","datecaseinitiated","dateofadjudicationorder","dateofadjudicationwaiverorder","dateofdispositionalorder","dateoffirstpermanencyorder","dateofsheltercaretempcustodyorder","dateoftprorderforfather","dateoftprorderformother","dateoftprorderforotherparent","dateoftprpetitionforfather","dateoftprpetitionformother","dateoftprpetitionforotherparent","dateoriginalabuseandneglectpetitionfiled","familyandjuvenilehearingtype","fatherlistedoninitialabuseandneglectpetition","hearingdate","jacasetransfer","motherlistedonoriginalabuseorneglectpetition","otherparentlistedonintitialabuseandneglectpetition","recordid","statusdate","timecaseinitiated","vendorname"],"enums":{"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casestatus":["Open","Reinstated","Reactivated","Inactive","Closed"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"civilcaseclosuremethod":["1 Jury Trial","2 Bench Trial","3 Judgment","4 Dismissal"],"continuancepostponementreason":["Transportation","Evaluation","Illness","Court closed","Party/witness not available/Failure to appear","Lack of notice","Insufficient time","Incomplete Discovery/Crime lab delay","Other","Unknown"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"familyandjuvenilehearingtype":["Adjudication","Adoption","Competency","Contempt/Show","Cause","Detention","Disposition","Emergency removal/protective custody","First PermanencyHearing","Subsequent PermanencyHearing/Review","Guardianship","Initial Appearance","Permanency","Placement","Plea","Post-permanency hearing","Preliminary/Arraignment","Pretrial/Temporary","Shelter Care/Temporary Custody","Termination of Parental Rights","Trial/Contested hearing","Review","Waiver","Other Hearing"],"hearingprogress":["Held","Continued","Cancelled","Postponed/rescheduled","Other","Unknown"],"juvenileabusecaseoutcome":["Adoption","Guardianship","Transferred to another jurisdiction","Death of child","No Permanency","Other"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury"],"dateFields":["childdob","datecaseinitiated","dateofadjudicationorder","dateofadjudicationwaiverorder","dateofdispositionalorder","dateoffirstpermanencyorder","dateofsheltercaretempcustodyorder","dateoftprorderforfather","dateoftprorderformother","dateoftprorderforotherparent","dateoftprpetitionforfather","dateoftprpetitionformother","dateoftprpetitionforotherparent","dateoriginalabuseandneglectpetitionfiled","hearingdate","recorddate","statusdate"]},"di-aoic-trialcourt-party":{"required":["casegroup","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","childdob","circuitcourtncicnumber","defendantfirstname","defendantlastname","defendantmiddlename","recordid","srlflag","tprparty","vendorname"],"enums":{"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"relationshiptoaction":["Plaintiff/Petitioner on a primary claim","Plaintiff/Petitioner in a counterclaim","Plaintiff/Petitioner in a cross claim","Plaintiff/Petitioner in a third-party claim","Defendant/respondent on a primary claim","Defendant/Respondent in a counterclaim","Defendant/Respondent in a cross claim","Defendant/Respondent in a third-party claim"],"tprparty":["Mother","Father","Other"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury"],"dateFields":["childdob","recorddate"]},"di-aoic-trialcourt-party-hearing":{"required":["attorneyname","casegroup","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","hearingdate","recordid","srlflag","vendorname"],"enums":{"advocatetype":["Legal Aid Staff","Protection Order Advocate","Court Appointed Special Advocate (CASA)","Guardian Ad Litem","Other qualified professional"],"attorneytype":["Public Defender","Prosecutor","Private Attorney","State Government Attorney","Department of Child and Family Services Attorney","Pro Bono/Legal Aid Attorney","Other"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"hearingmode":["In-person","Telephonic","Video Conference","Combination","Did not participate"],"interpreterlanguage":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterqualification":["Certified","Qualified","Registered","Master","Advanced (for ASL only)","Unregistered","None of the above"],"interpretertype":["In Person","Telephone","Videoconference","Other"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["casenumbercentury"],"dateFields":["hearingdate","recorddate"]},"di-aoic-trialcourt-pretrial":{"required":["casecategorycode","casegroup","casegroupcode","caseid","casenumber","casenumbercentury","casesequencenumber","casetype","caseyear","chargedisposition","chargedispositiondate","chargedispositiontype","chargepenaltyclass","chargesequencenumber","chargesourcelevelofgovernment","chargestatuscode","circuitcourtncicnumber","criminalandquasicriminalhearingtype","datecaseinitiated","datesentenced","defendantaliasfirstname","defendantaliaslastname","defendantaliasmiddlename","defendantaliastitlesuffix","defendantattendance","defendantfirstname","defendantgender","defendantlastname","defendantmiddlename","defendantrace","defendantsequencenumber","detained","electronicmonitorordered","hearingdate","inchoateoffensecode","mostseriouscharge","offensechargedescription","offensecodetable","recordid","revocationfiled","statusdate","timecaseinitiated","vendorname","verifiedpetitionfordetentionfiled","verifiedpetitionfordetentiontype","warrantissued"],"enums":{"advocatetype":["Legal Aid Staff","Protection Order Advocate","Court Appointed Special Advocate (CASA)","Guardian Ad Litem","Other qualified professional"],"attorneytype":["Public Defender","Prosecutor","Private Attorney","State Government Attorney","Department of Child and Family Services Attorney","Pro Bono/Legal Aid Attorney","Other"],"casecategorycode":["AR","CH","ED","EV","FC","GC","GR","LA","L","LM","MH","MR","MC","PR","P","SC","TX","CF","CM","CV","DV","DT","MT","TR","OV","QC","AD","DC","D","DN","FA","F","JV","J","JA","JD","CL","CC","MX","OP"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casegroupcode":["FJ","CQ","CI","OT"],"casetype":["AD0001","AD0002","AR0001","AR0005","AR0006","AR0003","AR0004","CF0001","CF0002","CF0003","CF0004","CH0001","CH0002","CH0027","CH0003","CH0004","CH0005","CH0026","CH0006","CH0007","CH0012","CH0013","CH0014","CH0015","CH0016","CH0017","CH0028","CH0018","CH0019","CH0020","CH0021","CH0022","CH0023","CH0024","CL0001","CL0002","CM0001","CM0002","CM0003","CM0004","CV0001","CV0002","DC0001","DC0002","DC0003","DC0004","DC0005","DC0006","DC0007","DC0008","DC0009","DN0001","DN0002","DN0003","DN0004","DN0005","DN0006","DN0007","DN0008","DN0009","DT0001","DT0002","DT0003","DT0004","DV0001","DV0002","DV0003","DV0004","ED0001","ED0002","EV0001","EV0002","EV0005","EV0007","EV0008","EV0004","FA0020","FA0021","FA0022","FA0023","FA0024","FA0025","FA0026","FA0027","FA0028","FA0029","FA0030","FA0031","FA0032","FA0033","FA0034","FC0001","FC0002","FC0003","FC0004","GC0001","GC0002","GC0003","GC0004","GC0005","GC0006","GC0007","GC0008","GC0009","GC0010","GC0011","GR0001","GR0002","GR0003","GR0004","JA0001","JA0002","JA0003","JA0004","JD0001","JD0002","JV0001","JV0002","JV0003","JV0005","JV0006","JV0007","JV0008","LA0020","LA0021","LA0022","LA0023","LA0024","LA0025","LA0026","LA0027","LA0028","LA0029","LA0030","LA0031","LA0032","LM0001","LM0002","LM0003","LM0004","LM0005","LM0006","LM0007","LM0010","LM0011","LM0020","LM0021","LM0022","LM0023","LM0024","LM0025","LM0026","LM0027","LM0028","LM0029","LM0030","LM0031","MH0001","MH0002","MH0003","MH0004","MH0005","MR0001","MR0002","MR0003","MR0051","MR0008","MR0011","MR0012","MR0014","MR0015","MR0016","MR0017","MR0018","MR0019","MR0054","MR0020","MR0021","MR0022","MR0023","MR0025","MR0053","MR0032","MR0033","MR0034","MR0036","MR0052","MR0037","MR0041","MR0044","MR0046","MT0001","MT0002","OV0001","OV0002","PR0012","PR0013","PR0014","PR0015","QC0001","QC0002","QC0003","SC0001","SC0002","SC0003","SC0006","SC0007","TR0001","TR0002","TX0002","TX0001","TX0015","TX0010","TX0016","TX0017","TX0018","TX0011","TX0012","TX0006","TX0019","TX0008","TX0013","TX0014","TX0009","TX0020","TX0021"],"chargedisposition":["101","102","103","104","105","106","107","108","109","110","201","202","203","204","205","206","207","208","209","210","211","212","213","214","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","301","302","303","304","305","307","350","352","351","353","354","355","356","357","358","359","360","401","402","403","405","407","408","409","410","411","412","413","414","415","416","501","502","503","504","505","506","507","508","509","510","511","601","602","603","604","605","606","607","608","610","613","615","616","617","618","650","651","652","653","654","701","702","704","705","706","707","708","709","710","801","802","803","804","888"],"chargedispositiontype":["1","2","3","4","5","6"],"chargepenaltyclass":["M","X","1","2","3","4","A","B","C","P","U","O"],"chargesourcelevelofgovernment":["1","2","3","4"],"chargestatuscode":["1","2","3","4"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"civilinitiatinginsturmentpleading":["Petition (Juvenile only)","Complaint (Excluding Uniform Citations)","Uniform Citation and Complaint Form","Information","Indictment","Transfer from other jurisdiction/level of court"],"continuancepostponementreason":["Transportation","Evaluation","Illness","Court closed","Party/witness not available/Failure to appear","Lack of notice","Insufficient time","Incomplete Discovery/Crime lab delay","Other","Unknown"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"county":["Adams","Alexander","Bond","Boone","Brown","Bureau","Calhoun","Carroll","Cass","Champaign","Christian","Clark","Clay","Clinton","Coles","Cook","Crawford","Cumberland","DeWitt","DeKalb","Douglas","DuPage","Edgar","Edwards","Effingham","Fayette","Ford","Franklin","Fulton","Gallatin","Greene","Grundy","Hamilton","Hancock","Hardin","Henderson","Henry","Iroquois","Jackson","Jasper","Jefferson","Jersey","Jo Daviess","Johnson","Kane","Kankakee","Kendall","Knox","Lake","LaSalle","Lawrence","Lee","Livingston","Logan","Macon","Macoupin","Madison","Marion","Marshall","Mason","Massac","McDonough","McHenry","McLean","Menard","Mercer","Monroe","Montgomery","Morgan","Moultrie","Ogle","Peoria","Perry","Piatt","Pike","Pope","Pulaski","Putnam","Randolph","Richland","Rock Island","Saline","Sangamon","Schuyler","Scott","Shelby","St. Clair","Stark","Stephenson","Tazewell","Union","Vermilion","Wabash","Warren","Washington","Wayne","White","Whiteside","Will","Williamson","Winnebago","Woodford"],"criminalandquasicriminalhearingtype":["Initial Appearance Hearing","Detention Hearing","Revocation Hearing","Sanctions Hearing","Competency Hearing","Pretrial (Status) Hearing","Sentencing Hearing","Post-Termination Hearing"],"defendantaliastitlesuffix":["Sr.","Jr.","I","II","III","IV","V"],"defendantbondtype1":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","25"],"defendantbondtype2":["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","25"],"defendantgender":["Male","Female","X","Unknown"],"defendantrace":["American Indian or Alaskan Native","Asian or Pacific Islander","Black or African American","White or Caucasian","Hispanic or Latino","Unknown"],"hearingprogress":["Held","Continued","Cancelled","Postponed/rescheduled","Other","Unknown"],"hearingoutcomesupervision":["No pretrial supervision, no special conditions","No pretrial supervision, with special conditions","Pretrial supervision, no special conditions","Pretrial supervision, with special conditions"],"inchoateoffensecode":["C","S","A","D","E","M","O"],"interpreterlanguage":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterqualification":["Certified","Qualified","Registered","Master","Advanced (for ASL only)","Unregistered","None of the above"],"interpretertype":["In Person","Telephone","Videoconference","Other"],"modificationtype":["Technical Violations","Failure to Appear","New Offense"],"reasondetained":["Threat to safety","Willful Flight","Agreed or Uncontested"],"reasoninactive":["Warrant","Unfit to stand trial","Pre-Trial Diversion Specialty Court","Interlocutory Appeal","Failure to Appear","Judgment Bond Forfeiture","Bankruptcy Petition","Other","Mentally Disabled","Offender Initiative Program","Sexually Dangerous"],"sentencestatus1":["1-Sentence in Force","2-Waived","3-Suspended","4-Suspended in Part","5-Concurrent","6-Consecutive","7-Stayed"],"sentencetype1":["102","103","201","202","203","204","205","206","207","208","209","210","211","212","213","214","215","216","217","218","219","220","221","222","223","224","225","226","227","301","302","303","304","401","402","403","404","405","406","407","408","409","410","411","412","413","414","415","416","417","418"],"verifiedpetitionfordetentiontype":["Willful flight","Threat to Safety"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"],"mostseriouscharge":["M","X","1","2","3","4","A","B","C","P","U"],"defendantattendance":["Defendant Appeared With Counsel","Defendant Appeared Without Counsel","Defendant Did Not Appear"]},"numOrNull":["casenumbercentury","defendantbonddepositamount","defendantbondfaceamount","drugtestingfeeordered","drugtestingfeepaid","fineamount","monetaryconditionamount","pretrialfeeordered","pretrialfeepaid","restitutionamount","sentencelength1","totaljudgmentamount"],"dateFields":["chargedispositiondate","datecaseinitiated","datedefendantreturnedtocustody","dateofelectronicmonitoring","dateofoffense","daterevocationfiled","datesentenced","defendantdateofarrest","defendantdateofbirth","hearingdate","statusdate"]},"di-aoic-reviewingcourt-administration":{"required":["casesequencenumber","casetype","caseyear","circuitcourtncicnumber","lawfirmregistration","lawfirmrenewalyear","recordid","registeredlawfirmfilingtype","registeredlawfirmtype","vendorname"],"enums":{"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"lawfirmregistration":["Rule 721","Rule 722","None"],"registeredlawfirmfilingtype":["New Corporation Filing","Corporation Renewal Filed"],"registeredlawfirmtype":["Association","Corporation","Limited Liability","Partnership"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":[],"dateFields":["lawfirmrenewalyear","recorddate"]},"di-aoic-reviewingcourt-case-status":{"required":["casecategory","casegroup","casenumber","casesequencenumber","casestatus","casetype","caseyear","circuitcourtncicnumber","courtlevel","datecaseinitiated","recordid","statusdate","vendorname"],"enums":{"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casestatus":["Open","Reinstated","Reactivated","Inactive","Closed"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"courtlevel":["Circuit","Appellate","Supreme"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["appearancefeescollected","filingfeescollected"],"dateFields":["datecaseinitiated","statusdate"]},"di-aoic-reviewingcourt-financial":{"required":["casecategory","casegroup","casenumber","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","courtlevel","recordid","vendorname"],"enums":{"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"courtlevel":["Circuit","Appellate","Supreme"],"feewaived":["100%","75%","50%","25%","0%"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":["appearancefeescollected","filingfeescollected"],"dateFields":["datefeewaiverdecided","datefeewaiverfiled","recorddate"]},"di-aoic-reviewingcourt-hearings":{"required":["casecategory","casegroup","casenumber","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","courtlevel","recordid","vendorname"],"enums":{"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"courtlevel":["Circuit","Appellate","Supreme"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":[],"dateFields":[]},"di-aoic-reviewingcourt-party":{"required":["casecategory","casegroup","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","recordid","reviewingcourtpartyrole","srlflag","vendorname"],"enums":{"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"reviewingcourtpartyrole":["A Minor Child","A Minor Child/Appellant","A Minor Child/Appellee","Admittee","Advisor","Amicus Curiae","Amicus Curiae - Case initiator","Amicus Curiae - No Party Designation","Appellant","Appellant/Cross-Appellee","Appellate Court","Appellee","Appellee/Cross-Appellant","Applicant","Associate Member","Associated Attorney","Attorney","Attorney File Party","Chairperson","Chief Judge","Co-Chairperson","Commissioner","Contemnor - Appellant","Contemnor - Appellee","Court Liaison","Court Reporter","Cross-Appellant","Cross-Appellee","Defendant","Director","Dist List Member","Entity File","Ex Officio Member","Executive Director","Guardian Ad Litem","Intervenor","Intervenor - Appellant","Intervenor - Appellee","Intervenor - Defendant","Intervenor - Petitioner","Intervenor - Respondent","Joining in Appellant","Joining in Appellee","Joint","Judge","Justice","Justice/Judge File Party","Law Firm","Law Firm File Party","Liaison","Member","Movant","Non Lawyer","Other","Petitioner","Petitioner/Appellant","Plaintiff","President","Professor-Reporter","Proponent","Public Member","Referrer","Reporter","Respondent","Respondent/Appellee","Secretary","Separate Appellant","Separate Appellee","Supreme Court","Temporary Member","Treasurer","Trial Court","Trustee","Vice-Chair","Vice-President"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":[],"dateFields":["recorddate"]},"di-aoic-reviewingcourt-party-hearing":{"required":["attorneypresent","casecategory","casegroup","casenumber","casesequencenumber","casetype","caseyear","circuitcourtncicnumber","recordid","srlflag","vendorname"],"enums":{"attorneytype":["Public Defender","Prosecutor","Private Attorney","State Government Attorney","Department of Child and Family Services Attorney","Pro Bono / Legal Aid Attorney","Other"],"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"cookcountydistrictcode":["1 1st Municipal District","2 2nd Municipal District","3 3rd Municipal District","4 4th Municipal District","5 5th Municipal District","6 6th Municipal District","0"],"interpreterlanguage":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterqualification":["Certified","Qualified","Registered","Master","Advanced (for ASL only)","Unregistered","None of the above"],"interpretertype":["In Person","Telephone","Videoconference","Other"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":[],"dateFields":["recorddate"]},"di-aoic-reviewingcourt-reviewing-courts":{"required":["appellatecourtdispositionmethod","appellatecourtdispositiontype","appellatecourtjudgment","appellatedistrict","attorneyname","casecategory","casefeetype","casegroup","casesequencenumber","casestatus","casetype","caseyear","circuitcourtncicnumber","courtlevel","datecaseinitiated","dateoralargumentheld","dateoralargumentscheduled","firstappellatedistrictdivision","justicename","justicerole","lawfirmregistration","lawfirmrenewalfeepaid","lawfirmrenewalyear","noncasefeetype","recordid","registeredlawfirmfilingtype","registeredlawfirmtype","reviewingcourtcasemilestone","reviewingcourtcasemilestonedate","reviewingcourtcasenumber","reviewingcourtcasestatus","reviewingcourtcasesubtype","reviewingcourtcasetype","reviewingcourtcourtappointedindicator","reviewingcourtdispositiondate","reviewingcourtlocation","reviewingcourtpartyrole","srlflag","supremecourtdispositioncode","supremecourtdispositiontype","supremecourtdocket","supremecourtjudgment","supremecourtrule","timeoralargumentheld","timeoralargumentscheduled","trialcourt","trialcourtcircuit","trialcourtjudge","vendorname"],"enums":{"appellatecourtdispositionmethod":["Bail Order Entered","Confession of Error","Dismissed for Failure to Comply with Rules","Dismissed for Lack of Jurisdiction","Dismissed for No Final Appealable Order","Dismissed in the Trial Court","Dismissed on Motion of Appellant","Dismissed on Motion of Appellee","Dismissed on Other","Dismissed on Stipulation of Parties","Dismissed per Court's Order","Disposed by any Other Means","Leave to Appeal Denied","Motion for Leave to File Late Notice Of Appeal Denied","Remanded with Directions for Further Proceedings","Transferred to Proper Court"],"appellatecourtdispositiontype":["Opinion Filed","Order Filed","Rule 23 Filed","Summary Order Filed"],"appellatecourtjudgment":["Abate Ab Initio","Affirm, Dismiss, Remand and Reverse","Affirm, Dismiss, Vacate","Affirm, Modify and Vacate","Affirm, Modify, Remand and Reverse","Affirmed","Affirmed (Inactive)","Affirmed and Amended","Affirmed and Remanded","Affirmed and Remanded with Directions","Affirmed as Modified","Affirmed as Modified and Remanded with Directions","Affirmed as Modified, Vacated, Remanded","Affirmed in Part","Affirmed in part and Remanded","Affirmed in Part and/or Reversed in Part","Affirmed in part, Dismissed in part","Affirmed in part, Modified in part","Affirmed in part, Modified in part and Cause Remanded","Affirmed in part, Reversed in part and Remanded","Affirmed in part, Reversed in part and Vacated","Affirmed in part, Vacated in part","Affirmed in part, Vacated in part and Remanded","Affirmed Mittimus Corrected","Affirmed with Directions","Affirmed, Modified and Remanded","Affirmed, Reversed, and Modified","Affirmed, Reversed, Remanded and Vacated in part","Appeal Stayed","Appeal Transferred","Bond Review Denied","Certified Questions Answered","Confirmed","Confirmed in part","Confirmed in part and Set Aside in part","Dismiss Appeal/People v. Wilk","Dismissed","Dismissed and Remanded","Dismissed and Vacated","Dismissed as Fee not paid","Dismissed as Moot","Dismissed for failure to comply with court order","Dismissed for Want of Prosecution","Dismissed in part and Affirmed in part","Dismissed in part, Reversed in part","Dismissed in part, Reversed in part, Vacated in part and Remanded","Dismissed in part, Vacated in part and Remanded with Directions","Jurisdictional Document Stricken","Mittimus Amended","Mittimus Corrected","Modified","Modified and Remanded","Motion Denied","Motion Granted","Notice of Appeal stricken from docket","Other","Remanded","Remanded to Agency","Remanded to trial court","Remanded with Directions","Reversed","Reversed and Dismissed","Reversed and Remanded","Reversed and Remanded with Directions","Reversed and Vacated","Reversed in Part","Reversed in part and Modified","Reversed in part and Remanded with Directions","Reversed in part and Remanded, Dismissed in part","Reversed in part and Vacated in part","Reversed, Remanded and Vacated","Set Aside","Set Aside in part","Stricken as Moot","Summary Disposition","Summary Reduction or Modification of Sentence","Summary Remand","Summary Reversal","Temporary Restraining Order","Temporary Restraining Order Denied","Temporary Restraining Order Dissolved","Vacated","Vacated (conviction vacated per order)","Vacated and Dismissed","Vacated and Modified in part","Vacated and Reinstated","Vacated and Remanded (order)","Vacated and Remanded with Directions","Vacated and/or Remanded","Vacated in part and Affirmed in part","Vacated in part and Affirmed in part","Vacated in part and Remanded","Vacated in part and Reversed in part","Vacated in part, Reversed in part and Remanded","Vacated, Remanded and Modified"],"appellatedistrict":["1st","2nd","3rd","4th","5th"],"casecategory":["Arbitration","Chancery","Eminent Domain","Eviction","Eviction","Foreclosure","Governmental Corporation","Guardianship","Law: Damages over $50,000","Law Magistrate: Damages over $10,000 up to $50,000","Law Magistrate: Damages over $10,000 up to $50,001","Mental Health","Miscellaneous Remedy","Probate","Small Claims","Tax","Adoption","Dissolution (Divorce) with Children","Dissolution (Divorce) without Children","Family","Juvenile Abuse","Juvenile Delinquent","Juvenile","Criminal Felony","Criminal Misdemeanor","Driving Under the Influence","Domestic Violence","Quasi-criminal","Contempt of Court","Miscellaneous Criminal","Order of Protection","Arbitration^","Dissolution (Divorce)","Law: Damages over $50,001","Law: Damages over $50,002","Municipal Corporation"],"casefeetype":["Appearance","Docketing","Contesting Elections","Law Corporation Registration","Law Corporation Renewal","Law License","Law License Replacement","Cert of Admission","Cert of Admission Add'l Copies","Cert of Admission Add'l Copies (2)","Cert of Admission Add'l Copies (3)","Cert of Admission Add'l Copies (4)","Cert of Admission Add'l Copies (5)"],"casegroup":["Family & Juvenile","Criminal & Quasi-Criminal","Civil","Other"],"casestatus":["Open","Reinstated","Reactivated","Inactive","Closed"],"casetype":["Change of Venue - Arbitration","Arbitration (up to $15K)","Arbitration ($15,000.01 to $50K)","Arbitration ($15,000.01 to $75K)","Change of Venue - Chancery","Abandoned Mobile Home","Appointment of Special Administrator","Construction of Inter Vivos Trust","Construction of Testamentary Trust","Contract Actions","Detinue","Equitable Lien","Exhume a Body","Foreclosure of Security Interest in Personal Property","Injunction (Except in Tax & Dissolution)","Interpleader","Mechanic's Lien Foreclosure","Partition","Partnership Dissolution","Petition for Issuance of Marriage License/Civil Union Certificate (Adult)","Quiet Title","Rescission of Contract","Remove Private Compromising Image (Take Down Order)","Restraining Order","Specific Performance","Structured Settlement (Original Action to Assign)","Trust Administration","Change of Venue - Eminent Domain","Eminent Domain","Change of Venue - Eviction","Commercial","Commercial - Possession Only","Residential","Residential - Possession Only","Residential","Residential - Possession Only","Ejectment","Change of Venue - Foreclosure","Residential Real Estate","Residential Real Estate (Tier 1)","Residential Real Estate (Tier 2)","Residential Real Estate (Tier 3)","Commercial Real Estate","Residential Foreclosure/Termination of Lease","Drainage Assessment (Except Tax Collection)","Foreclosure of Lien for Special Assessment","Petition for Annexation for Election","Petition for the Creation of Drainage District","Petition to Change Form of Government","Petition to Disconnect from Fire District","Petition to Dissolve Government Corporation","Petition to Organize Municipal Corporation","Retailer's Occupation Tax","Special Assessment (to Change or Restrain Collection)","Other Routine Matters of Municipal Corporations","Change of Venue - Guardianship","Guardianship of Minor","Guardianship of Person with Disability","Guardianship of Estate of Living Person","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Distress for Rent (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Change of Venue - Law Magistrate","Arbitration & Award (Up to $15K)","Arbitration & Award ($15,000.01 to $50K)","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act","Contract - Money Damages ($10,000.01 to $15K)","Contract - Money Damages ($15,000.01 to $50K)","Confession of Judgment (Up to $15K)","Confession of Judgment ($15,000.01 to $50K)","Distress for Rent (Up to $15K)","Distress for Rent ($15,000.01 to $50K)","Recover Support/Contribution (Up to $15K)","Recover Support/Contribution ($15,000.01 to $50K)","Replevin (Up to $15K)","Replevin ($15,000.01 to $50K)","Statutory Action by State/Political Subdivision (Up to $15K)","Statutory Action by State/Political Subdivision ($15,000.01 to $50K)","Tort - Money Damages ($10,000.01 to $15K)","Tort - Money Damages ($15,000.01 to 50K)","Trover (Up to $15K)","Trover ($15,000.01 to $50K)","Wrongful Death (Up to $15K)","Wrongful Death ($15,000.01 to $50K)","Change of Venue - Mental Health","Petition for Discharge","Petition for Hospitalization","Petition for Restoration","Petition to Administer Treatment","Change of Venue - Miscellaneous Remedy","Abatement of Nuisance","Administrative Review-Unemployment","Adult Protective Services Act","Appointment of Receiver","Building Code Violation","Burnt Records","Certiorari","Change of Name","Confirmation of Election Judge","Consumer Fraud/Deceptive Business Practice","Contagious Disease","Corporation Dissolution","Declaratory Judgment","Demolition","Election Contest","Escheat","Fictitious Vital Record","Lost Goods or Money (Estray)","Mandamus","Ne Exeat (Original Action)","Petition to Destroy Evidence","Petition to Destroy Exhibits","Petition for Discovery or to Depose","Prohibition","Quo Warranto","Review of Administrative Proceedings","Sexually Transmissible Disease Control Proceeding","Change of Venue - Probate","Administration of Decedent's Estate","Missing Person","Wrongful Death/Collection of Judgment","Change of Venue - Small Claims","Contract (Up to $2,500)","Contract ($2,500.01 to $10K)","Tort - Money Damages (Up to $2,500)","Tort - Money Damages ($2,500.01 to $10K)","Annual Tax Sale","Change of Venue - Tax","Collection and Refund Tax","Drainage Assessment Tax Collection","Estate Tax","Excise Tax","Income Tax","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Severance Tax","Tax Commission (Review of Decision)","Tax Foreclosure","Tax Injunction","Tax Refund/Objection","Use and Occupation Tax","Utility Tax","Change of Venue - Adoption","Adoption","Change of Venue - Dissolution with Children","Dissolution (with children)","Dissolution of Civil Union (with children)","Invalidity (with children)","Legal Separation (with children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Change of Venue - Dissolution without Children","Dissolution (without children)","Dissolution of Civil Union (without children)","Invalidity (without children)","Legal Separation (without children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody (Parentage established)","Petition to Request Support (Parentage established)","Petition for Parentage (Visitation)","Petition for Parentage (Child Support)","Petition for Visitation (Parentage established)","Petition for Visitation of Frail/Elderly Adult","Juvenile Abuse","Change of Venue - Juvenile Abuse","Dependency","Juvenile Delinquent","Change of Venue - Juvenile Delinquent","Juvenile","Change of Venue - Juvenile","Emancipation of Minor","Petition under Parental Notification of Abortion Act","Petition for Issuance of Marriage License/Civil Union Certificate","Req Authoritative Intervention","Sexting","Truancy","Felony","Change of Venue - Felony","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Misdemeanor","Change of Venue - Misdemeanor","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Driving Under the Influence","Change of Venue - DUI","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - DV","Domestic Violence","Specialty Court [Mental Health, Drug, DUI, etc.]","Suppressed Indictment","Change of Venue - QC","Quasi-Criminal","Specialty Court [Mental Health, Drug, DUI, etc.]","Direct Civil Contempt","Indirect Civil Contempt","Direct Criminal Contempt","Indirect Criminal Contempt","Jurors - Failure to Respond to Summons or Absent","Change of Venue - Miscellaneous Criminal","Administrative Subpoena","Application for Order-Eavesdropping","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Attachment (Original Action)","Certificate of Innocence","Eavesdrop - States Attorney Authorized","Extradition","Forfeiture of Seized Property","Fugitive from Justice","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition for Rule to Show Cause against a Juror for Failure to Appear","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Secure Testimony for Out-Of-State Witness","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Change of Venue - Order of Protection","Civil No Contact Order","Firearms Restraining Order","Order of Protection","Stalking No Contact Order","Arbitration - $5,000.00 up to $10,000.00","Arbitration - $10,000.01 up to $15,000.00","Injunction (Except in Tax & Dissolution)","Eviction (Possession Only)","Arbitration & Award (up to $250.00)","Arbitration & Award ($250.01 to $500.00)","Arbitration & Award ($500.01 to $1,500.00)","Arbitration & Award ($1,500.01 to $2,500.00)","Arbitration & Award ($2,500.01 to $10K)","Arbitration & Award ($10,000.01 to $15K)","Confession of Judgment (up to $250.00)","Confession of Judgment ($250.01 to $500.00)","Confession of Judgment ($500.01 to $1,500.00)","Confession of Judgment ($1,500.01 to $2,500.00)","Confession of Judgment ($2,500.01 to $15K)","Detinue (up to $250.00)","Detinue ($250.01 to $500.00)","Detinue ($500.01 to $1,500.00)","Detinue ($1,500.01 to $2,500.00)","Detinue ($2,500.01 to $15K)","Distress for Rent (up to $250.00)","Distress for Rent ($250.01 to $500.00)","Distress for Rent ($500.01 to $1,500.00)","Distress for Rent ($1,500.01 to $2,500.00)","Distress for Rent ($2,500.01 to $15K)","Ejectment (up to $250.00)","Ejectment ($250.01 to $500.00)","Ejectment ($500.01 to $1,500.00)","Ejectment ($1,500.01 to $2,500.00)","Ejectment ($2,500.01 to $15K)","Recover Support/Contribution (up to $250.00)","Recover Support/Contribution ($250.01 to $500.00)","Recover Support/Contribution ($500.01 to $1,500.00)","Recover Support/Contribution ($1,500.01 to $2,500.00)","Recover Support/Contribution ($2,500.01 to $15K)","Replevin (up to $250.00)","Replevin ($250.01 to $500.00)","Replevin ($500.01 to $1,500.00)","Replevin ($1,500.01 to $2,500.00)","Replevin ($2,500.01 to $15K)","Statutory Action by State/Political Subdivision ($10,000.01 up to $15K)","Trover (up to $250.00)","Trover ($250.01 to $500.00)","Trover ($500.01 to $1,500.00)","Trover ($1,500.01 to $2,500.00)","Trover ($2,500.01 to $15K)","Wrongful Death (up to $250.00)","Wrongful Death ($250.01 to $500.00)","Wrongful Death ($500.01 to $1,500.00)","Wrongful Death ($1,500.01 to $2,500.00)","Wrongful Death ($2,500.01 to $15K)","Contract (up to $250.00)","Contract ($250.01 to $500.00)","Contract ($500.01 to $1,500.00)","Contract ($1,500.01 to $2,500.00)","Tax Collection (up to $250.00)","Tax Collection ($250.01 to $500.00)","Tax Collection ($500.01 to $1,500.00)","Tax Collection ($1,500.01 to $2,500.00)","Tort - Money Damages (up to $250.00)","Tort - Money Damages ($250.01 to $500.00)","Tort - Money Damages ($500.001 to $1,500.00)","Tort - Money Damages ($1,500.01 to $2,500.00)","Action of Ward - No Administration (up to $5,000.00)","Action of Ward - No Administration ($5,000.01 or more)","Administration of Decedent's Estate (up to $15,000.00)","Administration of Decedent's Estate ($15,000.01 or more)","Administration of Decedent's Estate (Domestic/Foreign Will & Heirship)","Administration of Decedent's Estate (Letters of Office)","Administration of Decedent's Estate (Petition to Sell Real Estate)","Administration of Decedent's Estate (Proof of Heirship)","Administration of Estate of Minor (up to $15,000.00)","Administration of Estate of Minor ($15,000.01 or more)","Administration of Estate of Minor (Letters of Office to Estate)","Administration of Estate of Minor (Letters of Office to Guardian)","Administration of Estate of Minor (Petition to Sell Real Estate)","Administration of Estate of Disabled Adult (up to $15,000.00)","Administration of Estate of Disabled Adult ($15,000.01 or more)","Administration of Estate of Disabled Adult (Letters of Office to Estate)","Administration of Estate of Disabled Adult (Letters of Office to Guardian)","Administration of Estate of Disabled Adult (Petition to Sell Real Estate)","Construction of Testamentary Trust","Guardianship of Minor (Estate)","Guardianship of Minor & Estate","Guardianship of Minor (No Estate)","Guardianship of Person with Disability (No Estate)","Will Contest","Wrongful Death/Collection of Judgment (up to $5,000.00)","Wrongful Death/Collection of Judgment ($5,000.01 or more)","Dissolution","Dissolution of Civil Union","Invalidity","Legal Separation","Praecipe","Civil Actions to Compel Support","Confession of Judgment - up to $1,500.00","Confession of Judgment - $1,500.01 to $10,000.00","Contract - Money Damages (up to $10,000.00)","Petition for Tax Deed","Sale in Error","Scavenger Tax Sale","Suit to Restrain Collection or Change Special Assessment","Tax Foreclosure","Tax Injunction","Tax Objection","Tax Petition - Additional Parcels","Registration of Foreign Child-custody Determination","Registration of Foreign Support Order","Domestic or Foreign Will (without administration)","Letters of Office (without administration)","Letters of Office of a Ward (Issued to Guardian)","Letters of Office of a Ward (without administration)","Petition to Sell Real Estate","Proof of Heirship","Foreclosure (Commercial)","Foreclosure (Residential)","Foreclosure (Residential) Tier #1","Foreclosure (Residential) Tier #2","Foreclosure (Residential) Tier #3","Change of Venue - Law","Arbitration & Award (over $50,000.00)","Asbestos (Deferred) (over $50,000.00)","Asbestos (Negligence) (over $50,000.00)","Contract - Money Damages (over $50,000.00)","Confession of Judgment (over $50,000.00)","Detinue (over $50,000.00)","Distress for Rent (over $50,000.00)","Ejectment (over $50,000.00)","Eviction (rent over $50,000.00)","Residential Foreclosure/Termination of Lease (over $50,000.00)","Recover Support/Contribution (over $50,000.00)","Replevin (over $50,000.00)","Statutory Action (state/political subdivision) (over $50,000.00)","Tort - Money Damages (over $50,000.00)","Trover (over $50,000.00)","Wrongful Death (over $50,000.00)","Eviction - Commercial (rent over $50,000.00)","Eviction - Residential (rent over $50,000.00)","Detinue (Up to $15K)","Detinue ($15,000.01 to $50K)","Ejectment (Up to $15K)","Ejectment ($15,000.01 to $50K)","Eviction-Possession Only","Eviction-Rent (Up to $15K)","Eviction-Rent ($15,000.01 to $50K)","Residential Foreclosure/Termination of Lease (possession only)","Residential Foreclosure/Termination of Lease (Up to $15K)","Residential Foreclosure/Termination of Lease ($15,000.01 to $50K)","Eviction-Commercial (Possession Only)","Eviction-Commercial-Rent (Up to $15K)","Eviction-Commercial-Rent ($15,000,01 to $50K)","Eviction-Residential (Possession Only)","Eviction-Residential-Rent (Up to $15K)","Eviction-Residential-Rent ($15,000.01 to $50K)","Administrative Subpoena","Application for Order-Eavesdropping","Eavesdrop - States Attorney Authorized","Application for Order-Electronic Criminal Surveillance","Appointment of Special Prosecutor","Certificate of Innocence","Extradition","Forfeiture of Seized Property","Grand Jury Investigator","Habeas Corpus (Civil or Criminal)","Interstate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Adult)","Intrastate Probationer Transfer (Juvenile)","Peace Bond Complaint (Fugitive from Justice)","Petition to Expunge (Governor's Pardon)","Petition to Expunge (No Criminal Case)","Petition to Seal (No Existing Case)","Rendition","Search Warrant","Sexually Violent Person Commitment Proceedings","Statewide Grand Jury Proceedings","Statutory Summary Suspension (if no DT case)","Petition for the Creation of Drainage District","Petition of Annexation for Election","Petition to Organize Municipal Corporation","Other Routine Matters of Municipal Corporations","Change of Venue - Probate","Action of Ward - No Administration","Administration of Decedent's Estate","Administration of Estate of Minor","Administration of Estate of Disabled Adult","Adult Protective Service Act","Construction of Will","Missing Person","Guardianship of Minor","Guardianship of Person with Disability","Wrongful Death/Collection of Judgment","Tax Collection (Up to $2,500)","Tax Collection ($2,500.01 to $10K)","Special Assessment (To Change or Restrain Collection)","Change of Venue - Dissolution","Dissolution (with children)","Dissolution (without children)","Dissolution of Civil Union (with children)","Dissolution of Civil Union (without children)","Invalidity (with children)","Invalidity (without children)","Legal Separation (with children)","Legal Separation (without children)","Domestic Violence Dissolution (with Children)","Domestic Violence Dissolution of Civil Union (with Children)","Domestic Violence Invalidity (with Children)","Domestic Violence Legal Separation (with Children)","Domestic Violence Dissolution (without Children)","Domestic Violence Dissolution of Civil Union (without Children)","Domestic Violence Invalidity (without Children)","Domestic Violence Legal Separation (without Children)","Change of Venue - Family","Abandoned Baby","Child of Assisted Reproduction","Delayed Record of Birth","Emancipation of Minor","Gestational Surrogacy","Notice to Putative Father/Adoption Act","Notice to Putative Father/Juvenile Court Act","Parentage Act - Challenge","Petition for Confidential Intermediary","Petition for Custody","Petition to Request Support","Petition Under Parental Notification of Abortion Act","Petition for Order to Issue Marriage License/Civil Union Cert (Adult)","Petition for Order to Issue Marriage License/Civil Union Cert (Minor)","Petition for Parental Responsibility of Child(ren) (Visitation)","Petition for Parental Responsibility (Child Support)","Petition for Visitation of Child(ren)","Petition for Visitation of Frail/Elderly Adult","Juvenile","Change of Venue - Juvenile","Req Authoritative Intervention","Foreclosure of Lien for Special Assessment","Retailer's Occupation Tax","Attachment (Original Action)","Petition to Secure Testimony for Out-Of-State Witness","Civil Remedies for Nonconsensual Dissemination of Private Sexual Images Act"],"circuitcourtncicnumber":["IL001025J","IL002015J","IL003015J","IL004015J","IL005015J","IL006015J","IL007015J","IL008015J","IL009015J","IL010025J","IL011015J","IL012015J","IL013015J","IL014015J","IL015025J","IL016025J","IL017015J","IL018015J","IL019015J","IL020015J","IL021015J","IL022015J","IL023015J","IL024015J","IL025015J","IL026015J","IL027015J","IL028015J","IL029015J","IL030015J","IL031015J","IL032015J","IL033025J","IL034015J","IL035015J","IL036015J","IL037015J","IL038025J","IL039015J","IL040015J","IL041025J","IL042015J","IL043015J","IL044015J","IL045035J","IL046015J","IL047015J","IL048025J","IL049025J","IL050035J","IL051015J","IL052025J","IL053015J","IL054025J","IL055015J","IL056015J","IL057015J","IL058015J","IL059015J","IL060025J","IL061015J","IL062015J","IL063015J","IL064015J","IL065015J","IL066015J","IL067015J","IL068015J","IL069015J","IL070015J","IL071015J","IL072025J","IL073015J","IL074015J","IL075015J","IL076015J","IL077015J","IL078015J","IL079015J","IL080015J","IL081025J","IL082025J","IL083015J","IL084055J","IL085015J","IL086015J","IL087025J","IL088015J","IL089015J","IL090015J","IL091015J","IL092015J","IL093015J","IL094015J","IL095015J","IL096015J","IL097015J","IL098015J","IL099015J","IL100025J","IL101025J","IL102015J"],"courtlevel":["Circuit","Appellate","Supreme"],"firstappellatedistrictdivision":["1st","2nd","3rd","4th","5th","6th"],"interpreterlanguage":["Spanish","French","Polish","Chinese (Incl. Mandarin, Cantonese)","Tagalog (Incl. Filipino)","Arabic","Urdu","Gujarati","Russian","Hindi","Korean","ASL","Serbo-Croatian","Vietnamese","Lithuanian","Ukrainian","Romanian","Other"],"interpreterqualification":["Certified","Qualified","Registered","Master","Advanced (for ASL only)","Unregistered","None of the above"],"interpretertype":["In Person","Telephone","Videoconference","Other"],"justicerole":["Author","Concurring","Concurring in Part and Dissenting in Part","Dissenting","Joined in Concurring in Part and Dissenting in Part","Joining in Concurrence","Joining in Dissent","Joining in Special Concurrence","Specially Concurring","Specially Concurring in Part and Dissenting in Part","Took no part","Votes to Deny","Votes to Grant"],"lawfirmregistration":["Rule 721","Rule 722","None"],"noncasefeetype":["Copy Charges","Miscellaneous","Shipping Charges","Certification","Sanctions Paid"],"registeredlawfirmfilingtype":["New Corporation Filing","Corporation Renewal Filed"],"registeredlawfirmtype":["Association","Corporation","Limited Liability","Partnership"],"reviewingcourtcasemilestone":["Accelerated","Anders Finley","Appellant Brief Filed","Appellee Brief Filed","Case Microfilm","Case Ready","Case Reinstated","Case Submitted","Circulation Begun","Disposition","Disposition Withdrawn","Expedited","Include on Case Status Report","Motion Disposed","Motion Pending","Oral Argument Held","Other","PLA Allowed","PLA Denied","PLA Denied Leave To File","PLA Denied SO","PLA Dismissed","PLA Held","PLA Withdrawn","Ready Case Law Class","Ready Case Microfilm Case List Report","Ready Case Oral Argument","Ready Case Oral Argument Cancellation","Ready Case Petition Rehearing","Ready Case Petition Rehearing Cancellation","Ready Case PLA Cancellation","Ready Case PLA Conference","Ready to Vault","Record Filed","Remove from Case Status Report","Reply Brief Filed","SC Remanded to AC","Voting Ready"],"reviewingcourtcasestatus":["Advisement Docket","Briefing Docket","Civil Docket","Leave to Appeal Docket","Mandate Pending","Pending","People's Docket","Ready Docket","Rehearing Docket","Stayed","Supreme Court Docket","Other"],"reviewingcourtcasesubtype":["Ad Hoc Attorney","Administrative Orders","Admission on Foreign License","Bar Exam App. Deadlines & Fees","Bar Exam Qualifications","Capital Litigation Trial Bar - Inactive","Character & Fitness 9.13","Character & Fitness 9.3(e)","Civil","Client Protection Program","Complainant Filings - Inactive","Conditional Admission","Criminal","Criminal - MD Docket","Criminal - MR Docket","Educational Requirements - Bar Exam","Extensions - Inactive","Foreign Law School Graduate","Foreign Legal Consultant","House Counsel","Immunity - Inactive","Imposition of Death","Imposition of Death - Affirmed/Vacated","Justice","Law Class Candidate","Law Firm","Legal Service Program Lawyers","Licensed Attorney","Master Roll","Military Spouse","Misc - Expunge - Inactive","Miscellaneous","Miscellaneous A","Miscellaneous B","Miscellaneous C","Miscellaneous D","Name Change","Name Change Female","Name Change Male","Name Change Non-Binary","Oral Argument (non party) Video Request","Other","Other - Dissolved","Other - Inactive","Other - PR Docket","Petitions - Inactive","Policy - Inactive","Post Conviction","Pro Hac","Pro Se Correspondence","Proposed Rule","R753(d)(2) Hearing Board Report","R753(e)(1) PLE","R753(e)(6) Review Board Report","R754 Subpoena Power","R754(d) Subpoena Power","R754(e) Subpoena Enforcement","R756(a)(8) Petition for Perm. Retirement Status","R757 Disability Inactive","R758 Disability Inactive","R759 Restoration to Active Status","R760 Appointment of Medical Expert","R761 Interim Suspension - Conviction","R762(a) Name-Strike","R762(b) Discipline on Consent","R763 Reciprocal Discipline","R764 Petition for Rule to Show Cause","R765 Substitute Service","R766 Confidentiality and Privacy","R766(n)","R767 Reinstatement","R772 Probation","R773 Costs","R774 Interim Suspension","R776 Appointment of Receiver","Review Character & Fitness Decision","Rule 721 Filings","Rules of Professional Conduct - Inactive","Section I","Section II","Section III","Section IV","Statewide Grand Jury","Supervisory Order","TBD","Voluntary Transfer to Inactive Status","Workers' Comp - Civil"],"reviewingcourtcasetype":["Abortion Act 303A","Admin hearing de novo 306(a)(6)","Administrative Order","Admission","Adoption Act 307(a)(6)","Amended Rule","Appeal Bond","Application/Certified Question 308","Appointed Court Staff","Attorney File","Atty disqualify 306(a)(7)","Bail Bond Orders 604(c)","By Petition 306","Capital","Cert class action 306(a)(8)","Certificate of Importance","Certification of Question (Federal)","Child Custody/Allocation of Parental Responsibilities 306(a)(5)","Child Custody/Allocation of Parental Responsibilities 306(a)(5) - NC","Citizen Participation Act 306(a)(9)","Committee","Condition of Supervision 604(b)","Declaratory Relief","Defendant Unfit 604(e)","Disciplinary Commission","Discipline","Discretionary Acceleration 311(b)","Disqualify Defense Counsel 604(g)","Distribution List","Eminent Domain Act 307(a)(7)","Extension of Time to File PLA 306(c)(4)","Finance institution 307(a)(5)","Former Jeopardy 604(f)","Forum non conveniens 306(a)(2)","Habeas Corpus","Habeas Corpus/Mandamus","Habeas Corpus/Supervisory Order","Injunction 307(a)(1)","Judge/Justice File","Judicial Assignments/Appointments","Law Firm File","Mandamus","Mandamus/Habeas Corpus","Mandamus/Prohibition","Mandamus/Supervisory Order","Miscellaneous","Mortgagee possession 307(a)(4)","Motion Direct Appeal","Motion for Leave to Appeal 303(e)","Necessity for Special Finding 304(a)","New Rule","New trial 306(a)(1)","No juris to defendant 306(a)(3)","No Special Finding Required 304(b)","Notice as of Right 307","Notice of Appeal","Notice of Appeal - Child Custody / Allocation of Parental Responsibilities - Inactive","Notice of Appeal - Child Custody / Allocation of Parental Responsibilities 306A","Notice of Appeal - Child Custody / Allocation of Parental Responsibilities 311(a)","Notice of Appeal - Child Custody / Allocation of Parental Responsibilities 311(a) - NC","Notice of Appeal - Delinquent Minor - Accelerated 660A","Notice of Appeal - Delinquent Minor 660(a)","Notice of Appeal - Late","Notice of Appeal - Mental Health","Notice of Appeal/Partial Final Judgments 304","Notice of Appeal/Stay Enforcement 305","Other","Petition - as a matter of right","Petition - as a matter of right - Child Custody","Petition - as a matter of right - Child Custody - NC","Petition - as a matter of right - Juvenile","Petition - as a matter of right or leave to appeal","Petition - as a matter of right or leave to appeal - Child Custody","Petition - as a matter of right or leave to appeal - Child Custody - NC","Petition - as a matter of right or leave to appeal - Juvenile","Petition - leave to appeal","Petition - leave to appeal - Child Custody","Petition - leave to appeal - Child Custody - NC","Petition - leave to appeal - Juvenile","Petition - leave to appeal or as a matter of right","Petition - leave to appeal or as a matter of right - Child Custody","Petition - leave to appeal or as a matter of right - Child Custody - NC","Petition - leave to appeal or as a matter of right - Juvenile","Plea of Guilty 604(d)","Post Conviction 651","Pro Se Correspondence","Prohibition","Proposed Rule","Receiver or sequestrator 307(a)(2)","Receiver powers or property 307(a)(3)","Revenue","Separate Notice of Appeal 303(a)(3)","State Appeals 303","State Appeals 604(a)","Statewide Grand Jury","Statute Invalid","Stay of Judgment","Stay of Judgment 305(d)","Supervisory Order","Tax Tribunal","Transfer and Consolidation","Transfer venue 306(a)(4)","TRO 307(d)","Unknown"],"reviewingcourtcourtappointedindicator":["Court-Appointed: Civil","Court-Appointed: Criminal","Court-Appointed: Incarcerated - Civil","Not Court-Appointed/Pro Bono","Sup. Ct. Vol. Pro Bono Prog. Crim Appeals"],"reviewingcourtlocation":["Supreme Court","Appellate Court - 1st District","Appellate Court - 2nd District","Appellate Court - 3rd District","Appellate Court - 4th District","Appellate Court - 5th District"],"reviewingcourtpartyrole":["A Minor Child","A Minor Child/Appellant","A Minor Child/Appellee","Admittee","Advisor","Amicus Curiae","Amicus Curiae - Case initiator","Amicus Curiae - No Party Designation","Appellant","Appellant/Cross-Appellee","Appellate Court","Appellee","Appellee/Cross-Appellant","Applicant","Associate Member","Associated Attorney","Attorney","Attorney File Party","Chairperson","Chief Judge","Co-Chairperson","Commissioner","Contemnor - Appellant","Contemnor - Appellee","Court Liaison","Court Reporter","Cross-Appellant","Cross-Appellee","Defendant","Director","Dist List Member","Entity File","Ex Officio Member","Executive Director","Guardian Ad Litem","Intervenor","Intervenor - Appellant","Intervenor - Appellee","Intervenor - Defendant","Intervenor - Petitioner","Intervenor - Respondent","Joining in Appellant","Joining in Appellee","Joint","Judge","Justice","Justice/Judge File Party","Law Firm","Law Firm File Party","Liaison","Member","Movant","Non Lawyer","Other","Petitioner","Petitioner/Appellant","Plaintiff","President","Professor-Reporter","Proponent","Public Member","Referrer","Reporter","Respondent","Respondent/Appellee","Secretary","Separate Appellant","Separate Appellee","Supreme Court","Temporary Member","Treasurer","Trial Court","Trustee","Vice-Chair","Vice-President"],"supremecourtdispositioncode":["Active with Conditions","Censure","Complaint Dismissed","Conditional reinstatement revoked - suspension until further order of the Court","Consent Petition denied","Disability Inactive","Disbarment","Exceptions stricken","Exceptions withdrawn","Inactive status on an interim basis","Motion for a supervisory order denied/allowed","Motion to quash subpoena allowed/denied","Motion to release confidential information allowed/denied","Other","Permanent Retirement","Petition Denied","Petition Dismissed","Petition referred to the Hearing Board","Petition stricken","Petition Withdrawn","Probation","Probation Revoked - Suspension ordered","Reinstatement Allowed","Reinstatement Denied","Remand","Reprimand","Respondent Discharged","Restored to Active Status","Rule discharged","Suggestion of death - spread of record","Suspension","Vacates or Recalls Disposition"],"supremecourtdispositiontype":["Denied Motion for Reconsideration of the Denial of the Motion to File a Late PLA","Dismissed","Leave to File Allowed","Leave to File Denied","Opinion Filed","Opinion Modified Upon Denial of Rehearing","Order","PLA Allowed w/Supervisory Order","PLA Denied","PLA Denied as Moot","PLA Denied w/Supervisory Order","PLA Withdrawn","Withdraw Opinion Disposition","Withdraw PLA Disposition"],"supremecourtdocket":["A - Law Class","B - Law Class","C - Law Class","G - General","J - Judge","L - Law Firm Corporation Renewals","MD - Miscellaneous Docket","MR - Miscellaneous Record","NC - Non-Case","PR - Proposed Rule"],"supremecourtjudgment":["Affirmed","Affirmed/Reversed in Part","Dismissed","Miscellaneous","Mixed","Modified","Other","Reversed","Reversed and Remanded","Summary Order","Vacate or Remand"],"supremecourtrule":["20","23","63A7","63A8","86","213","213j","218","295","302a","302b","303","303(a)(3)","303(d)","303(e)","303A","304","304(a)","304(b)","305","305(d)","306","306(a)(1)","306(a)(2)","306(a)(3)","306(a)(4)","306(a)(5)","306(a)(6)","306(a)(7)","306(a)(8)","306(a)(9)","306(c)(4)","306A","307","307(a)(1)","307(a)(2)","307(a)(3)","307(a)(4)","307(a)(5)","307(a)(6)","307(a)(7)","307(d)","308","311(a)","311(b)","315","315a","315(i)","315j","316","317","317a","335","352","361","381","382","383","384","552","603","603u","604","604(a)","604(b)","604(c)","604(d)","604(e)","604(f)","604(g)","606","606(c)","651","660(a)","660A","701","703","704","705","706","707","708","709","710","712","714","715","716","717","719","721","753","753(d)(2)","753(e)(1)","753(e)(6)","754","754(d)","754(e)","754(f)","756","756(a)(8)","756(a)(9)","757","758","759","760","761","761(b)","761(d)","762(a)","762(b)","763","764","765","766","766N","767","770","772","773","774","776","777","779","780","999"],"trialcourt":["Adams County Circuit Court","Alexander County Circuit Court","Bond County Circuit Court","Boone County Circuit Court","Brown County Circuit Court","Bureau County Circuit Court","Calhoun County Circuit Court","Carroll County Circuit Court","Cass County Circuit Court","Champaign County Circuit Court","Christian County Circuit Court","Clark County Circuit Court","Clay County Circuit Court","Clinton County Circuit Court","Coles County Circuit Court","Cook County Circuit Court","Crawford County Circuit Court","Cumberland County Circuit Court","DeKalb County Circuit Court","DeWitt County Circuit Court","Douglas County Circuit Court","DuPage County Circuit Court","Edgar County Circuit Court","Edwards County Circuit Court","Effingham County Circuit Court","Fayette County Circuit Court","Ford County Circuit Court","Franklin County Circuit Court","Fulton County Circuit Court","Gallatin County Circuit Court","Greene County Circuit Court","Grundy County Circuit Court","Hamilton County Circuit Court","Hancock County Circuit Court","Hardin County Circuit Court","Henderson County Circuit Court","Henry County Circuit Court","Iroquois County Circuit Court","Jackson County Circuit Court","Jasper County Circuit Court","Jefferson County Circuit Court","Jersey County Circuit Court","Jo Daviess County Circuit Court","Johnson County Circuit Court","Kane County Circuit Court","Kankakee County Circuit Court","Kendall County Circuit Court","Knox County Circuit Court","Lake County Circuit Court","LaSalle County Circuit Court","Lawrence County Circuit Court","Lee County Circuit Court","Livingston County Circuit Court","Logan County Circuit Court","Macon County Circuit Court","Macoupin County Circuit Court","Madison County Circuit Court","Marion County Circuit Court","Marshall County Circuit Court","Mason County Circuit Court","Massac County Circuit Court","McDonough County Circuit Court","McHenry County Circuit Court","McLean County Circuit Court","Menard County Circuit Court","Mercer County Circuit Court","Monroe County Circuit Court","Montgomery County Circuit Court","Morgan County Circuit Court","Moultrie County Circuit Court","Ogle County Circuit Court","Peoria County Circuit Court","Perry County Circuit Court","Piatt County Circuit Court","Pike County Circuit Court","Pope County Circuit Court","Pulaski County Circuit Court","Putnam County Circuit Court","Randolph County Circuit Court","Richland County Circuit Court","Rock Island County Circuit Court","Saline County Circuit Court","Sangamon County Circuit Court","Schuyler County Circuit Court","Scott County Circuit Court","Shelby County Circuit Court","St. Clair County Circuit Court","Stark County Circuit Court","Stephenson County Circuit Court","Tazewell County Circuit Court","Union County Circuit Court","Vermilion County Circuit Court","Wabash County Circuit Court","Warren County Circuit Court","Washington County Circuit Court","Wayne County Circuit Court","White County Circuit Court","Whiteside County Circuit Court","Will County Circuit Court","Williamson County Circuit Court","Winnebago County Circuit Court","Woodford County Circuit Court"],"trialcourtcircuit":["1st","2nd","3rd","4th","5th","6th","7th","8th","9th","10th","11th","12th","13th","14th","15th","16th","17th","18th","19th","20th","21st","22nd","23rd","24th","Cook"],"vendorname":["Automon","Capita","Cfive","Conscisys","Corrections Software Solutions","Finvi","Goodin & Associates","Integrated Software Specialists","JANO Justice Systems","Journal Technologies","Justice Systems","Monitor - Connectrex","Nami","Nexus","OSPS","Thomson-Reuters","Tracker - Solution Specialties","Tyler Supervision","Tyler Technologies","Valorem","WinnebagoDoIT"]},"numOrNull":[],"dateFields":["datecaseinitiated","datefeewaiverdecided","datefeewaiverfiled","dateoralargumentheld","dateoralargumentscheduled","feedate","lawfirmrenewalyear","recorddate","reviewingcourtcasemilestonedate","reviewingcourtdispositiondate"]}};

// IL event type wrappers
const IL_EVENT_TYPES = ["di-aoic-new-record-event","di-aoic-delete-record-event"];

function getILEntityRules(entityType) {
  return IL_ENTITY_RULES[entityType] || null;
}


const KNOWN_BAD = {
  "di-texas-oca-court-charge": {
    ocaRef: "OCA-006, OCA-010"
  }
};

const PUBLISHERS = ["ASYST","Cardinal Tracking","CentralSquare Tech","CourtPlus","Data Engineering Test","Eforce","Engagement Builder","Equivant","FastCourt-FundView","Intech","Journal","LGS","NetData","NetData-ICON","OpenGov","PTS Solutions","Rare Element","SunGard","TechShare","Technology Consultants","Tyler Tech-Incode","Tyler Tech-Odyssey","Utility Data Systems of Texas","eDoc","iDocket"];

const V3_COUNTIES = ["Anderson","Andrews","Angelina","Aransas","Archer","Armstrong","Atascosa","Austin","Bailey","Bandera","Bastrop","Baylor","Bee","Bell","Bexar","Blanco","Borden","Bosque","Bowie","Brazoria","Brazos","Brewster","Briscoe","Brooks","Brown","Burleson","Burnet","Caldwell","Calhoun","Callahan","Cameron","Camp","Carson","Cass","Castro","Chambers","Cherokee","Childress","Clay","Cochran","Coke","Coleman","Collin","Collingsworth","Colorado","Comal","Comanche","Concho","Cooke","Coryell","Cottle","Crane","Crockett","Crosby","Culberson","Dallam","Dallas","Dawson","DeWitt","Deaf Smith","Delta","Denton","Dickens","Dimmit","Donley","Duval","Eastland","Ector","Edwards","El Paso","Ellis","Erath","Falls","Fannin","Fayette","Fisher","Floyd","Foard","Fort Bend","Franklin","Freestone","Frio","Gaines","Galveston","Garza","Glasscock","Goliad","Gonzales","Gray","Grayson","Gregg","Grimes","Guadalupe","Hale","Hall","Hamilton","Hansford","Hardeman","Hardin","Harris","Harrison","Hartley","Haskell","Hays","Hemphill","Henderson","Hidalgo","Hill","Hockley","Hood","Hopkins","Houston","Howard","Hudspeth","Hunt","Hutchinson","Irion","Jack","Jackson","Jasper","Jeff Davis","Jefferson","Jim Hogg","Jim Wells","Johnson","Jones","Karnes","Kaufman","Kendall","Kenedy","Kent","Kerr","Kimble","King","Kinney","Kleberg","Knox","La Salle","Lamar","Lamb","Lampasas","Lavaca","Lee","Leon","Liberty","Limestone","Lipscome","Live Oak","Llano","Loving","Lubbock","Lynn","Madison","Marion","Martin","Mason","Matagorda","Maverick","McCulloch","McLennan","McMullen","Medina","Menard","Midland","Milam","Mills","Mitchell","Montague","Montgomery","Moore","Morris","Motley","Nacogdoches","Navarro","Newton","Nolan","Nueces","Ochiltree","Oldham","Orange","Palo Pinto","Panola","Parker","Parmer","Pecos","Polk","Potter","Presidio","Rains","Randall","Reagan","Real","Red River","Reeves","Refugio","Roberts","Robertson","Rockwall","Runnels","Rusk","Sabine","San Augustine","San Jacinto","San Patricio","San Saba","Schleicher","Scurry","Shackelford","Shelby","Sherman","Smith","Somervell","Starr","Stephens","Sterling","Stonewall","Sutton","Swisher","Tarrant","Taylor","Terrell","Terry","Throckmorton","Titus","Tom Green","Travis","Trinity","Tyler","Upshur","Upton","Uvalde","Val Verde","Van Zandt","Victoria","WIlson","WInkler","Walker","Waller","Ward","Washington","Webb","Wharton","Wheeler","Wichita","Wilbarger","Willacy","Williamson","Wise","Wood","Yoakum","Young","Zapata","Zavala"];

const PARTY_RACE = ["American Indian or Alaska Native","Asian or Pacific Islander","Black or African American","Not Available (Blank)","Unknown","White",null];
const PARTY_ETHNICITY = ["Hispanic","Non-Hispanic","Not Available (Blank)","Unknown",null];
const PARTY_SEX = ["Female","Male","Not Available (Blank)","Unknown",null];
const PLEA_V3 = ["A - Not Applicable","C - No Contest or Nolo Contendere","F - Not True","G - Guilty","N - Not Guilty","T - True","U - Unreported/Unknown",null];
const CASE_STATUS_EVENT = ["Ancillary Case Filed","Appeal from Lower Court","Case Disposed","Case Inactivated","Case Reactivated","Case Reopened - All Other Cases Added","Case Reopened - Modification of MH Commitment","Case Reopened - Motion to Modify (Juvenile)","Case Reopened - Motion to Revoke","Case Reopened - Transferred In - External","Case Reopened - Transferred In/Reassigned - Internal","New Case Filed",null];
const COURT_TYPE = ["Business Court","Constitutional County Court","District Court","Statutory County Court","Statutory Probate Court",null];
const PRIMARY_CASE_CATEGORY = ["Civil","Criminal","Family","Juvenile","Mental Health","Probate and Guardianship",null];
const JUDICIAL_COUNCIL_CASE_CATEGORY = ["Adoption","All Other Family","Ch 1102 Investigation","Ch 48 Removal","Child Protection","Commitment to Intellectual Disability Services","Contract","Criminal - Felony","Criminal - Fine Only Misdemenanor","Criminal - Misdemeanor","Dependent Administration","Divorce","Emergency Mental Health","Employment","Extended Mental Health Services Commitment","Guardianship - Adult","Guardianship - Minor","Independent Administration","Injury or Damage","Juvenile","Order for Protective Custody","Order to Authorize Psychoactive Medications","Other Civil","Other Estate Proceedings","Other Probate","Parent-Child - No Divorce","Post-Judgment Actions","Protective Order - No Divorce","Real Property","Related to Criminal Matters","Tax","Temporary Mental Health Services Commitment","Termination of Parental Rights","Title IV-D",null];
const CURRENT_CASE_STATUS = ["Disposed","Inactive","New Filing","Reactivated","Reopened",null];
const CASE_JUDICIAL_OFFICER_TYPE = ["Associate Judge/Other Judicial Officer","Judge","Visiting Judge","Visiting Judge - Long Term Assignment",null];

const APPOINTMENT_TYPE = ["Appointment of Counsel","Appointment of Interpreter",null];
const POSITION = ["Ad Litem","Arbitrator","Attorney","Attorney Ad Litem","Competency Evaluator","Doctor","Guardian","Guardian Ad Litem","Interpreter","Mediator","Permanent Guardian","Physician","Psychologist","Temporary Guardian",null];
const RELATIONSHIP_TO_WARD = ["Associated with a public guardianship program","Attorney","Friend or family member","Not applicable","Private professional guardian",null];
const SOURCE_OF_FEE = ["Applicant","County","Defendant","Estate","General Fund","Insurance","Managing Conservator","Municipality","Named Person","Other","Parent or Guardian","Plaintiff","Possessory Conservator","Pro Bono","Registry of the Court","State","The Parties","Trust","Trustee","Unknown",null];
const JCIT_CASE_TYPE = ["Administrative Appeal","Adoption/Adoption with Termination","Adult Adoption","Annulment with Children","Annulment without Children","Antitrust/Unfair Competition","Appeal from a Lower Court(Civil)","Appeal from a Lower Court(Criminal)","Artificial Media - Financial Exploitation","Artificial Media - Sexually Explicit","Assault/Battery","Bill of Review","Capital Felony","Child Protection","Child Protection (Gov. Code 24.620)","Child Support","Child in Need of Supervision","Code Violations","Communicable Disease","Condemnation","Construction","Cruelly Treated Animal","Custody or Visitation","Dangerous Dog","Debt/Contract - Consumer/DTPA","Debt/Contract - Debt Collection","Debt/Contract - Fraud/Misrepresentation","Debt/Contract - Other","Declare Marriage Void with Children","Declare Marriage Void without Children","Defamation/Libel/Slander","Delinquent Conduct","Dependent Administration","Discrimination","Divorce with Children","Divorce without Children","Dog Causing Death or Serious Bodily Injury","Driver's License Suspension Hearing","Eminent Domain","Enforcement","Evictions - Commercial","Evictions - Residential","Expunction","Felony","Felony - State Jail","Felony 1","Felony 2","Felony 3","Foreclosure - Home Equity-Expedited","Foreclosure - Other","Foreign Judgment","Foreign Will","Franchise","Fraudulent Liens","Garnishment","Gestational Parenting","Grandparent Access","Guardianship - Adult","Guardianship - Minor","Guardianship Management Trust-Adult","Habeas Corpus","Handgun License","Home Owners Association","Independent Administration","Insurance","Intellectual Property","Judgment Nisi","Judicial Review- Fraudulent Documents","Lawyer Discipline","Letters Testamentary","Malpractice - Accounting","Malpractice - Legal","Malpractice - Medical","Malpractice - Other Professional Liability","Managment Trust-Minor","Misdemeanor","Misdemeanor A","Misdemeanor B","Misdemeanor C","Modification - Custody","Modification - Other","Motor Vehicle Accident","Muniment of Title","Name Change","Non-Competition","Non-Disclosure","Occupational Driver's License","Open Safety Deposit Box","Order for Entry and Property Retrieval","Other Civil","Other Contract","Other Employment","Other Estate Proceedings","Other Family Law","Other Injury or Damage","Other Landlord/Tenant - Commercial","Other Landlord/Tenant - Residential","Other Parent-Child","Other Probate","Other Real Property","Other Related to Criminal Matters","Other Tax","Parentage/Paternity/Voluntary Legitimation","Partition","Partnership","Perpetuate Testimony","Premises","Product Liability - Asbestos/Silica","Product Liability - Other","Protective Order","Protective Order (Non-Domestic Relations)","Quiet Title","Register Foreign Judgment","Relief from Firearms Disability","Removal of Disabilities of Minority","Removal of Discriminatory Provision","Repair and Remedy","Retaliation","Sale of Property","Securities/Stock","Seizure/Forfeiture","Sexual Predator (Health & Safety Code 841)","Small Claims","Small Estate Proceedings","Stolen or Seized Property","Tax Appraisal","Tax Delinquency","Tax Suit","Temporary Authorization for Care of Child","Temporary Guardianship - Adult","Temporary Guardianship - Minor","Termination","Termination of Parental Rights","Toll Road","Tortious Interference","Tow Hearing","Transfer Structured Settlement Payment Rights","Trespass to Try Title","Truancy","Turnover","Unaccompanied Alien Child","Workers' Compensation","Writ - Habeas Corpus - 11.07","Writ - Habeas Corpus - 11.071","Writ - Habeas Corpus - 11.072","Writ - Other","Writ of Sequestration","Writ to Retrieve Judgment",null];
const JUDICIAL_COUNCIL_OFFENSE_TYPE = ["Aggravated Assault or Attempted Murder","Aggravated Robbery or Robbery","Assault - Other","Automobile Theft","Burglary","Capital Murder","DWI - First Offense","DWI - Second Offense","DWLS/DWLI","Drug Offenses - Other","Drug Possession","Drug Possession - Marijuana","Drug Sale or Manufacture","Family Violence Assault","Felony DWI","Indecency or Sexual Assault of a Child","Juvenile - CINS","Juvenile - Contempt of Court","Murder","Other Felonies","Other Homicides","Other Misdemeanors","Sexual Assault of an Adult","Theft","Theft by Check","Traffic",null];

const ATTORNEY_TYPE = ["Appointed - private practice","Appointed - public defender","Pro Se","Retained/Private",null];
const PARTY_REPRESENTED = ["Defendant","Defendant/Respondent","Incapacitated Person","Minor","Other","Patient","Plaintiff/Petitioner","Proposed Ward","Resident","Ward",null];

const EVENT_TYPE_CE = ["Affidavit of Inability to Pay Costs","Annual Account","Bench Trial","Competency Evaluation Report","Final Account","Final Commitment Hearing Held","Guardianship of Person Report","Inventory","Jury Sworn","Jury Trial","Mental Illness/Intellectual Disability Assessment","Mistrial","Motion for Continuance by Attorney","Motion for Hate Crime Finding","Order Closing Guardianship","Order Determining Indigency Issued","Order Establishing Guardianship or Administration","Petition for Transfer to Adult Criminal Court","Protective Order Signed","Set for Review","Warrant Issued - Committed Offense While on Bail/Supervision","Warrant Issued - Failure to Appear","Warrant Issued - Violated Condition of Release",null];
const MH_COMMITMENT_TYPE = ["Inpatient","Long-Term Care","Modification - Inpatient to Outpatient","Modification - Outpatient to Inpatient","Outpatient",null];
const PLEADING_MOTION_OUTCOME = ["Denied","Dismissed/Withdrawn","Granted","Granted - Affirmative Finding Made (Hate Crime)","Granted - Affirmative Finding Not Made (Hate Crime)","Granted In Part",null];

const FILING_STATUTE = ["ABC","AGC","AWL","BCC","CCP","CPR","EC","EDC","EST","FC","FNC","GC","HRC","HSC","IC","LC","LGC","Miscellaneous/Unknown","NRC","OC","PC","PRC","PWC","TC","TRC","TUC","VCS","WC","X",null];
const LEVEL_AND_DEGREE = ["F* - Felony -Unclassified","F1 - Felony - 1st Degree","F2 - Felony - 2nd Degree","F3 - Felony - 3rd Degree","FS - Felony - State Jail","FX - Felony - Capital","M* - Misdemeanor - Unclassified","MA - Misdemeanor - Class A","MB - Misdemeanor - Class B","MC - Misdemeanor - Class C",null];
const FILING_CHARGE_MODIFIERS = ["Attempt","Conspiracy","Criminal Solicitation of Minor","None","Solicitation",null];
const DEADLY_WEAPON_FINDING = ["No","Yes - Firearm","Yes - Not a Firearm",null];
const CHARGE_MANNER_OF_DISPOSITION = ["Bench Trial","Jury Trial","Non-Trial",null];
const CHARGE_DISPOSITION = ["Abandoned Charges","Acquitted","Acquitted - Insane","Acquitted - Mentally Incompetent","Amend Probation","Community Supervision Expired","Commuted","Conditional Discharge","Convicted","Convicted - Appeal Pending","Convicted - Lesser Charge","DIC Update","Dead","Deferred","Deferred Amended Probation","Deferred Sentence Modified","Dismissed","Dismissed - Insane","Dismissed - Mentally Incompetent","Mistrial","Multiple Charges - 1 Disposition","Non-Disclosure Order","Not Guilty","Pardoned","Pending","Pending - Mental Incompetent","Probation Discharge","Probation Revocation","Quashed","Reduced to Class C","Reversed","Sentence Modified","Unadjudicated With","Waived",null];

// Odyssey Source branch county allowlist (~105 counties — enforced by the registered Source ID, not the full schema)
const ODYSSEY_COUNTIES = new Set(["Anderson","Andrews","Angelina","Aransas","Archer","Austin","Bastrop","Bell","Bexar","Bowie","Brazoria","Brazos","Burnet","Caldwell","Calhoun","Cameron","Chambers","Clay","Collin","Comal","Comanche","Crane","Dallas","DeWitt","Delta","Denton","Donley","Eastland","Ector","El Paso","Erath","Fannin","Fayette","Fort Bend","Franklin","Galveston","Gillespie","Gonzales","Grayson","Gregg","Guadalupe","Hale","Hamilton","Harris","Harrison","Hartley","Hays","Henderson","Hidalgo","Hill","Hood","Howard","Hunt","Hutchinson","Jackson","Jasper","Jeff Davis","Jefferson","Johnson","Karnes","Kaufman","Kendall","Kerr","Lamar","Leon","Liberty","Limestone","Loving","Lubbock","Matagorda","Medina","Mills","Montague","Montgomery","Morris","Navarro","Nueces","Panola","Parker","Pecos","Polk","Potter","Randall","Refugio","Rockwall","San Jacinto","San Patricio","Scurry","Smith","Somervell","Sutton","Tarrant","Taylor","Tom Green","Travis","Upton","Victoria","Walker","Waller","Webb","Wichita","Williamson","Winkler","Wise","Wood","Yoakum"]);

// Publisher-specific county enums
// Odyssey Source branch is restricted to ~104 counties based on registered Source ID

// v0.1 county enum — County-Subdivision format (delete-record-event entity types)
const V01_COUNTIES = new Set(["Anderson","Anderson-Elkhart","Anderson-Frankston","Anderson-PCT 1-Pl 1","Anderson-PCT 2-Pl 1","Anderson-PCT 3-Pl 1","Anderson-PCT 4-Pl 1","Anderson-Palestine","Andrews","Andrews-Andrews","Andrews-PCT 1","Andrews-PCT 2","Angelina","Angelina-Diboll","Angelina-Hudson","Angelina-Huntington","Angelina-Lufkin","Angelina-PCT 1-Pl 1","Angelina-PCT 2-Pl 1","Angelina-PCT 3-Pl 1","Angelina-PCT 4-Pl 1","Angelina-Zavalla","Aransas","Aransas-Fulton","Aransas-PCT 1","Aransas-PCT 2","Aransas-Rockport","Archer","Archer-Archer City","Archer-Holliday","Archer-Lakeside City","Archer-PCT 1-Pl 1","Archer-PCT 2-Pl 1","Archer-PCT 3-Pl 1","Archer-PCT 4-Pl 1","Archer-Windthorst","Armstrong","Armstrong-Claude","Atascosa","Atascosa-Charlotte","Atascosa-Jourdanton","Atascosa-Lytle","Atascosa-PCT 1","Atascosa-PCT 2","Atascosa-PCT 3","Atascosa-PCT 4","Atascosa-Pleasanton","Atascosa-Poteet","Austin","Austin-Bellville","Austin-PCT 1-Pl 1","Austin-PCT 2-Pl 1","Austin-PCT 3-Pl 1","Austin-PCT 4-Pl 1","Austin-San Felipe","Austin-Sealy","Austin-Wallis","Bailey","Bailey-Muleshoe","Bailey-PCT 1-Pl 1","Bandera","Bandera-Bandera","Bandera-PCT 1","Bandera-PCT 2","Bandera-PCT 3","Bandera-PCT 4","Bastrop","Bastrop-Bastrop","Bastrop-Elgin","Bastrop-PCT 1-Pl 1","Bastrop-PCT 2-Pl 1","Bastrop-PCT 3-Pl 1","Bastrop-PCT 4-Pl 1","Bastrop-Smithville","Baylor","Baylor-PCT 1-Pl 1","Baylor-PCT 2-Pl 1","Baylor-Seymour","Bee","Bee-Beeville","Bee-PCT 1","Bee-PCT 2","Bee-PCT 3","Bee-PCT 4","Bell","Bell-Bartlett","Bell-Belton","Bell-Harker Heights","Bell-Holland","Bell-Killeen","Bell-Little River-Academy","Bell-Morgan's Point Resort","Bell-Nolanville","Bell-PCT 1-Pl 1","Bell-PCT 2-Pl 1","Bell-PCT 3-Pl 1","Bell-PCT 3-Pl 2","Bell-PCT 4-Pl 1","Bell-PCT 4-Pl 2","Bell-Rogers","Bell-Salado","Bell-Temple","Bell-Troy","Bexar","Bexar-Alamo Heights","Bexar-Balcones Heights","Bexar-Castle Hills","Bexar-China Grove","Bexar-City of Sandy Oaks","Bexar-Converse","Bexar-Elmendorf","Bexar-Fair Oaks Ranch","Bexar-Grey Forest","Bexar-Helotes","Bexar-Hill Country Village","Bexar-Hollywood Park","Bexar-Kirby","Bexar-Leon Valley","Bexar-Live Oak","Bexar-Olmos Park","Bexar-PCT 1-Pl 1","Bexar-PCT 2-Pl 1","Bexar-PCT 3-Pl 1","Bexar-PCT 4-Pl 1","Bexar-Saint Hedwig","Bexar-San Antonio","Bexar-Selma","Bexar-Shavano Park","Bexar-Somerset","Bexar-Terrell Hills","Bexar-Universal City","Bexar-Von Ormy","Bexar-Windcrest","Blanco","Blanco-Blanco","Blanco-Johnson City","Blanco-PCT 1-Pl 1","Blanco-PCT 4-Pl 1","Borden","Bosque","Bosque-Clifton","Bosque-Meridian","Bosque-Morgan","Bosque-PCT 1-Pl 1","Bosque-PCT 2-Pl 1","Bosque-Valley Mills","Bosque-Walnut Springs","Bowie","Bowie-De Kalb","Bowie-Hooks","Bowie-Maud","Bowie-Nash","Bowie-New Boston","Bowie-PCT 1-Pl 1","Bowie-PCT 1-Pl 2","Bowie-PCT 2-Pl 1","Bowie-PCT 3-Pl 1","Bowie-PCT 4-Pl 1","Bowie-PCT 5-Pl 1","Bowie-Redwater","Bowie-Texarkana","Bowie-Wake Village","Brazoria","Brazoria-Alvin","Brazoria-Angleton","Brazoria-Brazoria","Brazoria-Brookside Village","Brazoria-Clute","Brazoria-Danbury","Brazoria-Freeport","Brazoria-Holiday Lakes","Brazoria-Iowa Colony","Brazoria-Jones Creek","Brazoria-Lake Jackson","Brazoria-Liverpool","Brazoria-Manvel","Brazoria-Oyster Creek","Brazoria-PCT 1-Pl 1","Brazoria-PCT 1-Pl 2","Brazoria-PCT 2-Pl 1","Brazoria-PCT 2-Pl 2","Brazoria-PCT 3-Pl 1","Brazoria-PCT 3-Pl 2","Brazoria-PCT 4-Pl 1","Brazoria-PCT 4-Pl 2","Brazoria-Pearland","Brazoria-Richwood","Brazoria-Surfside Beach","Brazoria-Sweeny","Brazoria-West Columbia","Brazos","Brazos-Bryan","Brazos-College Station","Brazos-PCT 1","Brazos-PCT 2","Brazos-PCT 3","Brazos-PCT 4","Brewster","Brewster-Alpine","Brewster-PCT 1-Pl 1","Brewster-PCT 2-Pl 1","Brewster-PCT 3-Pl 1","Briscoe","Briscoe-PCT 1-Pl 1","Briscoe-PCT 2-Pl 1","Brooks","Brooks-Falfurrias","Brooks-PCT 1-Pl 1","Brooks-PCT 2-Pl 1","Brooks-PCT 3-Pl 1","Brooks-PCT 4-Pl 1","Brown","Brown-Bangs","Brown-Brownwood","Brown-Early","Brown-PCT 1-Pl 1","Brown-PCT 2-Pl 1","Brown-PCT 3-Pl 1","Brown-PCT 4-Pl 1","Burleson","Burleson-Caldwell","Burleson-PCT 1","Burleson-PCT 2","Burleson-PCT 3","Burleson-PCT 4","Burleson-Snook","Burleson-Somerville","Burnet","Burnet-Bertram","Burnet-Burnet","Burnet-Cottonwood Shores","Burnet-Granite Shoals","Burnet-Highland Haven","Burnet-Marble Falls","Burnet-Meadowlakes","Burnet-PCT 1-Pl 1","Burnet-PCT 2-Pl 1","Burnet-PCT 3-Pl 1","Burnet-PCT 4-Pl 1","Caldwell","Caldwell-Lockhart","Caldwell-Luling","Caldwell-Martindale","Caldwell-PCT 1-Pl 1","Caldwell-PCT 2-Pl 1","Caldwell-PCT 3-Pl 1","Caldwell-PCT 4-Pl 1","Calhoun","Calhoun-PCT 1-Pl 1","Calhoun-PCT 2-Pl 1","Calhoun-PCT 3-Pl 1","Calhoun-PCT 4-Pl 1","Calhoun-PCT 5-Pl 1","Calhoun-Point Comfort","Calhoun-Port Lavaca","Calhoun-Seadrift","Callahan","Callahan-Baird","Callahan-Clyde","Callahan-Cross Plains","Callahan-PCT 1-Pl 1","Callahan-PCT 3-Pl 1","Callahan-PCT 4-Pl 1","Cameron","Cameron-Brownsville","Cameron-Combes","Cameron-Harlingen","Cameron-Indian Lake","Cameron-Jail Magistrate Court","Cameron-La Feria","Cameron-Laguna Vista","Cameron-Los Fresnos","Cameron-PCT 1","Cameron-PCT 2-Pl 1","Cameron-PCT 2-Pl 2","Cameron-PCT 2-Pl 3","Cameron-PCT 3-Pl 1","Cameron-PCT 3-Pl 2","Cameron-PCT 4","Cameron-PCT 5 Pl 3","Cameron-PCT 5-Pl 1","Cameron-PCT 5-Pl 2","Cameron-Palm Valley","Cameron-Port Isabel","Cameron-Primera","Cameron-Rancho Viejo","Cameron-Rio Hondo","Cameron-San Benito","Cameron-Santa Rosa","Cameron-South Padre Island","Camp","Camp-Pittsburg","Carson","Carson-Groom","Carson-PCT 1-Pl 1","Carson-PCT 2-Pl 1","Carson-Panhandle","Carson-Skellytown","Carson-White Deer","Cass","Cass-Atlanta","Cass-Avinger","Cass-Bloomburg","Cass-Hughes Springs","Cass-Linden","Cass-PCT 1-Pl 1","Cass-PCT 2-Pl 1","Cass-PCT 3-Pl 1","Cass-PCT 4-Pl 1","Cass-Queen City","Castro","Castro-Dimmitt","Castro-Hart","Chambers","Chambers-Anahuac","Chambers-Beach City","Chambers-Mont Belvieu","Chambers-Old River-Winfree","Chambers-PCT 1-Pl 1","Chambers-PCT 2-Pl 1","Chambers-PCT 3-Pl 1","Chambers-PCT 4-Pl 1","Chambers-PCT 5-Pl 1","Chambers-PCT 6-Pl 1","Cherokee","Cherokee-Alto","Cherokee-Bullard","Cherokee-Cuney","Cherokee-Jacksonville","Cherokee-New Summerfield","Cherokee-PCT 1-Pl 1","Cherokee-PCT 2-Pl 1","Cherokee-PCT 3-Pl 1","Cherokee-PCT 4-Pl 1","Cherokee-Rusk","Cherokee-Wells","Childress","Childress-Childress","Clay","Clay-Henrietta","Cochran","Cochran-Morton","Coke","Coke-Bronte","Coke-PCT 1","Coke-Robert Lee","Coleman","Coleman-Coleman","Coleman-Santa Anna","Collin","Collin-Allen","Collin-Anna","Collin-Blue Ridge","Collin-Celina","Collin-Fairview","Collin-Farmersville","Collin-Frisco","Collin-Josephine","Collin-Lavon","Collin-Lucas","Collin-McKinney","Collin-Melissa","Collin-Murphy","Collin-Nevada","Collin-PCT 1","Collin-PCT 2","Collin-PCT 3","Collin-PCT 4","Collin-Parker","Collin-Plano","Collin-Princeton","Collin-Prosper","Collin-Town of New Hope","Collin-Wylie","Collingsworth","Collingsworth-Wellington","Colorado","Colorado-Columbus","Colorado-Eagle Lake","Colorado-PCT 1-Pl 1","Colorado-PCT 2-Pl 1","Colorado-PCT 3-Pl 1","Colorado-PCT 4-Pl 1","Colorado-Weimar","Comal","Comal-Bulverde","Comal-Garden Ridge","Comal-New Braunfels","Comal-PCT 1","Comal-PCT 2","Comal-PCT 3","Comal-PCT 4","Comanche","Comanche-Comanche","Comanche-De Leon","Concho","Concho-Eden","Cooke","Cooke-Gainesville","Cooke-Lindsay","Cooke-Muenster","Cooke-PCT 1","Cooke-PCT 2","Cooke-Town of Oak Ridge","Cooke-Valley View","Coryell","Coryell-Copperas Cove","Coryell-Evant","Coryell-Gatesville","Coryell-PCT 1","Coryell-PCT 2","Coryell-PCT 3-Pl 1","Coryell-PCT 4-Pl 1","Cottle","Cottle-Paducah","Crane","Crane-Crane","Crockett","Crosby","Crosby-Crosbyton","Crosby-Lorenzo","Crosby-PCT 1-Pl 1","Crosby-Ralls","Culberson","Culberson-PCT 1-Pl 1","Culberson-PCT 2-Pl 1","Culberson-PCT 3-Pl 1","Culberson-PCT 4-Pl 1","Culberson-Van Horn","Dallam","Dallam-Dalhart","Dallam-Texline","Dallas","Dallas-Addison","Dallas-Balch Springs","Dallas-Carrollton","Dallas-Cedar Hill","Dallas-Cockrell Hill","Dallas-Coppell","Dallas-Dallas","Dallas-DeSoto","Dallas-Duncanville","Dallas-Farmers Branch","Dallas-Garland","Dallas-Glenn Heights","Dallas-Grand Prairie","Dallas-Highland Park","Dallas-Hutchins","Dallas-Irving","Dallas-Lancaster","Dallas-Mesquite","Dallas-PCT 1-Pl 1","Dallas-PCT 1-Pl 2","Dallas-PCT 2-Pl 1","Dallas-PCT 2-Pl 2","Dallas-PCT 3-Pl 1","Dallas-PCT 3-Pl 2","Dallas-PCT 4-Pl 1","Dallas-PCT 4-Pl 2","Dallas-PCT 5-Pl 1","Dallas-PCT 5-Pl 2","Dallas-Richardson","Dallas-Rowlett","Dallas-Sachse","Dallas-Seagoville","Dallas-Sunnyvale","Dallas-University Park","Dallas-Wilmer","Dawson","Dawson-Lamesa","DeWitt","DeWitt-Cuero","DeWitt-PCT 1-Pl 1","DeWitt-PCT 2-Pl 1","DeWitt-Yorktown","Deaf Smith","Deaf Smith-Hereford","Delta","Delta-Cooper","Delta-PCT 5-Pl 1","Denton","Denton-Argyle","Denton-Aubrey","Denton-Bartonville","Denton-City of Dish","Denton-Copper Canyon","Denton-Corinth","Denton-Cross Roads","Denton-Denton","Denton-Double Oak","Denton-Flower Mound","Denton-Hackberry","Denton-Hickory Creek","Denton-Highland Village","Denton-Justin","Denton-Krugerville","Denton-Krum","Denton-Lake Dallas","Denton-Lakewood Village","Denton-Lewisville","Denton-Little Elm","Denton-Northlake","Denton-Oak Point","Denton-PCT 1","Denton-PCT 2","Denton-PCT 3","Denton-PCT 4","Denton-PCT 5","Denton-PCT 6","Denton-Pilot Point","Denton-Ponder","Denton-Providence Village","Denton-Roanoke","Denton-Sanger","Denton-Shady Shores","Denton-The Colony","Denton-Trophy Club","Denton-Westlake","Dickens","Dickens-PCT 1-Pl 1","Dickens-Spur","Dimmit","Dimmit-Carrizo Springs","Dimmit-PCT 1-Pl 1","Dimmit-PCT 2-Pl 1","Dimmit-PCT 3-Pl 1","Dimmit-PCT 4-Pl 1","Donley","Donley-Clarendon","Donley-Howardwick","Donley-PCTs 1 & 2 Pl 1","Donley-PCTs 3 & 4 Pl 2","Duval","Duval-Benavides","Duval-Freer","Duval-PCT 1-Pl 1","Duval-PCT 2-Pl 1","Duval-PCT 3-Pl 1","Duval-PCT 4-Pl 1","Duval-San Diego","Eastland","Eastland-Cisco","Eastland-Eastland","Eastland-Gorman","Eastland-PCT 1","Eastland-PCT 2","Eastland-PCT 4","Eastland-Ranger","Eastland-Rising Star","Ector","Ector-Odessa","Ector-PCT 1-Pl 1","Ector-PCT 2-Pl 1","Ector-PCT 3-Pl 1","Ector-PCT 4-Pl 1","Edwards","El Paso","El Paso-Anthony","El Paso-Clint","El Paso-El Paso","El Paso-Horizon City","El Paso-PCT 1-Pl 1","El Paso-PCT 2-Pl 1","El Paso-PCT 3-Pl 1","El Paso-PCT 4-Pl 1","El Paso-PCT 5-Pl 1","El Paso-PCT 6-Pl 1","El Paso-PCT 6-Pl 2","El Paso-PCT 7-Pl 1","El Paso-San Elizario","El Paso-Socorro","Ellis","Ellis-Alma","Ellis-Bardwell","Ellis-Ennis","Ellis-Ferris","Ellis-Garrett","Ellis-Italy","Ellis-Maypearl","Ellis-Midlothian","Ellis-Milford","Ellis-Oak Leaf","Ellis-Ovilla","Ellis-PCT 1-Pl 1","Ellis-PCT 2-Pl 1","Ellis-PCT 3-Pl 1","Ellis-PCT 4-Pl 1","Ellis-Palmer","Ellis-Pecan Hill","Ellis-Red Oak","Ellis-Waxahachie","Erath","Erath-Dublin","Erath-PCT 1","Erath-PCT 2-Pl 1","Erath-PCT 3","Erath-PCT 4","Erath-Stephenville","Falls","Falls-Lott","Falls-Marlin","Falls-PCT 1-Pl 1","Falls-PCT 2-Pl 1","Falls-PCT 3-Pl 1","Falls-PCT 4-Pl 1","Falls-Rosebud","Fannin","Fannin-Bonham","Fannin-Ector","Fannin-Honey Grove","Fannin-Ladonia","Fannin-Leonard","Fannin-PCT 1-Pl 1","Fannin-PCT 2-Pl 1","Fannin-PCT 3-Pl 1","Fannin-Savoy","Fannin-Trenton","Fayette","Fayette-Flatonia","Fayette-La Grange","Fayette-PCT 1-Pl 1","Fayette-PCT 2-Pl 1","Fayette-PCT 3-Pl 1","Fayette-PCT 4-Pl 1","Fayette-Round Top","Fayette-Schulenburg","Fisher","Fisher-PCT 1-Pl 1","Floyd","Floyd-Floydada","Floyd-Lockney","Floyd-PCT  4","Floyd-PCT 1","Floyd-PCT 2","Floyd-PCT 3","Foard","Foard-Crowell","Fort Bend","Fort Bend-Arcola","Fort Bend-Fulshear","Fort Bend-Meadows Pl","Fort Bend-Missouri City","Fort Bend-Needville","Fort Bend-Orchard","Fort Bend-PCT 1-Pl 1","Fort Bend-PCT 1-Pl 2","Fort Bend-PCT 2-Pl 1","Fort Bend-PCT 2-Pl 2","Fort Bend-PCT 3","Fort Bend-PCT 4-Pl 1","Fort Bend-Richmond","Fort Bend-Rosenberg","Fort Bend-Simonton","Fort Bend-Stafford","Fort Bend-Sugar Land","Fort Bend-Thompsons","Franklin","Franklin-Mount Vernon","Freestone","Freestone-Fairfield","Freestone-PCT 1","Freestone-PCT 2","Freestone-PCT 3","Freestone-PCT 4","Freestone-Teague","Freestone-Wortham","Frio","Frio-Dilley","Frio-PCT 1-Pl 1","Frio-PCT 2-Pl 1","Frio-PCT 3-Pl 1","Frio-PCT 4-Pl 1","Frio-Pearsall","Gaines","Gaines-PCT 1-Pl 1","Gaines-PCT 2-Pl 1","Gaines-Seagraves","Gaines-Seminole","Galveston","Galveston-Bayou Vista","Galveston-Clear Lake Shores","Galveston-Dickinson","Galveston-Friendswood","Galveston-Galveston","Galveston-Hitchcock","Galveston-Jamaica Beach","Galveston-Kemah","Galveston-La Marque","Galveston-League City","Galveston-PCT 1","Galveston-PCT 2","Galveston-PCT 3","Galveston-PCT 4","Galveston-Santa Fe","Galveston-Texas City","Galveston-Village of Tiki Island","Garza","Garza-PCT 1-Pl 1","Garza-PCT 2-Pl 1","Garza-Post","Gillespie","Gillespie-Fredericksburg","Gillespie-PCT 1-Pl 1","Gillespie-PCT 2-Pl 1","Gillespie-PCT 3-Pl 1","Gillespie-PCT 4-Pl 1","Glasscock","Goliad","Goliad-Goliad","Goliad-PCT 1","Goliad-PCT 2","Gonzales","Gonzales-Gonzales","Gonzales-Nixon","Gonzales-PCT 1","Gonzales-PCT 3-Pl 1","Gonzales-PCT 4-Pl 1","Gonzales-Smiley","Gonzales-Waelder","Gray","Gray-Lefors","Gray-PCT 1","Gray-PCT 2","Gray-PCT 3","Gray-Pampa","Grayson","Grayson-Bells","Grayson-Collinsville","Grayson-Denison","Grayson-Gunter","Grayson-Howe","Grayson-PCT 1","Grayson-PCT 2","Grayson-PCT 3","Grayson-PCT 4","Grayson-Pottsboro","Grayson-Sherman","Grayson-Southmayd","Grayson-Tioga","Grayson-Tom Bean","Grayson-Van Alstyne","Grayson-Whitesboro","Grayson-Whitewright","Gregg","Gregg-Clarksville City","Gregg-Gladewater","Gregg-Kilgore","Gregg-Lakeport","Gregg-Longview","Gregg-PCT 1-Pl 1","Gregg-PCT 2-Pl 1","Gregg-PCT 3-Pl 1","Gregg-PCT 4-Pl 1","Gregg-White Oak","Grimes","Grimes-Navasota","Grimes-PCT 1-Pl 1","Grimes-PCT 2-Pl 1","Grimes-PCT 3-Pl 1","Grimes-Todd Mission","Guadalupe","Guadalupe-Cibolo","Guadalupe-Marion","Guadalupe-PCT 1-Pl 1","Guadalupe-PCT 2-Pl 1","Guadalupe-PCT 3","Guadalupe-PCT 4-Pl 1","Guadalupe-Santa Clara","Guadalupe-Schertz","Guadalupe-Seguin","Hale","Hale-Abernathy","Hale-Hale Center","Hale-PCT 1-Pl 1","Hale-PCT 3-Pl 1","Hale-Petersburg","Hale-Plainview","Hall","Hall-Estelline","Hall-Memphis","Hall-PCT 1","Hall-PCT 2","Hall-PCT 3","Hall-PCT 4-Pl 1","Hamilton","Hamilton-Hamilton","Hamilton-Hico","Hamilton-PCT 1-Pl 1","Hansford","Hansford-Spearman","Hardeman","Hardeman-Chillicothe","Hardeman-Quanah","Hardin","Hardin-Kountze","Hardin-Lumberton","Hardin-PCT 1-Pl 1","Hardin-PCT 2-Pl 1","Hardin-PCT 3-Pl 1","Hardin-PCT 4-Pl 1","Hardin-PCT 5-Pl 1","Hardin-PCT 6-Pl 1","Hardin-Silsbee","Hardin-Sour Lake","Harris","Harris-Baytown","Harris-Bellaire","Harris-Bunker Hill","Harris-Deer Park","Harris-El Lago","Harris-Galena Park","Harris-Hedwig Village","Harris-Hilshire Village","Harris-Houston","Harris-Humble","Harris-Hunters Creek Village","Harris-Jacinto City","Harris-Jersey Village","Harris-Katy","Harris-La Porte","Harris-Morgan's Point","Harris-Nassau Bay","Harris-PCT 1-Pl 1","Harris-PCT 1-Pl 2","Harris-PCT 2-Pl 1","Harris-PCT 2-Pl 2","Harris-PCT 3-Pl 1","Harris-PCT 3-Pl 2","Harris-PCT 4-Pl 1","Harris-PCT 4-Pl 2","Harris-PCT 5-Pl 1","Harris-PCT 5-Pl 2","Harris-PCT 6-Pl 1","Harris-PCT 6-Pl 2","Harris-PCT 7-Pl 1","Harris-PCT 7-Pl 2","Harris-PCT 8-Pl 1","Harris-PCT 8-Pl 2","Harris-Pasadena","Harris-Piney Point Village","Harris-Seabrook","Harris-Shoreacres","Harris-South Houston","Harris-Southside Pl","Harris-Spring Valley Village","Harris-Taylor Lake Village","Harris-Tomball","Harris-Webster","Harris-West University Pl","Harrison","Harrison-Hallsville","Harrison-Marshall","Harrison-PCT 1","Harrison-PCT 2","Harrison-PCT 3","Harrison-PCT 4","Harrison-Waskom","Hartley","Hartley-Channing","Haskell","Haskell-Haskell","Haskell-PCT 1-Pl 1","Haskell-Rule","Haskell-Weinert","Hays","Hays-Buda","Hays-Dripping Springs","Hays-Jail Magistrate Court","Hays-Kyle","Hays-PCT 1-Pl 1","Hays-PCT 1-Pl 2","Hays-PCT 2-Pl 1","Hays-PCT 3-Pl 1","Hays-PCT 4-Pl 1","Hays-PCT 5-Pl 1","Hays-San Marcos","Hays-Wimberley","Hays-Woodcreek","Hemphill","Hemphill-Canadian","Henderson","Henderson-Athens","Henderson-Berryville","Henderson-Brownsboro","Henderson-Caney City","Henderson-Chandler","Henderson-Coffee City","Henderson-Enchanted Oaks","Henderson-Eustace","Henderson-Gun Barrel City","Henderson-Log Cabin","Henderson-Malakoff","Henderson-PCT 1","Henderson-PCT 2","Henderson-PCT 3","Henderson-PCT 4","Henderson-PCT 5","Henderson-Payne Springs","Henderson-Seven Points","Henderson-Star Harbor","Henderson-Tool","Henderson-Trinidad","Hidalgo","Hidalgo-Alamo","Hidalgo-Alton","Hidalgo-Donna","Hidalgo-Edcouch","Hidalgo-Edinburg","Hidalgo-Elsa","Hidalgo-Hidalgo","Hidalgo-La Joya","Hidalgo-La Villa","Hidalgo-McAllen","Hidalgo-Mercedes","Hidalgo-Mission","Hidalgo-PCT 1-Pl 1","Hidalgo-PCT 1-Pl 2","Hidalgo-PCT 2-Pl 1","Hidalgo-PCT 2-Pl 2","Hidalgo-PCT 3-Pl 1","Hidalgo-PCT 3-Pl 2","Hidalgo-PCT 4-Pl 1","Hidalgo-PCT 4-Pl 2","Hidalgo-PCT 5-Pl 1","Hidalgo-Palmhurst","Hidalgo-Palmview","Hidalgo-Penitas","Hidalgo-Pharr","Hidalgo-Progreso","Hidalgo-San Juan","Hidalgo-Sullivan City","Hidalgo-Weslaco","Hill","Hill-Hillsboro","Hill-Hubbard","Hill-Itasca","Hill-PCT 1-Pl 1","Hill-PCT 2-Pl 1","Hill-PCT 3-Pl 1","Hill-PCT 4-Pl 1","Hill-Whitney","Hockley","Hockley-Anton","Hockley-Levelland","Hockley-PCT 1-Pl 1","Hockley-PCT 2-Pl 1","Hockley-PCT 4-Pl 1","Hockley-PCT 5-Pl 1","Hockley-Ropesville","Hockley-Sundown","Hood","Hood-Granbury","Hood-Lipan","Hood-PCT 1","Hood-PCT 2","Hood-PCT 3","Hood-PCT 4","Hood-Tolar","Hopkins","Hopkins-Cumby","Hopkins-PCT 1-Pl 1","Hopkins-PCT 2-Pl 1","Hopkins-Sulphur Springs","Houston","Houston-Crockett","Houston-Grapeland","Houston-PCT 1-Pl 1","Houston-PCT 2-Pl 1","Howard","Howard-Big Spring","Howard-PCT 1-Pl 1","Howard-PCT 1-Pl 2","Howard-PCT 2","Hudspeth","Hudspeth-PCT 1-Pl 1","Hudspeth-PCT 2-Pl 1","Hudspeth-PCT 3-Pl 1","Hudspeth-PCT 4-Pl 1","Hunt","Hunt-Caddo Mills","Hunt-Celeste","Hunt-Commerce","Hunt-Greenville","Hunt-Hawk Cove","Hunt-Lone Oak","Hunt-PCT 1-Pl 1","Hunt-PCT 1-Pl 2","Hunt-PCT 2-Pl 1","Hunt-PCT 3-Pl 1","Hunt-PCT 4-Pl 1","Hunt-Quinlan","Hunt-West Tawakoni","Hunt-Wolfe City","Hutchinson","Hutchinson-Borger","Hutchinson-Fritch","Hutchinson-PCT 1","Hutchinson-PCT 2","Hutchinson-Stinnett","Irion","Irion-Mertzon","Jack","Jack-Bryson","Jack-Jacksboro","Jackson","Jackson-Edna","Jackson-Ganado","Jackson-PCT 1-Pl 1","Jackson-PCT 2-Pl 1","Jasper","Jasper-Jasper","Jasper-Kirbyville","Jasper-PCT 1-Pl 1","Jasper-PCT 2-Pl 1","Jasper-PCT 3-Pl 1","Jasper-PCT 4-Pl 1","Jasper-PCT 5-Pl 1","Jasper-PCT 6-Pl 1","Jeff Davis","Jefferson","Jefferson-Beaumont","Jefferson-Bevil Oaks","Jefferson-Groves","Jefferson-Nederland","Jefferson-PCT 1-Pl 1","Jefferson-PCT 1-Pl 2","Jefferson-PCT 2","Jefferson-PCT 4","Jefferson-PCT 6","Jefferson-PCT 7","Jefferson-PCT 8","Jefferson-Port Arthur","Jefferson-Port Neches","Jim Hogg","Jim Hogg-PCT 1-Pl 1","Jim Hogg-PCT 2-Pl 1","Jim Hogg-PCT 3-Pl 1","Jim Hogg-PCT 4-Pl 1","Jim Wells","Jim Wells-Alice","Jim Wells-Orange Grove","Jim Wells-PCT 1-Pl 1","Jim Wells-PCT 3-Pl 1","Jim Wells-PCT 4-Pl 1","Jim Wells-PCT 5-Pl 1","Jim Wells-PCT 6-Pl 1","Jim Wells-Premont","Johnson","Johnson-Alvarado","Johnson-Briaroaks","Johnson-Burleson","Johnson-Cleburne","Johnson-Cross Timber","Johnson-Godley","Johnson-Grandview","Johnson-Joshua","Johnson-Keene","Johnson-PCT 1-Pl 1","Johnson-PCT 2-Pl 1","Johnson-PCT 3-Pl 1","Johnson-PCT 4-Pl 1","Johnson-Rio Vista","Johnson-Venus","Jones","Jones-Anson","Jones-Hamlin","Jones-Hawley","Jones-Stamford","Karnes","Karnes-Falls City","Karnes-Karnes City","Karnes-Kenedy","Karnes-PCT 1","Karnes-PCT 2","Karnes-PCT 3","Karnes-PCT 4","Kaufman","Kaufman-City of Oak Ridge","Kaufman-Combine","Kaufman-Crandall","Kaufman-Forney","Kaufman-Kaufman","Kaufman-Kemp","Kaufman-Mabank","Kaufman-PCT 1","Kaufman-PCT 2","Kaufman-PCT 3","Kaufman-PCT 4","Kaufman-Scurry","Kaufman-Talty","Kaufman-Terrell","Kendall","Kendall-Boerne","Kendall-PCT 1-Pl 1","Kendall-PCT 2-Pl 1","Kendall-PCT 3-Pl 1","Kendall-PCT 4-Pl 1","Kenedy","Kenedy-PCT 1-Pl 1","Kenedy-PCT 2-Pl 1","Kenedy-PCT 3-Pl 1","Kenedy-PCT 4-Pl 1","Kent","Kerr","Kerr-Ingram","Kerr-Kerrville","Kerr-PCT 1-Pl 1","Kerr-PCT 2","Kerr-PCT 3-Pl 1","Kerr-PCT 4-Pl 1","Kimble","Kimble-Junction","King","Kinney","Kinney-Brackettville","Kleberg","Kleberg-Kingsville","Kleberg-PCT 1-Pl 1","Kleberg-PCT 2-Pl 1","Kleberg-PCT 3-Pl 1","Kleberg-PCT 4-Pl 1","Knox","Knox-Knox City","Knox-Munday","La Salle","La Salle-Cotulla","La Salle-Encinal","La Salle-PCT 1-Pl 1","La Salle-PCT 2-Pl 1","La Salle-PCT 3-Pl 1","La Salle-PCT 4-Pl 1","Lamar","Lamar-PCT 1-Pl 1","Lamar-PCT 2-Pl 1","Lamar-PCT 3-Pl 1","Lamar-PCT 4-Pl 1","Lamar-PCT 5-Pl 1","Lamar-PCT 5-Pl 2","Lamar-Paris","Lamar-Reno (Lamar County)","Lamar-Roxton","Lamb","Lamb-Amherst","Lamb-Earth","Lamb-Littlefield","Lamb-Olton","Lamb-PCT 1-Pl 1","Lamb-PCT 2-Pl 1","Lamb-PCT 3-Pl 1","Lamb-PCT 4-Pl 1","Lamb-Sudan","Lampasas","Lampasas-Kempner","Lampasas-Lampasas","Lampasas-Lometa","Lampasas-PCT 1-Pl 1","Lampasas-PCT 2-Pl 1","Lampasas-PCT 3-Pl 1","Lampasas-PCT 4-Pl 1","Lavaca","Lavaca-Hallettsville","Lavaca-Moulton","Lavaca-PCT 1-Pl 1","Lavaca-PCT 2-Pl 1","Lavaca-PCT 3-Pl 1","Lavaca-PCT 4-Pl 1","Lavaca-Shiner","Lavaca-Yoakum","Lee","Lee-Giddings","Lee-Lexington","Lee-PCT 2-Pl 1","Lee-PCT 3-Pl 1","Lee-PCT 4-Pl 1","Leon","Leon-Buffalo","Leon-Jewett","Leon-Marquez","Leon-Normangee","Leon-Oakwood","Leon-PCT 1-Pl 1","Leon-PCT 2-Pl 1","Leon-PCT 4-Pl 1","Liberty","Liberty-Cleveland","Liberty-Daisetta","Liberty-Dayton","Liberty-Dayton Lakes","Liberty-Hardin","Liberty-Kenefick","Liberty-Liberty","Liberty-PCT 1-Pl 1","Liberty-PCT 2-Pl 1","Liberty-PCT 3-Pl 1","Liberty-PCT 4-Pl 1","Liberty-PCT 5-Pl 1","Liberty-PCT 6-Pl 1","Liberty-Plum Grove","Limestone","Limestone-Coolidge","Limestone-Groesbeck","Limestone-Kosse","Limestone-Mexia","Limestone-PCT 1-Pl 1","Limestone-PCT 2-Pl 1","Limestone-PCT 3-Pl 1","Limestone-PCT 4-Pl 2","Limestone-Thornton","Lipscomb","Lipscomb-Booker","Lipscomb-Follett","Live Oak","Live Oak-George West","Live Oak-PCT 1","Live Oak-PCT 2-Pl 1","Live Oak-PCT 3-Pl 1","Live Oak-PCT 4-Pl 1","Live Oak-Three Rivers","Llano","Llano-Horseshoe Bay","Llano-Llano","Llano-PCT 1-Pl 1","Llano-PCT 2-Pl 1","Llano-PCT 3-Pl 1","Llano-PCT 4-Pl 1","Llano-Sunrise Beach Village","Loving","Lubbock","Lubbock-Buffalo Springs","Lubbock-Idalou","Lubbock-Lubbock","Lubbock-New Deal","Lubbock-PCT 1-Pl 1","Lubbock-PCT 2-Pl 1","Lubbock-PCT 3-Pl 1","Lubbock-PCT 4-Pl 1","Lubbock-Ransom Canyon","Lubbock-Shallowater","Lubbock-Slaton","Lubbock-Wolfforth","Lynn","Lynn-O'Donnell","Lynn-PCT 1-Pl 1","Lynn-PCT 4-Pl 1","Lynn-Tahoka","Lynn-Wilson","Madison","Madison-City of Midway","Madison-Madisonville","Madison-PCT 1","Madison-PCT 2","Marion","Marion-Jefferson","Marion-PCT 1-Pl 1","Marion-PCT 2-Pl 1","Martin","Martin-PCT 1","Martin-PCT 2","Mason","Mason-Mason","Matagorda","Matagorda-Bay City","Matagorda-PCT 1-Pl 1","Matagorda-PCT 2-Pl 1","Matagorda-PCT 3-Pl 1","Matagorda-PCT 4-Pl 1","Matagorda-PCT 6-Pl 1","Matagorda-Palacios","Maverick","Maverick-Eagle Pass","Maverick-PCT 1-Pl 1","Maverick-PCT 2-Pl 1","Maverick-PCT 3-Pl 1","Maverick-PCT 3-Pl 2","Maverick-PCT 4-Pl 1","McCulloch","McCulloch-Brady","McLennan","McLennan-Bellmead","McLennan-Beverly Hills","McLennan-Bruceville-Eddy","McLennan-Crawford","McLennan-Hewitt","McLennan-Lacy Lakeview","McLennan-Lorena","McLennan-Mart","McLennan-McGregor","McLennan-Moody","McLennan-PCT 1-Pl 1","McLennan-PCT 1-Pl 2","McLennan-PCT 2","McLennan-PCT 3","McLennan-PCT 4","McLennan-PCT 5","McLennan-Riesel","McLennan-Robinson","McLennan-Waco","McLennan-West","McLennan-Woodway","McMullen","Medina","Medina-Castroville","Medina-Devine","Medina-Hondo","Medina-La Coste","Medina-Natalia","Medina-PCT 1-Pl 1","Medina-PCT 2-Pl 1","Medina-PCT 3-Pl 1","Medina-PCT 4-Pl 1","Menard","Menard-Menard","Midland","Midland-Midland","Midland-PCT 1","Midland-PCT 2","Midland-PCT 3","Midland-PCT 4","Milam","Milam-Buckholts","Milam-Cameron","Milam-Milano","Milam-PCT 1-Pl 1","Milam-PCT 2-Pl 1","Milam-PCT 3-Pl 1","Milam-PCT 4-Pl 1","Milam-Rockdale","Milam-Thorndale","Mills","Mitchell","Mitchell-Colorado City","Mitchell-Loraine","Mitchell-PCT 1-Pl 1","Mitchell-PCT 2-Pl 1","Mitchell-PCT 3-Pl 1","Mitchell-PCT 4-Pl 1","Montague","Montague-Bowie","Montague-Nocona","Montague-PCT 1-Pl 1","Montague-PCT 2-Pl 1","Montague-Saint Jo","Montgomery","Montgomery-Conroe","Montgomery-Cut and Shoot","Montgomery-Magnolia","Montgomery-Montgomery","Montgomery-Oak Ridge North","Montgomery-PCT 1-Pl 1","Montgomery-PCT 2-Pl 1","Montgomery-PCT 3-Pl 1","Montgomery-PCT 4-Pl 1","Montgomery-PCT 5-Pl 1","Montgomery-Panorama Village","Montgomery-Patton Village","Montgomery-Roman Forest","Montgomery-Shenandoah","Montgomery-Splendora","Montgomery-Stagecoach","Montgomery-Willis","Montgomery-Woodbranch","Moore","Moore-Cactus","Moore-Dumas","Moore-PCT 1-Pl 1","Moore-PCT 2-Pl 1","Moore-Sunray","Morris","Morris-Daingerfield","Morris-Lone Star","Morris-Naples","Morris-Omaha","Morris-PCT 1","Morris-PCT 2","Motley","Nacogdoches","Nacogdoches-Garrison","Nacogdoches-Nacogdoches","Nacogdoches-PCT 1","Nacogdoches-PCT 2-Pl 1","Nacogdoches-PCT 3-Pl 1","Nacogdoches-PCT 4-Pl 1","Navarro","Navarro-Angus","Navarro-Blooming Grove","Navarro-Corsicana","Navarro-Dawson","Navarro-Frost","Navarro-Kerens","Navarro-PCT 1","Navarro-PCT 2","Navarro-PCT 3","Navarro-PCT 4","Navarro-Rice","Navarro-Richland","Newton","Newton-Newton","Newton-PCT 1-Pl 1","Newton-PCT 2-Pl 1","Newton-PCT 3-Pl 1","Newton-PCT 4-Pl 1","Nolan","Nolan-Roscoe","Nolan-Sweetwater","Nueces","Nueces-Bishop","Nueces-City of Agua Dulce","Nueces-Corpus Christi","Nueces-Driscoll","Nueces-PCT 1-Pl 1","Nueces-PCT 1-Pl 2","Nueces-PCT 1-Pl 3","Nueces-PCT 2-Pl 1","Nueces-PCT 2-Pl 2","Nueces-PCT 3","Nueces-PCT 4-Pl 1","Nueces-PCT 5-Pl 1","Nueces-PCT 5-Pl 2","Nueces-Port Aransas","Nueces-Robstown","Ochiltree","Ochiltree-Perryton","Oldham","Oldham-Vega","Orange","Orange-Bridge City","Orange-Orange","Orange-PCT 1-Pl 1","Orange-PCT 2-Pl 1","Orange-PCT 3-Pl 1","Orange-PCT 4-Pl 1","Orange-Pine Forest","Orange-Pinehurst","Orange-Rose City","Orange-Vidor","Orange-West Orange","Palo Pinto","Palo Pinto-Mineral Wells","Palo Pinto-PCT 1-Pl 1","Palo Pinto-PCT 2-Pl 1","Palo Pinto-PCT 3-Pl 1","Palo Pinto-PCT 4-Pl 1","Palo Pinto-PCT 5-Pl 1","Palo Pinto-Strawn","Panola","Panola-Carthage","Panola-PCT 1","Panola-PCT 2","Panola-PCT 3","Panola-PCT 4","Parker","Parker-Aledo","Parker-Azle","Parker-Hudson Oaks","Parker-PCT 1","Parker-PCT 2","Parker-PCT 3","Parker-PCT 4","Parker-Reno","Parker-Sanctuary","Parker-Springtown","Parker-Weatherford","Parker-Willow Park","Parmer","Parmer-Bovina","Parmer-Farwell","Parmer-Friona","Parmer-PCT 1-Pl 1","Parmer-PCT 2-Pl 1","Parmer-PCT 3-Pl 1","Pecos","Pecos-Fort Stockton","Pecos-Iraan","Pecos-PCT 1-Pl 1","Pecos-PCT 3-Pl 1","Pecos-PCT 4-Pl 1","Pecos-PCT 6-Pl 1","Polk","Polk-Corrigan","Polk-Livingston","Polk-Onalaska","Polk-PCT 1-Pl 1","Polk-PCT 2-Pl 1","Polk-PCT 3-Pl 1","Polk-PCT 4-Pl 1","Potter","Potter-Amarillo","Potter-PCT 1","Potter-PCT 2","Potter-PCT 3","Potter-PCT 4","Presidio","Presidio-Marfa","Presidio-PCT 1-Pl 1","Presidio-PCT 2-Pl 1","Presidio-Presidio","Rains","Rains-Alba","Rains-East Tawakoni","Rains-Emory","Rains-Point","Randall","Randall-Canyon","Randall-Lake Tanglewood","Randall-PCT 1-Pl 1","Randall-PCT 4","Randall-PCT 4-Pl 1","Randall-Timbercreek Canyon","Randall-Village of Palisades","Reagan","Reagan-Big Lake","Real","Red River","Red River-Bogata","Red River-Clarksville","Reeves","Reeves-PCT 1-Pl 1","Reeves-PCT 2-Pl 1","Reeves-PCT 3-Pl 1","Reeves-PCT 4-Pl 1","Reeves-Town of Pecos City","Refugio","Refugio-Bayside","Refugio-PCT 1","Refugio-PCT 2","Refugio-Refugio","Refugio-Woodsboro","Roberts","Robertson","Robertson-Bremond","Robertson-Calvert","Robertson-Franklin","Robertson-Hearne","Robertson-PCT 1","Robertson-PCT 2-Pl 1","Robertson-PCT 3-Pl 1","Robertson-PCT 4-Pl 1","Rockwall","Rockwall-Fate","Rockwall-Heath","Rockwall-McLendon-Chisholm","Rockwall-PCT 1-Pl 1","Rockwall-PCT 2-Pl 1","Rockwall-PCT 3-Pl 1","Rockwall-PCT 4-Pl 1","Rockwall-Rockwall","Rockwall-Royse City","Runnels","Runnels-Ballinger","Runnels-Miles","Runnels-PCT 1-Pl 1","Runnels-PCT 2-Pl 1","Runnels-Winters","Rusk","Rusk-Henderson","Rusk-Mount Enterprise","Rusk-New London","Rusk-Overton","Rusk-PCT 1-Pl 1","Rusk-PCT 2-Pl 1","Rusk-PCT 3-Pl 1","Rusk-PCT 4-Pl 1","Rusk-PCT 5-Pl 1","Rusk-Tatum","Sabine","Sabine-Hemphill","Sabine-PCT 1-Pl 1","Sabine-PCT 2-Pl 1","Sabine-Pineland","San Augustine","San Augustine-PCT 1-Pl 1","San Augustine-PCT 2-Pl 1","San Augustine-PCT 3-Pl 1","San Augustine-PCT 4-Pl 1","San Augustine-San Augustine","San Jacinto","San Jacinto-PCT 1-Pl 1","San Jacinto-PCT 2-Pl 1","San Jacinto-PCT 3-Pl 1","San Jacinto-PCT 4-Pl 1","San Jacinto-Shepherd","San Patricio","San Patricio-Aransas Pass","San Patricio-Gregory","San Patricio-Ingleside","San Patricio-Lake City","San Patricio-Mathis","San Patricio-Odem","San Patricio-PCT 1","San Patricio-PCT 2","San Patricio-PCT 4","San Patricio-PCT 5","San Patricio-PCT 6","San Patricio-PCT 8","San Patricio-Portland","San Patricio-Sinton","San Patricio-Taft","San Saba","San Saba-Richland Springs","San Saba-San Saba","Schleicher","Schleicher-Eldorado","Scurry","Scurry-PCT 1","Scurry-PCT 2-Pl 1","Scurry-Snyder","Shackelford","Shackelford-Albany","Shelby","Shelby-Center","Shelby-PCT 1-Pl 1","Shelby-PCT 2-Pl 1","Shelby-PCT 3-Pl 1","Shelby-PCT 4-Pl 1","Shelby-PCT 5-Pl 1","Shelby-Tenaha","Shelby-Timpson","Sherman","Sherman-Stratford","Sherman-Texhoma","Smith","Smith-Arp","Smith-Lindale","Smith-Noonday","Smith-PCT 1-Pl 1","Smith-PCT 2-Pl 1","Smith-PCT 3-Pl 1","Smith-PCT 4-Pl 1","Smith-PCT 5-Pl 1","Smith-Troup","Smith-Tyler","Smith-Whitehouse","Smith-Winona","Somervell","Somervell-Glen Rose","Somervell-PCT 1-Pl 1","Somervell-PCT 2-Pl 1","Starr","Starr-Escobares","Starr-La Grulla","Starr-PCT 1-Pl 1","Starr-PCT 2-Pl 1","Starr-PCT 3-Pl 1","Starr-PCT 4-Pl 1","Starr-PCT 4-Pl 2","Starr-PCT 5-Pl 1","Starr-PCT 6-Pl 1","Starr-PCT 7-Pl 1","Starr-PCT 8-Pl 1","Starr-Rio Grande City","Starr-Roma","Stephens","Stephens-Breckenridge","Sterling","Stonewall","Sutton","Sutton-Sonora","Swisher","Swisher-Happy","Swisher-Kress","Swisher-Tulia","Tarrant","Tarrant-Arlington","Tarrant-Bedford","Tarrant-Benbrook","Tarrant-Blue Mound","Tarrant-Colleyville","Tarrant-Crowley","Tarrant-Dalworthington Gardens","Tarrant-Edgecliff Village","Tarrant-Euless","Tarrant-Everman","Tarrant-Forest Hill","Tarrant-Fort Worth","Tarrant-Grapevine","Tarrant-Haltom City","Tarrant-Haslet","Tarrant-Hurst","Tarrant-Keller","Tarrant-Kennedale","Tarrant-Lake Worth","Tarrant-Lakeside","Tarrant-Mansfield","Tarrant-North Richland Hills","Tarrant-PCT 1-Pl 1","Tarrant-PCT 2-Pl 1","Tarrant-PCT 3-Pl 1","Tarrant-PCT 4-Pl 1","Tarrant-PCT 5","Tarrant-PCT 6","Tarrant-PCT 7-Pl 1","Tarrant-PCT 8-Pl 1","Tarrant-Pantego","Tarrant-Pelican Bay","Tarrant-Richland Hills","Tarrant-River Oaks","Tarrant-Saginaw","Tarrant-Sansom Park","Tarrant-Southlake","Tarrant-Watauga","Tarrant-Westover Hills","Tarrant-Westworth Village","Tarrant-White Settlement","Taylor","Taylor-Abilene","Taylor-Merkel","Taylor-PCT 1-Pl 1","Taylor-PCT 1-Pl 2","Taylor-PCT 2-Pl 1","Taylor-PCT 3-Pl 1","Taylor-PCT 4-Pl 1","Taylor-Tuscola","Taylor-Tye","Terrell","Terrell-PCT 1 & 2 Pl 2","Terrell-PCTs 3 & 4 Pl 1","Terry","Terry-Brownfield","Throckmorton","Titus","Titus-Mount Pleasant","Titus-PCT 1, 3 & 4","Titus-PCT 2-Pl 1","Titus-PCT 3","Titus-PCT 4","Titus-Winfield","Tom Green","Tom Green-PCT 1-Pl 1","Tom Green-PCT 2-Pl 1","Tom Green-PCT 3-Pl 1","Tom Green-PCT 4-Pl 1","Tom Green-San Angelo","Travis","Travis-Austin","Travis-Austin Community Court","Travis-Briarcliff","Travis-City of Bee Cave","Travis-Jonestown","Travis-Lago Vista","Travis-Lakeway","Travis-Manor","Travis-Mustang Ridge","Travis-PCT 1-Pl 1","Travis-PCT 2-Pl 1","Travis-PCT 3-Pl 1","Travis-PCT 4-Pl 1","Travis-PCT 5-Pl 1","Travis-Pflugerville","Travis-Rollingwood","Travis-Sunset Valley","Travis-Village of Point Venture","Travis-Volente","Travis-West Lake Hills","Trinity","Trinity-Groveton","Trinity-PCT 1-Pl 1","Trinity-PCT 2-Pl 1","Trinity-PCT 3-Pl 1","Trinity-PCT 4-Pl 1","Trinity-Trinity","Tyler","Tyler-Ivanhoe","Tyler-PCT 1-Pl 1","Tyler-PCT 2-Pl 1","Tyler-PCT 3-Pl 1","Tyler-PCT 4-Pl 1","Tyler-Woodville","Upshur","Upshur-Big Sandy","Upshur-East Mountain","Upshur-Gilmer","Upshur-Ore City","Upshur-PCT 1-Pl 1","Upshur-PCT 2-Pl 1","Upshur-PCT 3-Pl 1","Upshur-PCT 4-Pl 1","Upton","Upton-McCamey","Upton-PCT 1-Pl 1","Upton-PCT 2-Pl 1","Upton-PCT 3-Pl 1","Upton-PCT 4-Pl 1","Uvalde","Uvalde-PCT 1-Pl 1","Uvalde-PCT 2","Uvalde-PCT 3-Pl 1","Uvalde-PCT 4-Pl 1","Uvalde-PCT 6-Pl 1","Uvalde-Sabinal","Uvalde-Uvalde","Val Verde","Val Verde-Del Rio","Val Verde-PCT 1-Pl 1","Val Verde-PCT 2-Pl 1","Val Verde-PCT 3-Pl 1","Val Verde-PCT 4-Pl 1","Van Zandt","Van Zandt-Canton","Van Zandt-Edgewood","Van Zandt-Grand Saline","Van Zandt-PCT 1-Pl 1","Van Zandt-PCT 2-Pl 1","Van Zandt-PCT 3-Pl 1","Van Zandt-PCT 4-Pl 1","Van Zandt-Van","Van Zandt-Wills Point","Victoria","Victoria-PCT 1","Victoria-PCT 2","Victoria-PCT 3","Victoria-PCT 4","Victoria-Victoria","Walker","Walker-Huntsville","Walker-PCT 1-Pl 1","Walker-PCT 2-Pl 1","Walker-PCT 3-Pl 1","Walker-PCT 4-Pl 1","Waller","Waller-Brookshire","Waller-Hempstead","Waller-PCT 1-Pl 1","Waller-PCT 2-Pl 1","Waller-PCT 3-Pl 1","Waller-PCT 4-Pl 1","Waller-Pattison","Waller-Prairie View","Waller-Waller","Ward","Ward-Monahans","Ward-PCT 1-Pl 1","Ward-PCT 2-Pl 1","Ward-Wickett","Washington","Washington-Brenham","Washington-PCT 1-Pl 1","Washington-PCT 2-Pl 1","Washington-PCT 3-Pl 1","Washington-PCT 4-Pl 1","Webb","Webb-El Cenizo","Webb-Laredo","Webb-PCT 1-Pl 1","Webb-PCT 1-Pl 2","Webb-PCT 2-Pl 1","Webb-PCT 2-Pl 2","Webb-PCT 3-Pl 1","Webb-PCT 4-Pl 1","Webb-Rio Bravo","Wharton","Wharton-East Bernard","Wharton-El Campo","Wharton-PCT 1","Wharton-PCT 2","Wharton-PCT 3","Wharton-PCT 4","Wharton-Wharton","Wheeler","Wheeler-PCT 1","Wheeler-PCT 2","Wheeler-Shamrock","Wheeler-Wheeler","Wichita","Wichita-Burkburnett","Wichita-Electra","Wichita-Iowa Park","Wichita-PCT 1-Pl 1","Wichita-PCT 1-Pl 2","Wichita-PCT 2-Pl 1","Wichita-PCT 3-Pl 1","Wichita-PCT 4-Pl 1","Wichita-Wichita Falls","Wilbarger","Wilbarger-PCT 1-Pl 1","Wilbarger-PCT 2-Pl 1","Wilbarger-Vernon","Willacy","Willacy-Lyford","Willacy-PCT 1-Pl 1","Willacy-PCT 2-Pl 1","Willacy-PCT 3-Pl 1","Willacy-PCT 4-Pl 1","Willacy-PCT 5-Pl 1","Willacy-Raymondville","Williamson","Williamson-Cedar Park","Williamson-Florence","Williamson-Georgetown","Williamson-Granger","Williamson-Hutto","Williamson-Jarrell","Williamson-Leander","Williamson-Liberty Hill","Williamson-PCT 1-Pl 1","Williamson-PCT 2-Pl 1","Williamson-PCT 3-Pl 1","Williamson-PCT 4","Williamson-Round Rock","Williamson-Taylor","Williamson-Thrall","Wilson","Wilson-Floresville","Wilson-La Vernia","Wilson-PCT 1-Pl 1","Wilson-PCT 2-Pl 1","Wilson-PCT 3-Pl 1","Wilson-PCT 4-Pl 1","Wilson-Poth","Wilson-Stockdale","Winkler","Winkler-Kermit","Winkler-PCT 1","Winkler-PCT 2","Winkler-Wink","Wise","Wise-Alvord","Wise-Aurora","Wise-Boyd","Wise-Bridgeport","Wise-Chico","Wise-Decatur","Wise-Lake Bridgeport","Wise-New Fairview","Wise-Newark","Wise-PCT 1","Wise-PCT 2","Wise-PCT 3","Wise-PCT 4","Wise-Paradise","Wise-Rhome","Wise-Runaway Bay","Wood","Wood-Hawkins","Wood-Mineola","Wood-PCT 1","Wood-PCT 2","Wood-PCT 3","Wood-PCT 4","Wood-Quitman","Wood-Winnsboro","Yoakum","Yoakum-Denver City","Yoakum-PCT 1-Pl 1","Yoakum-PCT 2-Pl 1","Yoakum-Plains","Young","Young-Graham","Young-Newcastle","Young-Olney","Young-PCT 1-Pl 1","Young-PCT 3-Pl 1","Zapata","Zapata-PCT 1-Pl 1","Zapata-PCT 2-Pl 1","Zapata-PCT 3-Pl 1","Zapata-PCT 4-Pl 1","Zavala","Zavala-Crystal City","Zavala-PCT 1-Pl 1","Zavala-PCT 2-Pl 1","Zavala-PCT 3-Pl 1","Zavala-PCT 4-Pl 1"]);
const V01_CASE_TYPE = ["Felony","Fine-Only Misdemeanor","Misdemeanor",null];
const V01_ATTORNEY_TYPE = ["Appointed - private practice","Appointed - public defender","Retained/Private",null];
const V01_JC_CASE_TYPE = ["Aggravated Assault or Attempted Murder","Aggravated Robbery or Robbery","Assault - Other","Automobile Theft","Burglary","Capital Murder","DWI - First Offense","DWI - Second Offense","DWLS/DWLI","Drug Offenses - Other","Drug Possession","Drug Possession - Marijuana","Drug Sale or Manufacture","Family Violence Assault","Felony DWI","Indecency or Sexual Assault of a Child","Murder","Other Felonies","Other Homicides","Other Misdemeanors","Sexual Assault of an Adult","Theft","Theft by Check","Traffic",null];
const V01_PRIMARY_CASE_CATEGORY = ["Criminal",null];

const V01_EVENT_TYPE_CE = ["Appointments","Case Disposed","Case Inactivated","Case Reactivated","Case Reopened - All Other Cases Added","Case Reopened - Motion to Revoke","Case Reopened - Transferred - External","Case Reopened - Transferred/Reassigned - Internal","Motion/Filing","New Case Filed","Order","Set for Review","Trial Information","Warrant Issued",null];
const V01_CURRENT_CASE_STATUS = ["Active Pending","Disposed","Inactive Pending",null];
const V01_INITIAL_FILING_TYPE = ["Appeal from Lower Court","New Case Filed",null];
const V01_CASE_DISPOSITION_DETAIL = ["Acquittal by the Court","Acquittal by the Jury","Conviction by the Court","Conviction by the Jury - Sentence by Judge","Conviction by the Jury - Sentence by Jury","Deferred Adjudication/Diversion","Dismissal","Guilty Plea or Nolo Contendere","Motion to Revoke Denied/Continued","Motion to Revoke Granted/Revoked","Other","Transfer - Another County","Transfer/Reassignment - Different Court Level","Transfer/Reassignment - Same Court Level",null];
const V01_ATTORNEY_TYPE_AT_DISPOSITION = ["Appointed - Private Practice","Appointed - Public Defender","None","Retained/Private",null];
const V01_PLEADING_MOTION_OUTCOME = ["Denied","Dismissed/withdrawn","Granted","Granted - affirmative finding made (hate crime)","Granted - affirmative finding not made (hate crime)","Granted in part",null];
const V01_WARRANT_REASON = ["Committed Offense While on Bail/Supervision","Failure to Appear","Violated Condition of Release",null];
const V01_TRIAL_INFORMATION = ["Bench Trial","Jury Sworn","Jury Trial","Mistrial",null];

const V01_PLEA_TYPE = ["C - No Contest or Nolo Contendere","G - Guilty","N - Not Guilty","U - Unreported/Unknown",null];
const V01_CHARGE_DISPOSITION = ["Abandoned Charges","Acquitted","Acquitted - Insane","Acquitted - Mentally Incompetent","Amend Probation","Community Supervision Expired","Commuted","Convicted","Convicted - Appeal Pending","Convicted - Lesser Charge","Dead","Deferred","Deferred Amended Probation","Deferred Sentence Modified","Dic Update","Dismissed","Dismissed - Insane","Dismissed - Mentally Incompetence","Mistrial","Multiple Charges - 1 Disposition","Non-Disclosure Order","Not Guilty","Pardoned","Pending","Pending - Mental Incompetence","Probation Discharge","Probation Revocation","Quashed","Reduced to Class C","Reversed","Sentence Modified","Unadjudicated With","Waived",null];
const V01_OTHER_ENHANCEMENTS = ["Bias or Prejudice Motivation (PC 12.47)","Controlled Substance (PC 12.49)","Criminal Street Gang (PC 71.01)","Delay in Arrest of Defendant (CCP 42.0198)","Disaster or Evacuation Area (PC 12.50)","Drug Free Zone (HSC 481.134(b))","Loss to Nursing or Convalescent Home (PC 12.48)","Public Servant (PC 12.501)","Repeat & Habitual - Felony (PC 12.42)","Repeat & Habitual - Misdemeanor (PC 12.43)","Repeat & Habitual - State Jail (PC 12.425)",null];

const V01_SENTENCE_TYPE = ["Community Service","Confinement - Prison","Confinement - State Jail","Confinement as Condition of Community Supervision (Split Sentence)","Confinement/confinement in lieu of payment - County Jail","Death","Fine Only","Life","Life without parole","Other","Probation/Community Supervision","Restitution","Shock Probation","State Felony Sentenced as Class A Misdemeanor","Time Served",null];
const V01_CONCURRENT_CONSECUTIVE = ["Concurrent","Consecutive",null];

const CRIMINAL_DISPOSITION_DETAIL = ["Acquittal by the Court","Acquittal by the Jury","All Other","Conviction by the Court","Conviction by the Jury - Sentence by Judge","Conviction by the Jury - Sentence by Jury","Deferred Adjudication/Probation/Community Supervision","Deferred Prosecution/Adjudication","Dismissal","Finding of DC/CINS by the Court","Finding of DC/CINS by the Jury - Sentence by Judge","Finding of DC/CINS by the Jury - Sentence by Jury","Finding of No DC/CINS by the Court","Finding of No DC/CINS by the Jury","Guilty Plea or Nolo Contendere","Motion to Modify Denied","Motion to Modify Granted","Motion to Revoke Denied/Continued","Motion to Revoke Granted/Revoked","Other","Plea of True","Pretrial Diversion","Transfer - Another County","Transfer - To Adult Criminal Court","Transfer/Reassignment - Different Court Level","Transfer/Reassignment - Same Court Level",null];
const JUVENILE_DISPOSITION_TYPE = ["All Other Probation","Committed - Determinate Sentence","Committed - Indeterminate Sentence","Determinate Sentence Probation","Final Judgment Without Disposition","Probation Revoked - Sentenced to TJJD/Secure Facility",null];
const SENTENCE_TYPE_V3 = ["Community Service","Confinement - Prison","Confinement - State Jail","Confinement as Condition of Community Supervision (Split Sentence)","Confinement/confinement in lieu of payment - County Jail","Death","Fine Only","Life","Life without parole","Other","Probation/Community Supervision","Restitution","Shock Probation","State Felony Sentenced as Class A Misdemeanor","Time Served",null];
const CONCURRENT_CONSECUTIVE = ["Concurrent","Consecutive",null];

const NON_CRIMINAL_DISPOSITION_DETAIL = ["Agreed Judgment","All Other Dispositions","Closed  - Probate","Default Judgment","Denied","Dismissed","Dismissed for Want of Prosecution","Disposed","Final Judgment - After Non-Jury Trial","Final Judgment - By Directed Verdict","Final Judgment - By Jury Verdict","Granted","Non-Suited or Dismissed by Plaintiff","Summary Judgment","Transfer - Another County","Transfer/Reassignment - Different Court Level","Transfer/Reassignment - Same Court Level",null];

const PARTY_TYPE = ["Administrator","Creditor","Custodian","Defendant","Defendant/Respondent","Executor","Guardian","Incapacitated Person","Minor","Other","Patient","Plaintiff/Petitioner","Proposed Ward","Resident","Temporary Administrator","Temporary Guardian","Trustee","Ward",null];

// Full field allowlists per entity type (from schema additionalProperties: false)
// Fields not present here will be flagged as additionalProperties violations
const ALLOWED_FIELDS = {
  "di-texas-oca-court-case-status": new Set(["cause_number","recordid","county","publisher","court_id_number","court_name","court_type","primary_case_category","judicial_council_case_category","jcit_case_type","judicial_council_offense_type","local_case_type","current_case_status","case_status_date","case_status_event","case_judicial_officer_name","case_judicial_officer_type","update_date"]),
  "di-texas-oca-court-appointments": new Set(["cause_number","recordid","county","publisher","court_id_number","court_name","court_type","primary_case_category","judicial_council_case_category","jcit_case_type","judicial_council_offense_type","case_style","local_case_type","appointment_type","case_judicial_officer_name","case_judicial_officer_type","appointee","position","relationship_to_ward_or_deceased","approving_judicial_officer_name","appointment_date","source_of_fee","amount_approved","amount_approved_date","number_of_hours_billed","total_billed_expenses","update_date"]),
  "di-texas-oca-court-attorney": new Set(["cause_number","recordid","county","publisher","court_id_number","court_name","court_type","primary_case_category","judicial_council_case_category","jcit_case_type","judicial_council_offense_type","local_case_type","attorney_entry_date","attorney_end_date","attorney_type","party_represented","attorney_name","state_bar_card_number","case_judicial_officer_name","case_judicial_officer_type","update_date"]),
  "di-texas-oca-court-case-events": new Set(["cause_number","recordid","county","publisher","court_id_number","court_name","court_type","primary_case_category","judicial_council_case_category","jcit_case_type","judicial_council_offense_type","event_type","event_date","type_of_mental_health_commitment_ordered","local_case_type","case_initial_filing_date","pleading_motion_outcome","case_judicial_officer_name","case_judicial_officer_type","update_date","event_judicial_officer_name","event_judicial_officer_type"]),
  "di-texas-oca-court-charges": new Set(["cause_number","recordid","county","publisher","court_id_number","court_name","court_type","primary_case_category","judicial_council_case_category","jcit_case_type","judicial_council_offense_type","case_initial_filing_date","party_age_at_time_of_offense","party_race","party_ethnicity","party_sex","party_zip_code","party_indigency_status","offense_date","arrest_date","charge_number","charge_filing_date","filing_statute","statute_citation","filing_offense_code","filing_charge_description","level_and_degree_of_prosecuted_offense","filing_charge_modifiers","prosecution_offense_literal","victim_age","deadly_weapon_finding","charge_disposition_date","charge_sentencing_date","charge_manner_of_disposition","charge_disposition","charge_adjudication","plea_type","plea_date","case_judicial_officer_name","update_date","most_severe_charge"]),
  "di-texas-oca-court-criminal-attorneys": new Set(["cause_number","recordid","county","publisher","court_id_number","primary_case_category","case_type","judicial_council_case_type","attorney_entry_date","attorney_end_date","attorney_type"]),
  "di-texas-oca-court-criminal-case-events": new Set(["cause_number","recordid","county","publisher","court_id_number","primary_case_category","event_type","event_date","case_type","judicial_council_case_type","local_case_type","current_case_status","case_initial_filing_date","initial_filing_type","case_disposition_detail","initial_disposition_date","age_of_case_at_initial_disposition_days","attorney_type_at_initial_disposition","motion_filing_type","pleading_motion_outcome","motion_id","warrant_reason","appointments","trial_information","judicial_officer_type","judicial_officer_first_name","judicial_officer_middle_name","judicial_officer_last_name","set_for_review"])
  // Add more entity types here as schemas are provided
};

const ENTITY_RULES = {
  "di-texas-oca-court-criminal-case-events": {
    numOrNull: ["age_of_case_at_initial_disposition_days"],
    enums: {
      primary_case_category: V01_PRIMARY_CASE_CATEGORY,
      event_type: V01_EVENT_TYPE_CE,
      case_type: V01_CASE_TYPE,
      judicial_council_case_type: V01_JC_CASE_TYPE,
      current_case_status: V01_CURRENT_CASE_STATUS,
      initial_filing_type: V01_INITIAL_FILING_TYPE,
      case_disposition_detail: V01_CASE_DISPOSITION_DETAIL,
      attorney_type_at_initial_disposition: V01_ATTORNEY_TYPE_AT_DISPOSITION,
      pleading_motion_outcome: V01_PLEADING_MOTION_OUTCOME,
      warrant_reason: V01_WARRANT_REASON,
      appointments: APPOINTMENT_TYPE,
      trial_information: V01_TRIAL_INFORMATION,
      judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-criminal-sanctions": {
    numOrNull: ["monetary_penalty_amount"],
    enums: {
      primary_case_category: V01_PRIMARY_CASE_CATEGORY,
      case_type: V01_CASE_TYPE,
      judicial_council_case_type: V01_JC_CASE_TYPE,
      sentence_type: V01_SENTENCE_TYPE,
      concurrent_consecutive_sentence: V01_CONCURRENT_CONSECUTIVE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-criminal-defendants": {
    numOrNull: [],
    enums: {
      primary_case_category: V01_PRIMARY_CASE_CATEGORY,
      case_type: V01_CASE_TYPE,
      judicial_council_case_type: V01_JC_CASE_TYPE,
      defendant_race: PARTY_RACE,
      defendant_ethnicity: PARTY_ETHNICITY,
      defendant_sex: PARTY_SEX
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-criminal-charges": {
    numOrNull: ["victim_age"],
    enums: {
      primary_case_category: V01_PRIMARY_CASE_CATEGORY,
      case_type: V01_CASE_TYPE,
      judicial_council_case_type: V01_JC_CASE_TYPE,
      filing_charge_modifiers: FILING_CHARGE_MODIFIERS,
      disposition_charge_modifier: FILING_CHARGE_MODIFIERS,
      other_enhancements: V01_OTHER_ENHANCEMENTS,
      deadly_weapon_finding: DEADLY_WEAPON_FINDING,
      charge_manner_of_disposition: CHARGE_MANNER_OF_DISPOSITION,
      charge_disposition: V01_CHARGE_DISPOSITION,
      plea_type: V01_PLEA_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-criminal-attorneys": {
    numOrNull: [],
    enums: {
      primary_case_category: V01_PRIMARY_CASE_CATEGORY,
      case_type: V01_CASE_TYPE,
      judicial_council_case_type: V01_JC_CASE_TYPE,
      attorney_type: V01_ATTORNEY_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-charges": {
    numOrNull: ["party_age_at_time_of_offense","victim_age"],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      party_race: PARTY_RACE,
      party_ethnicity: PARTY_ETHNICITY,
      party_sex: PARTY_SEX,
      filing_statute: FILING_STATUTE,
      level_and_degree_of_prosecuted_offense: LEVEL_AND_DEGREE,
      filing_charge_modifiers: FILING_CHARGE_MODIFIERS,
      deadly_weapon_finding: DEADLY_WEAPON_FINDING,
      charge_manner_of_disposition: CHARGE_MANNER_OF_DISPOSITION,
      charge_disposition: CHARGE_DISPOSITION,
      plea_type: PLEA_V3
    },
    badFields: { "filing_statute_citation": "statute_citation", "filing_level_and_degree_of_prosecuted_offense": "level_and_degree_of_prosecuted_offense" },
    refs: { party_age_at_time_of_offense:"OCA-005", party_race:"OCA-011", plea_type:"OCA-010", filing_statute_citation:"OCA-010", filing_level_and_degree_of_prosecuted_offense:"OCA-010" }
  },
  "di-texas-oca-court-appointments": {
    numOrNull: ["amount_approved","number_of_hours_billed","total_billed_expenses"],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      appointment_type: APPOINTMENT_TYPE,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE,
      position: POSITION,
      relationship_to_ward_or_deceased: RELATIONSHIP_TO_WARD,
      source_of_fee: SOURCE_OF_FEE
    },
    badFields: {},
    refs: { amount_approved:"OCA-007", number_of_hours_billed:"OCA-007", total_billed_expenses:"OCA-007" }
  },
  "di-texas-oca-court-attorney": {
    numOrNull: [],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      attorney_type: ATTORNEY_TYPE,
      party_represented: PARTY_REPRESENTED,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-party": {
    numOrNull: ["party_age_at_time_of_offense"],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      party_race: PARTY_RACE,
      party_ethnicity: PARTY_ETHNICITY,
      party_sex: PARTY_SEX,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE,
      party_type: PARTY_TYPE
    },
    badFields: {},
    refs: { party_age_at_time_of_offense:"OCA-011", party_race:"OCA-011" }
  },
  "di-texas-oca-court-dispositions-non_criminal": {
    numOrNull: [],
    enums: {
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      non_criminal_disposition_detail: NON_CRIMINAL_DISPOSITION_DETAIL,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-dispositions-non-criminal": {
    numOrNull: [],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      non_criminal_disposition_detail: NON_CRIMINAL_DISPOSITION_DETAIL,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-dispositions-criminal": {
    numOrNull: ["party_age_at_time_of_offense","victim_age","monetary_penalty_amount_court_costs","monetary_penalty_amount_fines","monetary_penalty_amount_restitution"],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      criminal_disposition_detail: CRIMINAL_DISPOSITION_DETAIL,
      party_race: PARTY_RACE,
      party_ethnicity: PARTY_ETHNICITY,
      party_sex: PARTY_SEX,
      attorney_type: ATTORNEY_TYPE,
      disposition_statute: FILING_STATUTE,
      disposition_charge_modifier: FILING_CHARGE_MODIFIERS,
      disposition_other_enhancements: V01_OTHER_ENHANCEMENTS,
      deadly_weapon_finding: DEADLY_WEAPON_FINDING,
      plea_type: PLEA_V3,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE,
      sentence_type: SENTENCE_TYPE_V3,
      juvenile_disposition_type: JUVENILE_DISPOSITION_TYPE,
      concurrent_consecutive_sentence: CONCURRENT_CONSECUTIVE
    },
    badFields: {},
    refs: {}
  },
  "di-texas-oca-court-case-events": {
    numOrNull: [],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      jcit_case_type: JCIT_CASE_TYPE,
      judicial_council_offense_type: JUDICIAL_COUNCIL_OFFENSE_TYPE,
      event_type: EVENT_TYPE_CE,
      type_of_mental_health_commitment_ordered: MH_COMMITMENT_TYPE,
      pleading_motion_outcome: PLEADING_MOTION_OUTCOME,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE,
      event_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: { county: "OCA-008, OCA-009" }
  },
  "di-texas-oca-court-case-status": {
    numOrNull: [],
    enums: {
      court_type: COURT_TYPE,
      primary_case_category: PRIMARY_CASE_CATEGORY,
      judicial_council_case_category: JUDICIAL_COUNCIL_CASE_CATEGORY,
      current_case_status: CURRENT_CASE_STATUS,
      case_status_event: CASE_STATUS_EVENT,
      case_judicial_officer_type: CASE_JUDICIAL_OFFICER_TYPE
    },
    badFields: {},
    refs: { case_status_event:"OCA-001" }
  }
};

function getTranslation(field, msg, entity) {
  // IL entities: validator writes self-contained messages; no TX translations needed
  if (entity && (entity._market === 'IL' || IL_VALID_ENTITY_TYPES.includes(entity.entityType||''))) {
    return null;
  }
  // Check error library first — library entries take priority over generic translations
  var libMatch = null;
  try { libMatch = matchLibraryEntry(field, msg, entity); } catch(e) {}
  if (libMatch) return libMatch;

  if (field === 'publisher') return 'The publisher name does not exactly match one of the approved values for this contract.';
  if (field === 'recordid') return 'Every entity must include a recordid so the submission can identify the record correctly.';

  if (field === 'county') {
    if (msg.includes('Casey')) return '"Casey" is not a real Texas county, so this submission cannot be accepted as valid production data.';
    if (msg.includes('registered for ~105 counties')) return `"${entity.county}" is a real Texas county, but it is not currently within the registered county scope for this source.`;
    if (msg.includes('County-Subdivision format')) return 'This entity type expects a county and subdivision together, such as "Grayson-Sherman", not just the county name by itself.';
    return 'The county value does not match the approved list for this entity type.';
  }

  if (msg.includes('additionalProperties')) {
    if (entity.entityType === 'di-texas-oca-court-case-status') return `"${field}" does not belong on court-case-status, which usually means this data is being sent under the wrong entity type.`;
    return `"${field}" is not part of the contract for ${entity.entityType}.`;
  }

  if (msg.includes('Wrong field name')) {
    const earlyCorrect = msg.match(/"([^"]+)"$/);
    return `This field name does not match the contract. Use ${earlyCorrect ? earlyCorrect[0] : 'the approved field name'} instead.`;
  }

  if (msg.includes('Invalid value')) {
    if (field === 'plea_type') return 'The plea value was sent in plain language, but this field expects the approved coded format instead.';
    if (field === 'party_race') return '"Not Available" is close, but it does not exactly match the approved contract value for this field.';
    if (field === 'case_status_event') return 'This case status event does not match one of the approved contract values.';
    return getSchemaDerivedTranslation(field, msg, entity) || `The value sent for "${field}" is not one of the approved options for this field.`;
  }

  // entityType errors
  if (field === 'entityType') {
    if (msg.includes('court-charge') && msg.includes('singular')) return 'This entity type name is not part of the contract. Use the approved plural entity type for the event being submitted.';
    if (msg.includes('not in the valid entity type list')) return 'This entity type is not recognized by the contract for the current submission.';
  }
  // county errors
  if (field === 'county') {
    if (msg.includes('Casey')) return '"Casey" is not a Texas county — this is test/demo data using a fake county. The submission cannot land in OCA. Fix owner: Odyssey CMS team (use a real registered county).';
    if (msg.includes('registered for ~105 counties')) return `"${entity.county}" is a real Texas county, but it is not currently within the registered county scope for this source.`;
    if (msg.includes('County-Subdivision format')) return 'v0.1 entity types require a county + court subdivision value (e.g. "Grayson-Sherman"), not just the county name. Fix owner: submitting publisher.';
    return 'The county value submitted is not in the allowed list for this entity type. Fix owner: submitting publisher.';
  }
  // publisher errors
  if (field === 'publisher') return 'The publisher name does not match the approved publisher enum. Verify the Publisher field matches exactly (case-sensitive) to an approved value. Fix owner: submitting publisher.';
  // recordid
  if (field === 'recordid') return 'Every entity must have a unique recordid. This is a required field — the submission cannot be processed without it. Fix owner: submitting publisher.';
  // additionalProperties
  if (msg.includes('additionalProperties')) {
    if (entity.entityType === 'di-texas-oca-court-case-status') return `"${field}" is not a field on court-case-status. Odyssey is likely submitting appointment-entity data under the wrong entity type. The EntityType should be di-texas-oca-court-appointments, not di-texas-oca-court-case-status. Fix owner: Odyssey CMS mapping.`;
    return `"${field}" is not an allowed field on ${entity.entityType}. The publisher is sending extra fields not defined in the contract schema. Remove this field from the payload. Fix owner: submitting publisher.`;
  }
  // type violations (string vs number)
  if (msg.includes('Must be number|null')) return getSchemaDerivedTranslation(field, msg, entity) || `"${field}" should be sent as a number, not as text in quotation marks. The payload sent "${entity && entity[field] !== undefined ? String(entity[field]) : 'this value'}" with quotes around it.`;
  // wrong field names
  if (msg.includes('Wrong field name')) {
    const correct = msg.match(/"([^"]+)"$/);
    return `The field was submitted under the wrong name. Rename it to ${correct ? correct[0] : 'the correct field name'} in the CMS mapping. Fix owner: Odyssey CMS team.`;
  }
  // enum violations
  if (msg.includes('Invalid value')) {
    if (field === 'plea_type') return 'Odyssey is submitting plain-English plea values (e.g. "Guilty") but the schema requires letter-code format (e.g. "G - Guilty"). Fix owner: Odyssey CMS data mapping.';
    if (field === 'party_race') return '"Not Available" is not a valid value — the correct value is "Not Available (Blank)" (exact match required). Fix owner: Odyssey CMS data mapping.';
    if (field === 'case_status_event') return 'The case status event value does not match the approved enum. Check the OCA data dictionary for valid values. Fix owner: submitting publisher.';
    return getSchemaDerivedTranslation(field, msg, entity) || `The submitted value is not in the approved list for "${field}". Check the OCA contract schema for valid values. Fix owner: submitting publisher.`;
  }
  try {
    var schemaDerived = getSchemaDerivedTranslation(field, msg, entity);
    if (schemaDerived) return schemaDerived;
  } catch (e) {}
  return null;
}

function getLibraryEntryMeta(field, msg, entity) {
  try {
    const entries = loadLibrary();
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.entityType && e.entityType !== 'All' && e.entityType !== entity.entityType) continue;
      if (e.field && e.field !== field) continue;
      var matched = false;
      if (e.matchType === 'field_name') {
        matched = true;
      } else if (e.matchType === 'field_value') {
        var val = entity[field];
        matched = val !== undefined && String(val) === String(e.matchValue);
      } else if (e.matchType === 'contains') {
        var val2 = entity[field];
        matched = val2 !== undefined && String(val2).toLowerCase().indexOf(String(e.matchValue).toLowerCase()) !== -1;
      }
      if (matched) return e;
    }
  } catch (e) {}
  return null;
}

function getSchemaObjectForFieldGuide(entityType, market) {
  var overrides = (typeof schemaOverrides !== "undefined" && schemaOverrides[market]) ? schemaOverrides[market] : {};
  if (overrides[entityType]) return overrides[entityType];
  if (market === 'IL' && typeof IL_ENTITY_RULES !== "undefined") return IL_ENTITY_RULES[entityType] || null;
  if (typeof ENTITY_RULES !== "undefined") return ENTITY_RULES[entityType] || null;
  return null;
}

function workbookSchemaRowsForEntity(entityType, market) {
  if (market !== 'TX' || typeof TX_WORKBOOK_SCHEMA_V3 === "undefined" || !TX_WORKBOOK_SCHEMA_V3) return [];
  return Array.isArray(TX_WORKBOOK_SCHEMA_V3[entityType]) ? TX_WORKBOOK_SCHEMA_V3[entityType] : [];
}

function workbookRequiredFieldsForEntity(entityType, market) {
  var required = new Set();
  workbookSchemaRowsForEntity(entityType, market).forEach(function (row) {
    if (row && row.field && row.required) required.add(row.field);
  });
  return required;
}

function mergeRequiredFieldSets(existing, workbookSet) {
  var merged = new Set();
  if (existing && typeof existing.forEach === "function") {
    existing.forEach(function (field) { merged.add(field); });
  } else if (Array.isArray(existing)) {
    existing.forEach(function (field) { merged.add(field); });
  }
  if (workbookSet && typeof workbookSet.forEach === "function") {
    workbookSet.forEach(function (field) { merged.add(field); });
  }
  return merged;
}

function applyWorkbookSchemaSupplement(entityType, market, rules) {
  var workbookRequired = workbookRequiredFieldsForEntity(entityType, market);
  if (!workbookRequired.size) return rules || null;
  var nextRules = Object.assign({}, rules || {});
  nextRules.required = mergeRequiredFieldSets(nextRules.required, workbookRequired);
  return nextRules;
}

function getSchemaFieldGuide(field, entity, msg) {
  if (!entity || !field) return null;
  var market = entity.market || entity._market || (IL_VALID_ENTITY_TYPES.includes(entity.entityType || '') ? 'IL' : 'TX');
  var schemaObject = applyWorkbookSchemaSupplement(entity.entityType, market, getSchemaObjectForFieldGuide(entity.entityType, market) || {}) || {};
  var properties = schemaObject && schemaObject.properties ? schemaObject.properties : {};
  var def = properties[field] || null;
  var requiredSet = new Set(Array.isArray(schemaObject.required) ? schemaObject.required : []);
  var enums = schemaObject && schemaObject.enums ? schemaObject.enums : {};
  var numOrNull = Array.isArray(schemaObject.numOrNull) ? schemaObject.numOrNull : [];
  var dateFields = Array.isArray(schemaObject.dateFields) ? schemaObject.dateFields : [];
  var allowedFields = (typeof ALLOWED_FIELDS !== "undefined" && ALLOWED_FIELDS[entity.entityType]) ? ALLOWED_FIELDS[entity.entityType] : null;

  function inferTypeFromMessage(text) {
    if (!text) return null;
    var mustBeMatch = text.match(/Must be\s+([^—-]+)/i);
    if (mustBeMatch && mustBeMatch[1]) return mustBeMatch[1].trim().replace(/\s+/g, ' ');
    if (/not a valid county/i.test(text)) return 'county enum';
    if (/Invalid value/i.test(text)) return 'string enum';
    return null;
  }

  function normalizeType(definition) {
    if (definition) {
      if (Array.isArray(definition.type) && definition.type.length) return definition.type.join(' | ');
      if (definition.type) return String(definition.type);
      if (Array.isArray(definition.enum) && definition.enum.length) return typeof definition.enum[0] === 'number' ? 'number enum' : 'string enum';
      if (Array.isArray(definition.anyOf) && definition.anyOf.length) return definition.anyOf.map(function (entry) { return entry.type || 'value'; }).filter(Boolean).join(' | ');
      if (Array.isArray(definition.oneOf) && definition.oneOf.length) return definition.oneOf.map(function (entry) { return entry.type || 'value'; }).filter(Boolean).join(' | ');
    }
    if (numOrNull.indexOf(field) !== -1) return 'number | null';
    if (dateFields.indexOf(field) !== -1) return 'date string';
    if (enums[field] && enums[field].length) return 'string enum';
    return inferTypeFromMessage(msg);
  }

  function collectConstraints(definition) {
    var bits = [];
    var enumValues = definition && Array.isArray(definition.enum) ? definition.enum : (enums[field] || null);
    if (enumValues && enumValues.length) bits.push('Enum (' + enumValues.length + ' values)');
    if (numOrNull.indexOf(field) !== -1) bits.push('Number or null');
    if (dateFields.indexOf(field) !== -1) bits.push('Date field');
    if (definition && definition.format) bits.push('Format: ' + definition.format);
    if (definition && typeof definition.maxLength === 'number') bits.push('Max length ' + definition.maxLength);
    if (definition && typeof definition.minLength === 'number') bits.push('Min length ' + definition.minLength);
    if (!bits.length && allowedFields && allowedFields.has && allowedFields.has(field)) bits.push('Recognized contract field');
    return bits;
  }

  function buildNote(definition) {
    var enumValues = definition && Array.isArray(definition.enum) ? definition.enum : (enums[field] || null);
    if (enumValues && enumValues.length) return enumValues.slice(0, 5).join(', ') + (enumValues.length > 5 ? ' +' + (enumValues.length - 5) + ' more' : '');
    if (definition && definition.description) return definition.description;
    if (allowedFields && allowedFields.has && allowedFields.has(field)) return 'This field is part of the loaded contract for this entity.';
    return null;
  }

  var type = normalizeType(def);
  var constraints = collectConstraints(def);
  var note = buildNote(def);
  if (!type && !constraints.length && !note && !(allowedFields && allowedFields.has && allowedFields.has(field))) return null;

  return {
    field: field,
    type: type || 'Contract field',
    required: requiredSet.has(field),
    constraints: constraints,
    note: note
  };
}

function extractCurrentValueFromErrorMessage(msg) {
  if (!msg) return undefined;
  var quotedValue =
    msg.match(/received string ["\u201c']([^"\u201d']+)["\u201d']/i) ||
    msg.match(/Invalid value ["\u201c']([^"\u201d']+)["\u201d']/i) ||
    msg.match(/^["\u201c']([^"\u201d']+)["\u201d']\s+is not a valid county/i);
  if (quotedValue && quotedValue[1] !== undefined) return quotedValue[1];
  var literalValue = msg.match(/received (?:number|integer|boolean|null)\s+([^.,;]+)/i);
  if (literalValue && literalValue[1]) return literalValue[1].trim();
  return undefined;
}

function getSchemaDerivedTranslation(field, msg, entity) {
  if (!field || !msg || !entity) return null;
  var guide = getSchemaFieldGuide(field, entity, msg);
  var currentValue = entity && Object.prototype.hasOwnProperty.call(entity, field) ? entity[field] : extractCurrentValueFromErrorMessage(msg);
  var currentValueText = currentValue === undefined ? null : (currentValue === null ? 'null' : String(currentValue));
  var typeText = guide && guide.type ? guide.type : null;
  var noteText = guide && guide.note ? guide.note : '';

  if (/Required field/i.test(msg)) {
    return `"${field}" is required by the contract${entity.entityType ? ' for ' + entity.entityType : ''} but it was missing from the payload.${typeText ? ' Expected type: ' + typeText + '.' : ''}`;
  }

  if (/Must be /i.test(msg) || /must be a number, not a string/i.test(msg)) {
    return `"${field}" should be sent as ${typeText || 'the expected contract type'}, not as text in quotation marks${currentValueText ? '. The payload sent "' + currentValueText + '" with quotes around it' : ''}.`;
  }

  if (/Invalid value/i.test(msg)) {
    var valueText = currentValueText ? ' "' + currentValueText + '"' : '';
    var extra = noteText ? ' Example allowed values: ' + noteText + '.' : '';
    return `"${field}" received a value${valueText} that is not allowed by the loaded schema.${extra}`;
  }

  if (/additionalProperties/i.test(msg)) {
    return `"${field}" is not part of the loaded contract for ${entity.entityType}.`;
  }

  return null;
}

function formatTrendBadValues(entry) {
  if (!entry || !entry.badValues || !entry.badValues.length) return '—';
  var values = entry.badValues.map(function(v) {
    var text = String(v);
    if ((entry.errorCategory || '').toLowerCase() === 'type error') {
      return 'string "' + text + '"';
    }
    return '"' + text + '"';
  });
  return values.join(', ');
}

// ── Dynamic Schema Derivation ─────────────────────────────────────────────────
// Reads an uploaded schema and derives the same rule shape as ENTITY_RULES
// Built-in ENTITY_RULES always serves as fallback — BIS-layer checks always run
function deriveRulesFromSchema(schema) {
  const numOrNull = [];
  const enums = {};
  const required = new Set(schema.required || []);

  const props = schema.properties || {};
  Object.entries(props).forEach(function(entry) {
    const field = entry[0];
    const def = entry[1];
    if (!def) return;

    // Type derivation — detect number|null fields
    const types = Array.isArray(def.type) ? def.type : (def.type ? [def.type] : []);
    if (types.includes('number') && !types.includes('string')) {
      numOrNull.push(field);
    }

    // Enum derivation — use schema enum array if present
    if (Array.isArray(def.enum) && def.enum.length > 0) {
      enums[field] = def.enum;
    }
  });

  return {
    numOrNull: numOrNull,
    enums: enums,
    required: required,
    // badFields and refs are BIS-layer knowledge — not derivable from schema
    // Always merged from built-in ENTITY_RULES
    badFields: {},
    refs: {}
  };
}

// Merge derived rules with built-in BIS-layer rules
// Derived rules win for enums and numOrNull (schema is authoritative)
// Built-in rules supply badFields, refs, and any checks not in the schema
function mergeRules(derived, builtin) {
  if (!builtin) return derived;
  return {
    // Union of numOrNull — schema derivation may find fields built-in missed
    numOrNull: Array.from(new Set([...derived.numOrNull, ...builtin.numOrNull])),
    // Derived enums win — schema is authoritative for allowed values
    // Built-in fills gaps for fields not in derived (shouldn't happen but safe)
    enums: Object.assign({}, builtin.enums, derived.enums),
    // Required: schema-derived takes precedence
    required: derived.required.size > 0 ? derived.required : (builtin.required || new Set()),
    // badFields and refs always come from built-in — BIS institutional knowledge
    badFields: builtin.badFields || {},
    refs: builtin.refs || {}
  };
}

function validateEntity(entity) {
  // Route to appropriate market validator
  if (entity._market === 'IL' || IL_VALID_ENTITY_TYPES.includes(entity.entityType || '')) {
    return validateEntityIL(entity);
  }
  return validateEntityTX(entity);
}

// ── IL AOIC Validator ─────────────────────────────────────────────────────────
function validateEntityIL(entity) {
  const errors = [];
  const et = entity.entityType || '';

  if (!et) {
    errors.push({ field:'entityType', msg:'Required field "entityType" is missing.', ref:null });
    return errors;
  }

  if (!IL_VALID_ENTITY_TYPES.includes(et)) {
    errors.push({ field:'entityType', msg:'"'+et+'" is not a recognized AOIC entity type. Check the entity type name against the v3.1.0 contract.', ref:null });
    return errors;
  }

  // Required: instanceid on all IL entity types
  if (!entity.instanceid) {
    errors.push({ field:'instanceid', msg:'Required field "instanceid" is missing on all AOIC entity types.', ref:null });
  }
  if (!entity.localid) {
    errors.push({ field:'localid', msg:'Required field "localid" is missing. This is the CMS-assigned local record ID.', ref:null });
  }

  // Source ID / System ID validation (Name field)
  if (entity.name !== undefined) {
    if (!IL_SOURCE_ID_MAP.hasOwnProperty(entity.name)) {
      const validNames = Object.keys(IL_SOURCE_ID_MAP).map(n => '"'+n+'"').join(', ');
      errors.push({ field:'name', msg:'"'+entity.name+'" is not a registered CMS vendor for AOIC. Valid values: '+validNames, ref:null });
    }
  }

  // Get entity-specific rules
  const rules = getILEntityRules(et);
  if (rules) {
    // Required field checks
    rules.required.forEach(function(f) {
      if (entity[f] === undefined || entity[f] === null || entity[f] === '') {
        errors.push({ field:f, msg:'Required field "'+f+'" is missing.', ref:null });
      }
    });

    // Number type checks
    rules.numOrNull.forEach(function(f) {
      if (entity[f] !== undefined && entity[f] !== null && typeof entity[f] === 'string') {
        errors.push({ field:f, msg:'Field "'+f+'" must be a number, not a string. Do not serialize numeric values as quoted strings.', ref:null });
      }
    });

    // Enum validation
    Object.entries(rules.enums).forEach(function(entry) {
      const f = entry[0];
      const valid = entry[1];
      if (entity[f] !== undefined && entity[f] !== null) {
        // Handle semicolon-separated multi-value fields
        const submitted = String(entity[f]);
        if (!valid.includes(submitted)) {
          const display = valid.length > 8 ? valid.slice(0,8).map(v=>'"'+v+'"').join(', ')+', ...' : valid.map(v=>'"'+v+'"').join(', ');
          errors.push({ field:f, msg:'Invalid value "'+submitted+'". Valid options: '+display, ref:null });
        }
      }
    });
  }

  return errors;
}

// ── TX OCA Validator (original, renamed) ─────────────────────────────────────
function validateEntityTX(entity) {
  const errors = [];
  const et = entity.entityType || entity.entity_type;

  if (!et) {
    errors.push({ field:"entityType", msg:'Required field "entityType" is missing.', ref:null });
    return errors;
  }

  if (!ALL_VALID.includes(et)) {
    const bad = KNOWN_BAD[et];
    if (bad) {
      // Resolve correct entity type based on the event type in the envelope
      const evType = entity._eventType || '';
      let suggestion;
      if (evType === 'di-texas-oca-new-record-event') {
        suggestion = 'Use di-texas-oca-court-charges (v3.0.0) — this is a new-record-event.';
      } else if (evType === 'di-texas-oca-delete-record-event') {
        suggestion = 'Use di-texas-oca-court-criminal-charges (v0.1) — this is a delete-record-event.';
      } else {
        suggestion = 'Use di-texas-oca-court-charges (v3.0.0) for new-record-event, or di-texas-oca-court-criminal-charges (v0.1) for delete-record-event.';
      }
      errors.push({ field:"entityType", msg:`Invalid entity type "${et}". ${suggestion}`, ref:bad.ocaRef });
    } else {
      errors.push({ field:"entityType", msg:`"${et}" is not in the valid entity type list for new-record-event or delete-record-event.`, ref:null });
    }
    return errors;
  }

  const isV3 = VALID_V3.includes(et);

  if (!entity.recordid) errors.push({ field:"recordid", msg:'Required field "recordid" is missing.', ref:null });

  if (!entity.county) {
    errors.push({ field:"county", msg:'Required field "county" is missing.', ref:null });
  } else if (isV3) {
    const isOdyssey = entity.publisher === "Tyler Tech-Odyssey";
    const countyValid = isOdyssey ? ODYSSEY_COUNTIES.has(entity.county) : V3_COUNTIES.includes(entity.county);
    if (!countyValid) {
      const isKnownFake = entity.county === "Casey";
      const odysseyNote = isOdyssey ? ` (Tyler Tech-Odyssey Source ID is registered for ~105 counties — "${entity.county}" is not among them. Submit ticket to D&I to request registration expansion.)` : " (county-only enum, no subdivisions)";
      errors.push({ field:"county", msg:`"${entity.county}" is not a valid county for this publisher's v3.0.0 submission${odysseyNote}.`, ref: isKnownFake ? "OCA-007, OCA-008, OCA-009" : null });
    }
  } else if (!isV3 && !V01_COUNTIES.has(entity.county)) {
    errors.push({ field:"county", msg:`"${entity.county}" is not a valid v0.1 county value (County-Subdivision format, e.g. "Grayson-Sherman").`, ref:null });
  }

  if (!entity.publisher) {
    errors.push({ field:"publisher", msg:'Required field "publisher" is missing.', ref:null });
  } else if (!PUBLISHERS.includes(entity.publisher)) {
    errors.push({ field:"publisher", msg:`"${entity.publisher}" is not in the allowed publisher enum.`, ref:null });
  }

  // Determine active rules — dynamic derivation from uploaded schema merged with built-in
  const market = 'TX';
  const uploadedSchema = schemaOverrides[market] && schemaOverrides[market][et];
  const builtinRules = ENTITY_RULES[et];
  let activeRules;

  if (uploadedSchema) {
    const derived = deriveRulesFromSchema(uploadedSchema);
    activeRules = mergeRules(derived, builtinRules);
  } else {
    activeRules = builtinRules;
  }

  activeRules = applyWorkbookSchemaSupplement(et, market, activeRules);

  if (activeRules) {
    // Type checks — number|null fields sent as strings
    activeRules.numOrNull.forEach(function(f) {
      if (entity[f] !== undefined && entity[f] !== null && typeof entity[f] === 'string') {
        errors.push({ field:f, msg:'Must be number|null — received string "' + entity[f] + '". Do not serialize as a quoted value.', ref:(activeRules.refs[f]||null) });
      }
    });

    // Enum checks — value not in allowed list
    Object.entries(activeRules.enums).forEach(function(entry) {
      const f = entry[0];
      const valid = entry[1];
      if (entity[f] !== undefined && !valid.includes(entity[f])) {
        const opts = valid.filter(function(v) { return v !== null; });
        const display = opts.length > 8
          ? opts.slice(0,8).map(function(v) { return '"' + v + '"'; }).join(', ') + ', ...'
          : opts.map(function(v) { return '"' + v + '"'; }).join(', ');
        const src = uploadedSchema ? ' (from uploaded schema)' : '';
        errors.push({ field:f, msg:'Invalid value "' + entity[f] + '"' + src + '. Valid options: ' + display, ref:(activeRules.refs[f]||null) });
      }
    });

    // Bad field name traps — BIS institutional knowledge, always from built-in
    Object.entries(activeRules.badFields).forEach(function(entry) {
      const bad = entry[0];
      const correct = entry[1];
      if (entity[bad] !== undefined) {
        errors.push({ field:bad, msg:'Wrong field name — the correct field name is "' + correct + '".', ref:(activeRules.refs[bad]||null) });
      }
    });
  }

  // additionalProperties check — only runs when we have a full schema for this entity type
  // Additional properties check — uploaded schema takes priority over built-in
  // uploadedSchema already resolved above
  let allowedFields;
  if (uploadedSchema && uploadedSchema.properties) {
    allowedFields = new Set(Object.keys(uploadedSchema.properties));
  } else {
    allowedFields = ALLOWED_FIELDS[et];
  }
  if (allowedFields) {
    const reserved = new Set(['entityType','entityId','_eventType']);
    Object.keys(entity).forEach(function(f) {
      if (!reserved.has(f) && !allowedFields.has(f)) {
        const src = uploadedSchema ? ' (uploaded schema)' : '';
        errors.push({ field:f, msg:'Additional property not allowed by schema' + src + ' (additionalProperties: false). Remove this field.', ref:null });
      }
    });
  }

  return errors;
}

function normalizeEntity(raw, eventType) {
  // Fields live inside EntityData in the full envelope format
  const data = raw.EntityData || raw.entityData || {};
  // EntityType can be Pascal (EntityType) or camel (entityType / entity_type)
  const entityType = raw.EntityType || raw.entityType || raw.entity_type
                  || data.EntityType || data.entityType || data.entity_type || '';
  const entityId = raw.EntityId || raw.entityId || null;
  // Merge EntityData fields up so validators can read them flat
  // _eventType is internal-only — used for context-aware error messages
  return { entityType, entityId, _eventType: eventType || '', ...data };
}



// ── Entity count preview ─────────────────────────────────────────────────────
function updateEntityPreview() {
  const ta = document.getElementById('input-area');
  const preview = document.getElementById('entity-preview');
  if (!ta || !preview) return;
  const text = ta.value.trim();
  if (!text) { preview.textContent = ''; return; }
  try {
    const p = JSON.parse(text);
    let count = 0;
    if (p.Events && Array.isArray(p.Events)) {
      p.Events.forEach(ev => { count += (ev.Entities || []).length; });
    } else if (p.entities && Array.isArray(p.entities)) {
      count = p.entities.length;
    } else if (Array.isArray(p)) {
      count = p.length;
    } else {
      count = 1;
    }
    preview.textContent = count + ' entit' + (count === 1 ? 'y' : 'ies') + ' detected';
    preview.style.color = 'var(--cyan)';
  } catch(e) {
    if (text.length > 5) {
      preview.textContent = 'invalid JSON';
      preview.style.color = 'var(--red)';
    } else {
      preview.textContent = '';
    }
  }
}


// ── Tab badges ───────────────────────────────────────────────────────────────
function updateTabBadges() {
  // History badge
  try {
    const runs = loadHistory();
    const badge = document.getElementById('tab-badge-history');
    if (badge) {
      if (runs.length > 0) {
        badge.textContent = runs.length > 99 ? '99+' : runs.length;
        badge.style.display = 'inline-block';
      } else {
        badge.style.display = 'none';
      }
    }
  } catch(e) {}
  // Catalog badge — count unique errors from history
  try {
    const errBadge = document.getElementById('tab-badge-catalog');
    if (errBadge) {
      const runs = loadHistory();
      const errRuns = runs.filter(r => r.errorCount > 0);
      if (errRuns.length > 0) {
        const totalErrs = errRuns.reduce((s, r) => s + r.errorCount, 0);
        errBadge.textContent = totalErrs > 999 ? '999+' : totalErrs;
        errBadge.style.display = 'inline-block';
      } else {
        errBadge.style.display = 'none';
      }
    }
  } catch(e) {}
}


// ── Drag-and-drop payload file ───────────────────────────────────────────────
function handlePayloadDrop(e) {
  e.preventDefault();
  const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (!file) return;
  if (!file.name.endsWith('.json') && file.type !== 'application/json' && file.type !== 'text/plain') {
    alert('Please drop a .json file.');
    return;
  }
  const reader = new FileReader();
  reader.onload = function(ev) {
    const ta = document.getElementById('input-area');
    if (ta) {
      ta.value = ev.target.result;
      updateEntityPreview();
    }
  };
  reader.readAsText(file);
}


// ── History filter clear ──────────────────────────────────────────────────────
function clearHistoryFilter() {
  const input = document.getElementById('history-filter');
  if (input) { input.value = ''; renderHistory(); }
  const btn = document.getElementById('history-filter-clear');
  if (btn) btn.style.display = 'none';
}
function updateHistoryFilterClear() {
  const input = document.getElementById('history-filter');
  const btn = document.getElementById('history-filter-clear');
  if (!input || !btn) return;
  btn.style.display = input.value.trim() ? 'inline-block' : 'none';
}

// ── Legend toggle ────────────────────────────────────────────────────────────
function toggleLegend(e) {
  e.stopPropagation();
  const pop = document.getElementById('legend-popover');
  if (!pop) return;
  pop.classList.toggle('open');
}
// Close legend when clicking elsewhere
document.addEventListener('click', function(e) {
  const pop = document.getElementById('legend-popover');
  if (pop && pop.classList.contains('open') && !pop.contains(e.target)) {
    pop.classList.remove('open');
  }
});

// ── Timestamp helpers ────────────────────────────────────────────────────────
function formatUnixMs(ts) {
  if (!ts) return null;
  try {
    const d = new Date(Number(ts));
    if (isNaN(d.getTime())) return null;
    return d.toLocaleString('en-US', {
      month: '2-digit', day: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short'
    });
  } catch(e) { return null; }
}

function parseInput(text) {
  try {
    const p = JSON.parse(text);

    // ── IL AOIC envelope: { EventType, Entities: [{EntityType, instanceid, ...}] }
    if (p.EventType && IL_EVENT_TYPES.includes(p.EventType) && Array.isArray(p.Entities)) {
      const entities = p.Entities.map(function(e) { return normalizeEntityIL(e, p.EventType); });
      // IL has no envelope-level Publisher — derive from unique entity .name values
      const ilNames = [...new Set(p.Entities.map(e => e.name || e.Name || '').filter(Boolean))];
      const ilPublisher = ilNames.length > 0 ? ilNames.join('; ') : null;
      return { entities, eventType: p.EventType, envelopeId: p.envelopeId || null, publisher: ilPublisher, market: 'IL' };
    }

    // ── TX OCA full envelope: { Events: [{ EventType, Entities: [...] }] }
    if (p.Events && Array.isArray(p.Events)) {
      const entities = [];
      const evType = p.EventType || null;
      p.Events.forEach(ev => (ev.Entities || []).forEach(ent => entities.push(normalizeEntity(ent, evType))));
      return { entities, eventType: evType, envelopeId: p.EnvelopeId || null, publisher: p.Publisher || null, market: 'TX', originalTimestamp: p.OriginalTimestamp || null };
    }
    // Simple envelope: { eventType, entities: [...] }
    if (p.entities && Array.isArray(p.entities)) {
      const evType = p.eventType || null;
      const firstET = (p.entities[0] && (p.entities[0].EntityType || p.entities[0].entityType)) || '';
      const simpleMarket = IL_VALID_ENTITY_TYPES.includes(firstET) ? 'IL' : 'TX';
      if (simpleMarket === 'IL') {
        const simpleILNames = [...new Set(p.entities.map(e => e.name || e.Name || '').filter(Boolean))];
        const simpleILPublisher = simpleILNames.length > 0 ? simpleILNames.join('; ') : (p.publisher || null);
        return { entities: p.entities.map(e => normalizeEntityIL(e, evType)), eventType: evType, envelopeId: p.envelopeId || null, publisher: simpleILPublisher, market: 'IL' };
      }
      return { entities: p.entities.map(e => normalizeEntity(e, evType)), eventType: evType, envelopeId: p.envelopeId || null, publisher: p.publisher || null, market: 'TX' };
    }
    // Array of entities — detect market by first entity type
    if (Array.isArray(p)) {
      const firstET = (p[0] && (p[0].EntityType || p[0].entityType)) || '';
      const market = IL_VALID_ENTITY_TYPES.includes(firstET) ? 'IL' : 'TX';
      const normalizer = market === 'IL' ? normalizeEntityIL : normalizeEntity;
      const arrPublisher = market === 'IL'
        ? ([...new Set(p.map(e => e.name || e.Name || '').filter(Boolean))].join('; ') || null)
        : null;
      return { entities: p.map(e => normalizer(e, null)), eventType: null, envelopeId: null, publisher: arrPublisher, market };
    }
    // Single entity
    const singleET = p.EntityType || p.entityType || '';
    const singleMarket = IL_VALID_ENTITY_TYPES.includes(singleET) ? 'IL' : 'TX';
    const singleNorm = singleMarket === 'IL' ? normalizeEntityIL : normalizeEntity;
    const singlePublisher = singleMarket === 'IL' ? (p.name || p.Name || null) : null;
    return { entities: [singleNorm(p, null)], eventType: null, envelopeId: null, publisher: singlePublisher, market: singleMarket };
  } catch(e) { return { error: e.message }; }
}

// IL entity normalizer — fields are flat (no EntityData nesting)
function normalizeEntityIL(raw, eventType) {
  const entityType = raw.EntityType || raw.entityType || '';
  const entityId = raw.EntityId || raw.entityId || null;
  const flat = Object.assign({}, raw);
  // Normalize casing of EntityType key to lowercase for validators
  delete flat.EntityType;
  flat.entityType = entityType;
  flat._eventType = eventType || '';
  flat._market = 'IL';
  if (entityId) flat.entityId = entityId;
  return flat;
}

function splitBatchDocuments(text) {
  const src = String(text || '').trim();
  if (!src) return [];

  const docs = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inString) {
      if (escape) escape = false;
      else if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      if (start === -1) start = i;
      continue;
    }
    if (ch === '{' || ch === '[') {
      if (depth === 0 && start === -1) start = i;
      depth++;
      continue;
    }
    if (ch === '}' || ch === ']') {
      depth--;
      if (depth === 0 && start !== -1) {
        const candidate = src.slice(start, i + 1).trim();
        if (candidate) docs.push(candidate);
        start = -1;
      }
    }
  }

  if (docs.length) return docs;

  return src.split(/\r?\n\s*\r?\n/g).map(function(part) {
    return part.trim();
  }).filter(Boolean);
}

function buildValidationRunFromText(text, options) {
  options = options || {};
  const parsed = parseInput(text);
  if (parsed.error) return { sourceText: text, parsed: parsed, error: parsed.error };

  const analysedDate = options.analysedDate instanceof Date ? options.analysedDate : new Date();
  const analysedAt = analysedDate.toLocaleString('en-US', {
    month:'2-digit',day:'2-digit',year:'numeric',
    hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'
  });
  const submittedAt = parsed.originalTimestamp ? formatUnixMs(parsed.originalTimestamp) : null;
  const historyTimestamp = analysedDate.toLocaleString('en-US', {
    month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'
  });

  const results = parsed.entities.map(function(e, i) {
    const errors = validateEntity(e);
    const market = parsed.market || (IL_VALID_ENTITY_TYPES.includes(e.entityType || '') ? 'IL' : 'TX');
    return {
      i: i,
      entityType: e.entityType || 'Unknown',
      entityId: e.entityId || null,
      recordid: e.recordid || '—',
      county: e.county || '—',
      instanceid: e.instanceid || '—',
      localid: e.localid || '—',
      market: market,
      _name: e.name || '',
      raw: e,
      errors: errors,
      valid: errors.length === 0
    };
  });

  const totalErr = results.reduce(function(sum, row) { return sum + row.errors.length; }, 0);
  const validN = results.filter(function(row) { return row.valid; }).length;
  const invalidEntities = results.filter(function(row) { return !row.valid; }).length;
  const topFieldMap = {};
  const ownerMap = {};
  const historyErrors = [];

  results.forEach(function(row) {
    row.errors.forEach(function(err) {
      const translation = getTranslation(err.field, err.msg, row) || '';
      topFieldMap[err.field] = (topFieldMap[err.field] || 0) + 1;
      const owner = _extractFixOwner(translation) || 'Unassigned';
      ownerMap[owner] = (ownerMap[owner] || 0) + 1;
      historyErrors.push({
        entityId: row.entityId,
        recordid: row.recordid,
        county: row.county,
        entityType: row.entityType,
        field: err.field,
        ref: err.ref || '',
        msg: err.msg,
        translation: translation,
        publisher: parsed.publisher || row._name || ''
      });
    });
  });

  const topField = Object.keys(topFieldMap).sort(function(a, b) { return topFieldMap[b] - topFieldMap[a]; })[0] || 'None';
  const topOwner = Object.keys(ownerMap).sort(function(a, b) { return ownerMap[b] - ownerMap[a]; })[0] || 'None';
  const envelopeId = (options.envelopeId || '').trim() || parsed.envelopeId || null;

  return {
    sourceText: text,
    parsed: parsed,
    sourceMode: options.sourceMode || 'single',
    batchSessionId: options.batchSessionId || '',
    results: results,
    totalErr: totalErr,
    validN: validN,
    invalidEntities: invalidEntities,
    totalEntities: results.length,
    submittedAt: submittedAt,
    analysedAt: analysedAt,
    topField: topField,
    topOwner: topOwner,
    historyRun: {
      timestamp: historyTimestamp,
      analysedAt: analysedDate.toISOString(),
      envelopeSubmittedAt: submittedAt,
      originalTimestamp: parsed.originalTimestamp || null,
      envelopeId: envelopeId,
      sourceMode: options.sourceMode || 'single',
      batchSessionId: options.batchSessionId || '',
      eventType: parsed.eventType || '',
      publisher: parsed.publisher || '',
      market: parsed.market || 'TX',
      entityCount: results.length,
      errorCount: totalErr,
      errors: historyErrors
    }
  };
}

function persistValidationRun(validationRun, options) {
  options = options || {};
  if (!validationRun || validationRun.error || options.saveHistory === false) return;
  try { addToHistory(validationRun.historyRun); } catch(e) {}
  if ((validationRun.parsed.market || 'TX') === 'TX') {
    try {
      autoLogRunToErrorLog(
        validationRun.parsed,
        validationRun.results,
        validationRun.historyRun.envelopeId,
        validationRun.parsed.originalTimestamp || null
      );
    } catch(e) {}
  }
}

function renderSingleValidationRun(validationRun) {
  const ra = document.getElementById('results-area');
  const sb = document.getElementById('summary-bar');
  const rc = document.getElementById('result-count');
  const copyBtn = document.getElementById('copy-results-btn');
  if (!ra || !sb || !rc) return;

  _activeResultFilter = 'all';
  const prevErrBtn = document.getElementById('sb-err-btn');
  const prevOkBtn = document.getElementById('sb-ok-btn');
  const prevClrBtn = document.getElementById('sb-clear-btn');
  if (prevErrBtn) prevErrBtn.classList.remove('active-filter');
  if (prevOkBtn) prevOkBtn.classList.remove('active-filter');
  if (prevClrBtn) prevClrBtn.classList.remove('visible');

  if (!validationRun || validationRun.error) {
    const msg = validationRun && validationRun.error ? validationRun.error : 'Unable to validate this payload.';
    ra.innerHTML = `<div class="parse-error"><div class="parse-error-title">✕ JSON Parse Error</div><div class="parse-error-msg">${escHtml(msg)}</div></div>`;
    sb.style.display = 'none';
    rc.textContent = '';
    if (copyBtn) copyBtn.style.display = 'none';
    try {
      const heroEventType = document.getElementById('hero-event-type');
      const heroSubmittedAt = document.getElementById('hero-submitted-at');
      const heroAnalysedAt = document.getElementById('hero-analysed-at');
      const heroRunSummary = document.getElementById('hero-run-summary');
      const heroRunMeta = document.getElementById('hero-run-meta');
      if (heroEventType) heroEventType.textContent = 'Invalid JSON';
      if (heroSubmittedAt) heroSubmittedAt.textContent = 'Not available';
      if (heroAnalysedAt) heroAnalysedAt.textContent = 'Not available';
      if (heroRunSummary) heroRunSummary.textContent = '0 entities / parse error';
      if (heroRunMeta) heroRunMeta.textContent = 'Fix JSON structure to validate this payload.';
    } catch(e) {}
    return;
  }

  const parsed = validationRun.parsed;
  const results = validationRun.results;
  const totalErr = validationRun.totalErr;
  const submittedAt = validationRun.submittedAt;
  const analysedAt = validationRun.analysedAt;

  sb.style.display = 'flex';
  let sbHtml = '';
  if (parsed.eventType) {
    sbHtml += `<span class="sum-neutral">eventType:</span><span style="color:var(--cyan);margin-left:4px">${escHtml(parsed.eventType)}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  }
  if (submittedAt) {
    sbHtml += `<span class="sum-neutral">submitted:</span><span style="color:var(--orange);margin-left:4px" title="Envelope OriginalTimestamp: ${escHtml(parsed.originalTimestamp)}">${escHtml(submittedAt)}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  }
  sbHtml += `<span class="sum-neutral">CATCH analysed:</span><span style="color:var(--purple);margin-left:4px">${escHtml(analysedAt)}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  sbHtml += `<span class="sum-neutral">entities:</span><span style="color:var(--text);margin-left:4px">${results.length}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  if (totalErr === 0) {
    sbHtml += `<span class="sum-ok">✓ All valid</span>`;
  } else {
    sbHtml += `<button class="sum-filter-btn sum-err" id="sb-err-btn" onclick="applyResultFilter('errors')" title="Show only errors">✕ ${totalErr} error${totalErr>1?'s':''}</button><button class="sum-filter-clear" id="sb-clear-btn" onclick="applyResultFilter('all')">✕ clear filter</button>`;
  }
  sb.innerHTML = sbHtml;
  rc.textContent = '';

  try {
    const heroEventType = document.getElementById('hero-event-type');
    const heroSubmittedAt = document.getElementById('hero-submitted-at');
    const heroAnalysedAt = document.getElementById('hero-analysed-at');
    const heroRunSummary = document.getElementById('hero-run-summary');
    const heroRunMeta = document.getElementById('hero-run-meta');
    if (heroEventType) heroEventType.textContent = parsed.eventType || 'Single entity / custom payload';
    if (heroSubmittedAt) heroSubmittedAt.textContent = submittedAt || 'Not provided';
    if (heroAnalysedAt) heroAnalysedAt.textContent = analysedAt;
    if (heroRunSummary) heroRunSummary.textContent = `${results.length} entities · ${totalErr} error${totalErr === 1 ? '' : 's'}`;
    if (heroRunMeta) heroRunMeta.textContent = totalErr === 0 ? 'Filter: all findings' : `Filter: all findings · ${validationRun.validN} passed`;
  } catch(e) {}

  try {
    const resultsHero = `<div class="results-toolbar">
      <div>
        <div class="results-toolbar-label">Findings filter</div>
        <div class="results-toolbar-copy">Switch between all findings and error-only review without losing the current validation run.</div>
      </div>
      <div class="results-filter-group">
        <button class="results-filter-btn active" id="results-filter-all" onclick="applyResultFilter('all')">All findings</button>
        <button class="results-filter-btn ${totalErr === 0 ? 'disabled' : ''}" id="results-filter-errors" onclick="applyResultFilter('errors')" ${totalErr === 0 ? 'disabled' : ''}>Errors only</button>
      </div>
    </div><div class="results-hero-strip">
      <div class="results-kpi"><span class="results-kpi-label">Total issues</span><strong class="results-kpi-value">${validationRun.totalErr}</strong></div>
      <div class="results-kpi"><span class="results-kpi-label">Affected entities</span><strong class="results-kpi-value">${validationRun.invalidEntities}/${validationRun.totalEntities}</strong></div>
      <div class="results-kpi"><span class="results-kpi-label">Top repeated field</span><strong class="results-kpi-value results-kpi-text">${escHtml(validationRun.topField)}</strong></div>
      <div class="results-kpi"><span class="results-kpi-label">Top fix owner</span><strong class="results-kpi-value results-kpi-text">${escHtml(validationRun.topOwner)}</strong></div>
    </div>`;
    ra.innerHTML = resultsHero + results.map(r => {
      const cls = r.valid ? 'valid' : 'invalid';
      let html = `<div class="result-card ${cls}">
        <div class="result-header">
          <span class="${r.valid ? 'status-valid' : 'status-invalid'}">${r.valid ? '✓ VALID' : '✕ INVALID'} · Entity ${r.i + 1}</span>
          <span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 8px;" title="${escHtml(r.entityType)}">${escHtml(r.entityType)}</span>
          ${!r.valid ? `<span class="error-count">${r.errors.length} error${r.errors.length>1?'s':''}</span>` : ''}
        </div>
        <div class="result-meta">
          <div class="meta-row"><span class="meta-key">entityType:</span><span class="meta-val">${escHtml(r.entityType)}</span></div>
          ${r.entityId ? `<div class="meta-row"><span class="meta-key">entityId &nbsp;:</span><span class="meta-val">${escHtml(r.entityId)}</span></div>` : ''}
          <div class="meta-row"><span class="meta-key">recordid &nbsp;:</span><span class="meta-val">${escHtml(r.recordid)}</span></div>
          ${r.market === 'IL'
            ? `<div class="meta-row"><span class="meta-key">instanceid:</span><span class="meta-val">${escHtml(r.instanceid||'—')}</span></div><div class="meta-row"><span class="meta-key">localid &nbsp; :</span><span class="meta-val">${escHtml(r.localid||'—')}</span></div>`
            : `<div class="meta-row"><span class="meta-key">county &nbsp;&nbsp; :</span><span class="meta-val">${escHtml(r.county)}</span></div>`
          }
        </div>`;
      if (r.valid) {
        html += `<div style="padding:6px 12px 10px;color:var(--green);font-size:10.5px">All checks passed.</div>`;
      } else {
        html += `<div class="error-list">`;
        r.errors.forEach(err => {
          const translation = getTranslation(err.field, err.msg, r);
          html += `<div class="error-item" style="cursor:pointer;" title="Click to jump to '${err.field.replace(/'/g,"\\'")}' in the payload" data-field="${escHtml(err.field)}" data-idx="${r.i}" onclick="jumpToField(this.dataset.field, parseInt(this.dataset.idx))">
            <div class="error-field-row">
              <span class="error-field">${escHtml(err.field)}</span>
              <span style="font-size:8px;color:var(--text3);margin-left:auto;padding-left:8px;opacity:0.7;letter-spacing:0.03em;">↖ jump</span>
            </div>
            <div class="finding-columns">
              <div class="finding-panel finding-panel-technical">
                <div class="finding-label">Technical error</div>
                <div class="error-msg">${escHtml(err.msg)}</div>
              </div>
              <div class="finding-panel finding-panel-plain">
                <div class="finding-label">Plain English</div>
                ${translation ? `<div class="error-translation">${escHtml(translation)}</div>` : `<div class="error-translation error-translation-empty">No plain-English translation was matched for this issue yet.</div>`}
                <button class="refine-error-btn" type="button" onclick='openRefineErrorModal(${JSON.stringify(JSON.stringify({ source:"finding", entityType:r.entityType, field:err.field, message:err.msg, translation:translation || "", fixOwner:_extractFixOwner(translation) || "Odyssey", action:"", ref:err.ref || "", matchValue:"", matchType:"contains" }))})'>Refine this error</button>
              </div>
            </div>
          </div>`;
        });
        html += `</div>`;
      }
      html += `</div>`;
      return html;
    }).join('');
  } catch(renderErr) { console.error(renderErr); }

  if (copyBtn) copyBtn.style.display = 'inline';
  _lastValidationResults = results;
  _lastValidationParsed = parsed;
}


function runValidation() {
  const text = document.getElementById('input-area').value.trim();
  if (!text) return;
  const runBtn = document.getElementById('run-btn');
  if (runBtn) { runBtn.disabled = true; runBtn.textContent = '⏳ Running…'; }
  // Defer to next tick so the button state renders before heavy work
  setTimeout(function() { _runValidationCore(); }, 10);
}
function _runValidationCore() {
  const text = document.getElementById('input-area').value.trim();
  const runBtn = document.getElementById('run-btn');
  function restoreBtn() { if (runBtn) { runBtn.disabled = false; runBtn.innerHTML = '▶&nbsp; Run Validation'; } }
  if (!text) { restoreBtn(); return; }
  const overrideElModern = document.getElementById('envelope-override');
  const validationRunModern = buildValidationRunFromText(text, {
    envelopeId: overrideElModern ? overrideElModern.value.trim() : ''
  });
  if (!validationRunModern.error) {
    try {
      if (overrideElModern && validationRunModern.parsed.envelopeId && !overrideElModern.dataset.manuallySet && !overrideElModern.value.trim()) {
        overrideElModern.value = validationRunModern.parsed.envelopeId;
        validationRunModern.historyRun.envelopeId = validationRunModern.historyRun.envelopeId || validationRunModern.parsed.envelopeId;
      }
    } catch(e) {}
    persistValidationRun(validationRunModern);
  }
  renderSingleValidationRun(validationRunModern);
  restoreBtn();
  updateTabBadges();
  return;
  if (!text) { restoreBtn(); return; }
  const ra = document.getElementById('results-area');
  const sb = document.getElementById('summary-bar');
  const rc = document.getElementById('result-count');
  _activeResultFilter = 'all';
  const _prevErrBtn = document.getElementById('sb-err-btn');
  const _prevOkBtn  = document.getElementById('sb-ok-btn');
  const _prevClrBtn = document.getElementById('sb-clear-btn');
  if (_prevErrBtn) _prevErrBtn.classList.remove('active-filter');
  if (_prevOkBtn)  _prevOkBtn.classList.remove('active-filter');
  if (_prevClrBtn) _prevClrBtn.classList.remove('visible');

  const parsed = parseInput(text);
  const copyBtn = document.getElementById('copy-results-btn');
  if (parsed.error) {
    ra.innerHTML = `<div class="parse-error"><div class="parse-error-title">✗ JSON Parse Error</div><div class="parse-error-msg">${escHtml(parsed.error)}</div></div>`;
    sb.style.display = 'none';
    rc.textContent = '';
    if (copyBtn) copyBtn.style.display = 'none';
    try {
      const heroEventType = document.getElementById('hero-event-type');
      const heroSubmittedAt = document.getElementById('hero-submitted-at');
      const heroAnalysedAt = document.getElementById('hero-analysed-at');
      const heroRunSummary = document.getElementById('hero-run-summary');
      const heroRunMeta = document.getElementById('hero-run-meta');
      if (heroEventType) heroEventType.textContent = 'Invalid JSON';
      if (heroSubmittedAt) heroSubmittedAt.textContent = 'Not available';
      if (heroAnalysedAt) heroAnalysedAt.textContent = 'Not available';
      if (heroRunSummary) heroRunSummary.textContent = '0 entities / parse error';
      if (heroRunMeta) heroRunMeta.textContent = 'Fix JSON structure to validate this payload.';
    } catch(e) {}
    return;
  }

  // Auto-populate EnvelopeId override field if not manually set
  try {
    const overrideField = document.getElementById('envelope-override');
    if (overrideField && parsed.envelopeId && !overrideField.dataset.manuallySet) {
      overrideField.value = parsed.envelopeId;
    }
  } catch(e) {}

  const results = parsed.entities.map((e, i) => {
    const errors = validateEntity(e);
    const market = parsed.market || (IL_VALID_ENTITY_TYPES.includes(e.entityType||'') ? 'IL' : 'TX');
    return {
      i,
      entityType: e.entityType || "Unknown",
      entityId: e.entityId || null,
      recordid: e.recordid || "—",
      county: e.county || "—",
      instanceid: e.instanceid || "—",
      localid: e.localid || "—",
      market,
      _name: e.name || '',
      raw: e,
      errors,
      valid: errors.length === 0
    };
  });

  const totalErr = results.reduce((s,r) => s + r.errors.length, 0);
  const validN = results.filter(r => r.valid).length;

  sb.style.display = 'flex';
  let sbHtml = '';
  if (parsed.eventType) {
    sbHtml += `<span class="sum-neutral">eventType:</span><span style="color:var(--cyan);margin-left:4px">${parsed.eventType}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  }
  // Envelope submission time from OriginalTimestamp
  const submittedAt = parsed.originalTimestamp ? formatUnixMs(parsed.originalTimestamp) : null;
  if (submittedAt) {
    sbHtml += `<span class="sum-neutral">submitted:</span><span style="color:var(--orange);margin-left:4px" title="Envelope OriginalTimestamp: ${parsed.originalTimestamp}">${submittedAt}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  }
  const analysedAt = new Date().toLocaleString('en-US', {month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'});
  sbHtml += `<span class="sum-neutral">CATCH analysed:</span><span style="color:var(--purple);margin-left:4px">${analysedAt}</span><span style="margin:0 8px;color:var(--text3)">·</span>`;
  sbHtml += `<span class="sum-neutral">entities:</span><span style="color:var(--text);margin-left:4px">${results.length}</span>`;
  sbHtml += `<span style="margin:0 8px;color:var(--text3)">·</span>`;
  if (totalErr === 0) {
    sbHtml += `<span class="sum-ok">✓ All valid</span>`;
  } else {
    sbHtml += `<button class="sum-filter-btn sum-err" id="sb-err-btn" onclick="applyResultFilter('errors')" title="Show only errors">✗ ${totalErr} error${totalErr>1?'s':''}</button><button class="sum-filter-clear" id="sb-clear-btn" onclick="applyResultFilter('all')">✕ clear filter</button>`;
  }
  sb.innerHTML = sbHtml;
  rc.textContent = '';

  try {
    const heroEventType = document.getElementById('hero-event-type');
    const heroSubmittedAt = document.getElementById('hero-submitted-at');
    const heroAnalysedAt = document.getElementById('hero-analysed-at');
    const heroRunSummary = document.getElementById('hero-run-summary');
    const heroRunMeta = document.getElementById('hero-run-meta');
    if (heroEventType) heroEventType.textContent = parsed.eventType || 'Single entity / custom payload';
    if (heroSubmittedAt) heroSubmittedAt.textContent = submittedAt || 'Not provided';
    if (heroAnalysedAt) heroAnalysedAt.textContent = analysedAt;
    if (heroRunSummary) heroRunSummary.textContent = `${results.length} entities · ${totalErr} error${totalErr === 1 ? '' : 's'}`;
    if (heroRunMeta) heroRunMeta.textContent = totalErr === 0 ? 'Filter: all findings' : `Filter: all findings · ${validN} passed`;
  } catch(e) {}

  // Record this run in history — wrapped in try/catch so storage failure never blocks validation
  try {
    const overrideEl = document.getElementById('envelope-override');
    const envelopeId = (overrideEl ? overrideEl.value.trim() : '') || parsed.envelopeId || null;
    const historyErrors = [];
    results.forEach(r => {
      r.errors.forEach(err => {
        const trans = getTranslation(err.field, err.msg, r);
        historyErrors.push({
          entityId: r.entityId,
          recordid: r.recordid,
          county: r.county,
          entityType: r.entityType,
          field: err.field,
          ref: err.ref || '',
          msg: err.msg,
          translation: trans || '',
          publisher: parsed.publisher || r._name || ''
        });
      });
    });
    addToHistory({
      timestamp: new Date().toLocaleString('en-US', {month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}),
      analysedAt: new Date().toISOString(),
      envelopeSubmittedAt: parsed.originalTimestamp ? formatUnixMs(parsed.originalTimestamp) : null,
      originalTimestamp: parsed.originalTimestamp || null,
      envelopeId,
      eventType: parsed.eventType || '',
      publisher: parsed.publisher || '',
      market: parsed.market || 'TX',
      entityCount: results.length,
      errorCount: totalErr,
      errors: historyErrors
    });
  } catch(e) { /* history storage unavailable — validation continues */ }

  // Auto-log to TX Error Log (TX only)
  if ((parsed.market || 'TX') === 'TX') {
    try {
      const overrideElLog = document.getElementById('envelope-override');
      const envelopeIdLog = (overrideElLog ? overrideElLog.value.trim() : '') || parsed.envelopeId || null;
      autoLogRunToErrorLog(parsed, results, envelopeIdLog, parsed.originalTimestamp || null);
    } catch(e) { /* error log unavailable — validation continues */ }
  }

  try {
  const totalEntities = results.length;
  const invalidEntities = results.filter(r => !r.valid).length;
  const totalErrors = results.reduce((sum, r) => sum + (r.errors ? r.errors.length : 0), 0);
  const topFieldMap = {};
  const ownerMap = {};
  results.forEach(r => {
    (r.errors || []).forEach(err => {
      topFieldMap[err.field] = (topFieldMap[err.field] || 0) + 1;
      const translation = getTranslation(err.field, err.msg, r) || '';
      const owner = _extractFixOwner(translation) || 'Unassigned';
      ownerMap[owner] = (ownerMap[owner] || 0) + 1;
    });
  });
  const topField = Object.keys(topFieldMap).sort((a, b) => topFieldMap[b] - topFieldMap[a])[0] || 'None';
  const topOwner = Object.keys(ownerMap).sort((a, b) => ownerMap[b] - ownerMap[a])[0] || 'None';
  const resultsHero = `<div class="results-toolbar">
    <div>
      <div class="results-toolbar-label">Findings filter</div>
      <div class="results-toolbar-copy">Switch between all findings and error-only review without losing the current validation run.</div>
    </div>
    <div class="results-filter-group">
      <button class="results-filter-btn active" id="results-filter-all" onclick="applyResultFilter('all')">All findings</button>
      <button class="results-filter-btn ${totalErrors === 0 ? 'disabled' : ''}" id="results-filter-errors" onclick="applyResultFilter('errors')" ${totalErrors === 0 ? 'disabled' : ''}>Errors only</button>
    </div>
  </div><div class="results-hero-strip">
    <div class="results-kpi"><span class="results-kpi-label">Total issues</span><strong class="results-kpi-value">${totalErrors}</strong></div>
    <div class="results-kpi"><span class="results-kpi-label">Affected entities</span><strong class="results-kpi-value">${invalidEntities}/${totalEntities}</strong></div>
    <div class="results-kpi"><span class="results-kpi-label">Top repeated field</span><strong class="results-kpi-value results-kpi-text">${escHtml(topField)}</strong></div>
    <div class="results-kpi"><span class="results-kpi-label">Top fix owner</span><strong class="results-kpi-value results-kpi-text">${escHtml(topOwner)}</strong></div>
  </div>`;
  ra.innerHTML = resultsHero + results.map(r => {
    const cls = r.valid ? 'valid' : 'invalid';
    let html = `<div class="result-card ${cls}">
      <div class="result-header">
        <span class="${r.valid ? 'status-valid' : 'status-invalid'}">${r.valid ? '✓ VALID' : '✗ INVALID'} · Entity ${r.i + 1}</span>
        <span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 8px;" title="${escHtml(r.entityType)}">${escHtml(r.entityType)}</span>
        ${!r.valid ? `<span class="error-count">${r.errors.length} error${r.errors.length>1?'s':''}</span>` : ''}
      </div>
      <div class="result-meta">
        <div class="meta-row"><span class="meta-key">entityType:</span><span class="meta-val">${escHtml(r.entityType)}</span></div>
        ${r.entityId ? `<div class="meta-row"><span class="meta-key">entityId &nbsp;:</span><span class="meta-val">${escHtml(r.entityId)}</span></div>` : ''}
        <div class="meta-row"><span class="meta-key">recordid &nbsp;:</span><span class="meta-val">${escHtml(r.recordid)}</span></div>
        ${r.market === 'IL'
          ? `<div class="meta-row"><span class="meta-key">instanceid:</span><span class="meta-val">${escHtml(r.instanceid||'—')}</span></div><div class="meta-row"><span class="meta-key">localid &nbsp; :</span><span class="meta-val">${escHtml(r.localid||'—')}</span></div>`
          : `<div class="meta-row"><span class="meta-key">county &nbsp;&nbsp; :</span><span class="meta-val">${escHtml(r.county)}</span></div>`
        }
      </div>`;
    if (r.valid) {
      html += `<div style="padding:6px 12px 10px;color:var(--green);font-size:10.5px">All checks passed.</div>`;
    } else {
      html += `<div class="error-list">`;
      r.errors.forEach(err => {
        const translation = getTranslation(err.field, err.msg, r);
        const libMeta = getLibraryEntryMeta(err.field, err.msg, r);
        const schemaGuide = getSchemaFieldGuide(err.field, r, err.msg);
        const trustStatus = libMeta ? (libMeta.trustStatus || 'trusted') : null;
        const rawEntity = r && r.raw ? r.raw : null;
        const currentValue = rawEntity && Object.prototype.hasOwnProperty.call(rawEntity, err.field)
          ? rawEntity[err.field]
          : extractCurrentValueFromErrorMessage(err.msg);
        const currentValueText = currentValue === undefined ? 'Field not present in payload' : (currentValue === null ? 'null' : String(currentValue));
        const trustChip = trustStatus
          ? `<span class="finding-chip trust-${escHtml(trustStatus)}">${escHtml(trustStatus)}</span>`
          : `<span class="finding-chip">unmatched</span>`;
        const schemaHintParts = [];
        if (schemaGuide && schemaGuide.type) schemaHintParts.push(`Expected ${escHtml(schemaGuide.type)}`);
        if (currentValue !== undefined) schemaHintParts.push(`Received ${escHtml(currentValueText)}`);
        if (schemaGuide && schemaGuide.required !== undefined) schemaHintParts.push(schemaGuide.required ? 'Required field' : 'Optional field');
        const schemaHint = schemaHintParts.length
          ? `<div class="finding-schema-hint"><span class="finding-support-label">Schema hint</span><div class="finding-support-value">${schemaHintParts.join(' · ')}</div></div>`
          : '';
        html += `<div class="error-item" style="cursor:pointer;" title="Click to jump to '${err.field.replace(/'/g,"\\'")}' in the payload" data-field="${escHtml(err.field)}" data-idx="${r.i}" onclick="jumpToField(this.dataset.field, parseInt(this.dataset.idx))">
          <div class="error-field-row">
            <span class="error-field">${escHtml(err.field)}</span>
            <span style="font-size:8px;color:var(--text3);margin-left:auto;padding-left:8px;opacity:0.7;letter-spacing:0.03em;">↖ jump</span>
          </div>
          <div class="finding-columns">
            <div class="finding-panel finding-panel-technical">
              <div class="finding-label">Technical error</div>
              <div class="error-msg">${escHtml(err.msg)}</div>
            </div>
            <div class="finding-panel finding-panel-plain">
              <div class="finding-label">Plain English</div>
              ${translation ? `<div class="error-translation">${escHtml(translation)}</div>` : `<div class="error-translation error-translation-empty">No plain-English translation was matched for this issue yet.</div>`}
              <button class="refine-error-btn" type="button" onclick='openRefineErrorModal(${JSON.stringify(JSON.stringify({ source:"finding", entityType:r.entityType, field:err.field, message:err.msg, translation:translation || "", fixOwner:_extractFixOwner(translation) || "Odyssey", action:"", ref:err.ref || "", matchValue:"", matchType:"contains" }))})'>Refine this error</button>
            </div>
          </div>
        </div>`;
      });
      html += `</div>`;
    }
    html += `</div>`;
    return html;
  }).join('');
  } catch(renderErr) { console.error(renderErr); }
  restoreBtn();
  const copyBtnPost = document.getElementById('copy-results-btn');
  if (copyBtnPost) copyBtnPost.style.display = 'inline';
  _lastValidationResults = results;
  _lastValidationParsed  = parsed;
  updateTabBadges();
}

// ── Export ELT Report (.xlsx) ─────────────────────────────────────────────────
function exportELTReport() {
  // Try to use current session data first (full entity details available)
  if (_lastValidationResults && _lastValidationParsed) {
    confirmExport('CATCH Validation Health Report (.xlsx) — current session').then(function(confirmed) {
      if (!confirmed) return;
      try { _buildAndDownloadELTReport(); }
      catch(e) { console.error('ELT export failed:', e); }
    });
    return;
  }

  // Fallback: use most recent history run
  const runs = loadHistory();
  if (runs.length === 0) {
    alert('⚠ No validation data available.\n\nPlease run a validation first by pasting a payload and clicking "Run Validation".');
    return;
  }

  const run = runs[0];
  const label = 'most recent run — ' + (run.envelopeId ? run.envelopeId.slice(0,16) + '…' : 'no envelope ID') + ' · ' + (run.timestamp || '');
  confirmExport('CATCH Validation Health Report (.xlsx)\nUsing ' + label + '\n\nℹ To export a specific run, use the Health button on its history card.').then(function(confirmed) {
    if (!confirmed) return;
    try { _buildAndDownloadELTReportFromHistory(run); }
    catch(e) { console.error('ELT export from history failed:', e); }
  });
}

function exportELTReportFromRun(idx) {
  const runs = loadHistory();
  const run = runs[idx];
  if (!run) { alert('Run not found.'); return; }
  const label = (run.envelopeId ? run.envelopeId.slice(0,16) + '… ' : '') + '(' + (run.timestamp || '') + ')';
  confirmExport('CATCH Validation Health Report (.xlsx)\nRun: ' + label).then(function(confirmed) {
    if (!confirmed) return;
    try { _buildAndDownloadELTReportFromHistory(run); }
    catch(e) { console.error('ELT export from run failed:', e); }
  });
}

// ── ELT helper: extract fix owner from translation string ────────────────────
function _extractFixOwner(translation) {
  if (!translation) return '';
  var m = translation.match(/[Ff]ix owner[:\s]+([^.]+)/);
  if (m) return m[1].trim();
  if (/D&I ticket|Submit.*ticket/i.test(translation)) return 'D&I';
  return '';
}

// ── ELT helper: merge cells in any sheet ─────────────────────────────────────
function _xlMerge(ws, r1, c1, r2, c2) {
  if (!ws['!merges']) ws['!merges'] = [];
  ws['!merges'].push({s:{r:r1,c:c1},e:{r:r2,c:c2}});
}

function _buildAndDownloadELTReport() {
  var results = _lastValidationResults;
  var parsed  = _lastValidationParsed;
  var now     = new Date();
  var analysedAt = now.toLocaleString('en-US', {month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
  var submittedAt = parsed.originalTimestamp ? formatUnixMs(parsed.originalTimestamp) : (parsed.envelopeSubmittedAt || '—');
  var envelopeId = (document.getElementById('envelope-override') || {}).value || parsed.envelopeId || '—';
  var publisher  = parsed.publisher || '—';
  var market     = parsed.market || 'TX';
  var eventType  = parsed.eventType || '—';

  var totalEntities  = results.length;
  var totalErrors    = results.reduce(function(s,r){ return s + r.errors.length; }, 0);
  var totalValid     = results.filter(function(r){ return r.valid; }).length;
  var totalInvalid   = totalEntities - totalValid;

  // ── Shared cell builder ───────────────────────────────────────────────────
  function mkCell(v, opts) {
    return { v: v, t: typeof v === 'number' ? 'n' : 's',
             s: {
               font:      { name:'Arial', sz:opts.sz||10, bold:!!opts.bold, italic:!!opts.italic, color:{ rgb:opts.color||'000000' } },
               fill:       opts.fill ? { fgColor:{ rgb:opts.fill }, patternType:'solid' } : { patternType:'none' },
               alignment: { horizontal:opts.align||'left', vertical:'center', wrapText:!!opts.wrap },
               border: {
                 top:    { style:'thin', color:{ rgb:'7895A8' } },
                 bottom: { style:'thin', color:{ rgb:'7895A8' } },
                 left:   { style:'thin', color:{ rgb:'7895A8' } },
                 right:  { style:'thin', color:{ rgb:'7895A8' } }
               },
               numFmt: opts.numFmt||''
             }
           };
  }

  // Build errorRows then delegate to shared builder
  var errorRows = [];
  results.forEach(function(r) {
    r.errors.forEach(function(e) {
      var translation = '';
      try { translation = getTranslation(e.field, e.msg, r) || ''; } catch(ex){}
      errorRows.push({ entityNum:r.i+1, entityType:r.entityType, recordid:r.recordid,
                       county:r.county||'—', field:e.field, ref:e.ref||'', msg:e.msg,
                       translation:translation, fixOwner:_extractFixOwner(translation) });
    });
  });

  _buildELTWorkbook({
    envelopeId:    envelopeId, publisher:publisher, market:market, eventType:eventType,
    analysedAt:    analysedAt, submittedAt:submittedAt,
    totalEntities: totalEntities, totalValid:totalValid, totalInvalid:totalInvalid, totalErrors:totalErrors,
    results:       results, errorRows:errorRows, entityList:null, isFromHistory:false,
    mkCell:        mkCell
  }, now);
}

function _buildAndDownloadELTReportFromHistory(run) {
  var now        = new Date();
  var analysedAt = now.toLocaleString('en-US', {month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
  var envelopeId = run.envelopeId || '—';
  var publisher  = run.publisher  || '—';
  var market     = run.market     || 'TX';
  var eventType  = run.eventType  || '—';

  var uniqueEntityIds = {};
  run.errors.forEach(function(e) {
    uniqueEntityIds[(e.entityId||e.recordid||e.entityType)+'||'+e.entityType] = true;
  });
  var totalInvalid  = Object.keys(uniqueEntityIds).length || (run.errorCount > 0 ? 1 : 0);
  var totalEntities = run.entityCount || 0;
  var totalValid    = totalEntities - totalInvalid;

  var entitiesByKey = {};
  run.errors.forEach(function(e) {
    var key = (e.entityId||e.recordid||e.entityType)+'||'+e.entityType;
    if (!entitiesByKey[key]) entitiesByKey[key] = { entityType:e.entityType, recordid:e.recordid||'—', county:e.county||'—', errors:[] };
    entitiesByKey[key].errors.push(e);
  });
  var entityList = Object.keys(entitiesByKey).map(function(k){ return entitiesByKey[k]; });

  var errorRows = run.errors.map(function(e) {
    return { entityNum:'', entityType:e.entityType, recordid:e.recordid||'—',
             county:e.county||'—', field:e.field, ref:e.ref||'', msg:e.msg,
             translation:e.translation||'', fixOwner:_extractFixOwner(e.translation||'') };
  });

  function mkCell(v, opts) {
    return { v: v, t: typeof v === 'number' ? 'n' : 's',
             s: {
               font:      { name:'Arial', sz:opts.sz||10, bold:!!opts.bold, italic:!!opts.italic, color:{ rgb:opts.color||'000000' } },
               fill:       opts.fill ? { fgColor:{ rgb:opts.fill }, patternType:'solid' } : { patternType:'none' },
               alignment: { horizontal:opts.align||'left', vertical:'center', wrapText:!!opts.wrap },
               border: {
                 top:    { style:'thin', color:{ rgb:'7895A8' } },
                 bottom: { style:'thin', color:{ rgb:'7895A8' } },
                 left:   { style:'thin', color:{ rgb:'7895A8' } },
                 right:  { style:'thin', color:{ rgb:'7895A8' } }
               },
               numFmt: opts.numFmt||''
             }
           };
  }

  _buildELTWorkbook({
    envelopeId:    envelopeId, publisher:publisher, market:market, eventType:eventType,
    analysedAt:    analysedAt, submittedAt:run.envelopeSubmittedAt||'—',
    totalEntities: totalEntities, totalValid:totalValid, totalInvalid:totalInvalid, totalErrors:run.errorCount||0,
    results:       null, errorRows:errorRows, entityList:entityList, isFromHistory:true,
    mkCell:        mkCell
  }, now);
}

function _buildELTWorkbook(p, now) {
  var mkCell = p.mkCell;
  var T_HEALTHY = 95;  // default pass-rate threshold for Healthy
  var T_WARN    = 80;  // default pass-rate threshold for Warning

  function C(r,c)    { return XLSX.utils.encode_cell({r:r,c:c}); }
  function hdr(v)    { return mkCell(v, { bold:true, fill:'1F3864', color:'FFFFFF', sz:11, align:'center' }); }
  function subhdr(v) { return mkCell(v, { bold:true, fill:'2E75B6', color:'FFFFFF', sz:10, align:'center' }); }
  function lbl(v)    { return mkCell(v, { bold:true, fill:'D6E4F0', sz:10 }); }
  function val(v,alt,al){ return mkCell(v, { fill:alt?'EBF3FB':null, align:al||'left', sz:10 }); }
  function ok(v)     { return mkCell(v, { fill:'D4EDDA', color:'155724', align:'center', sz:10, bold:true }); }
  function wrn(v)    { return mkCell(v, { fill:'FFF3CD', color:'7D4E00', align:'center', sz:10, bold:true }); }
  function crt(v)    { return mkCell(v, { fill:'FFE0E0', color:'721C24', align:'center', sz:10, bold:true }); }
  function note(v)   { return mkCell(v, { fill:'F6F8FA', color:'555555', sz:9,  italic:true }); }
  function thr(v)    { return mkCell(v, { fill:'FFF9C4', color:'000000', sz:10, bold:true, align:'center' }); }

  function statusCell(passRate) {
    if (passRate >= T_HEALTHY) return ok;
    if (passRate >= T_WARN)    return wrn;
    return crt;
  }

  var passRate  = p.totalEntities > 0 ? (p.totalValid / p.totalEntities * 100) : 100;

  // ═══════════════════════════════════════════════════════════════════════════
  // SHEET 1 – Dashboard
  // ═══════════════════════════════════════════════════════════════════════════
  var ws1 = {};
  var NC  = 7;  // columns 0-7 (8 wide)
  function s1(r,c,cell){ ws1[C(r,c)] = cell; }
  var r = 0;

  // ── A: Title ───────────────────────────────────────────────────────────────
  s1(r,0, mkCell('CATCH · Validation Health Report — TX OCA Community Pipeline',
    { bold:true, fill:'1F3864', color:'FFFFFF', sz:13, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  s1(r,0, mkCell('Tyler Technologies · BIS' + (p.isFromHistory ? '   (exported from history)' : ''),
    { fill:'2E75B6', color:'FFFFFF', sz:10, align:'center', italic:true }));
  _xlMerge(ws1,r,0,r,NC); r += 2;

  // ── B: How to use ─────────────────────────────────────────────────────────
  s1(r,0, mkCell('HOW TO USE THIS REPORT', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  [
    ['📊 Dashboard (this tab)', 'Pipeline health score, configurable thresholds, publisher status snapshot, error summary by entity type, and trend data. Start here.'],
    ['🔍 Error Log',            'Every field-level validation failure with error message, plain-English translation, and fix owner. Share with the submitting publisher for remediation.'],
    ['📋 Entity Detail',        'One row per entity. Shows validation status and which fields failed. Useful for scoping the impact of an issue across an envelope.'],
    ['📚 Error Catalog',        'Deduplicated error patterns found in this run, linked to OCA/BIS references and fix ownership. Reference for project stakeholders and governance.'],
  ].forEach(function(row, i) {
    var alt = i%2===0;
    s1(r,0, mkCell(row[0], { bold:true, fill:alt?'E8F0FE':'F1F3F4', sz:10 }));
    s1(r,1, mkCell(row[1], { fill:alt?'E8F0FE':'F1F3F4', sz:10 }));
    _xlMerge(ws1,r,1,r,NC); r++;
  });
  r++;

  // ── C: Timestamps ─────────────────────────────────────────────────────────
  s1(r,0, mkCell('TIMESTAMPS', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  [
    ['Payload Submitted to AEP', p.submittedAt,  'When the CMS vendor submitted this envelope to the Alliance Exchange Platform'],
    ['Analysed in CATCH',        p.analysedAt,   'When this envelope was validated by CATCH'],
    ['Report Exported',          now.toLocaleString('en-US',{month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}), 'When this Excel report was generated'],
  ].forEach(function(row, i) {
    var alt = i%2===0;
    s1(r,0, lbl(row[0]));
    s1(r,1, mkCell(row[1], { fill:alt?'EBF3FB':null, sz:10, bold:true }));
    _xlMerge(ws1,r,1,r,3);
    s1(r,4, note(row[2]));
    _xlMerge(ws1,r,4,r,NC);
    r++;
  });
  r++;

  // ── D: Run metadata ───────────────────────────────────────────────────────
  s1(r,0, mkCell('RUN METADATA', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  [['Envelope ID',p.envelopeId],['Publisher',p.publisher],['Market',p.market],['Event Type',p.eventType]].forEach(function(row,i){
    s1(r,0, lbl(row[0]));
    s1(r,1, mkCell(row[1], { fill:i%2===0?'EBF3FB':null, sz:10 }));
    _xlMerge(ws1,r,1,r,NC); r++;
  });
  r++;

  // ── E: Configurable health thresholds ─────────────────────────────────────
  s1(r,0, mkCell('HEALTH THRESHOLDS   ✏  Edit the yellow cells to change thresholds',
    { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  s1(r,0, lbl('🟢  Healthy  —  pass rate  ≥'));
  s1(r,1, thr(T_HEALTHY));
  s1(r,2, mkCell('%', { sz:10 }));
  s1(r,3, note('No action needed. Pipeline operating normally.'));
  _xlMerge(ws1,r,3,r,NC); r++;
  s1(r,0, lbl('🟡  Warning  —  pass rate  ≥'));
  s1(r,1, thr(T_WARN));
  s1(r,2, mkCell('%  (and below Healthy)', { sz:10, color:'555555' }));
  _xlMerge(ws1,r,2,r,3);
  s1(r,4, note('Elevated error rate. Review errors and notify publisher.'));
  _xlMerge(ws1,r,4,r,NC); r++;
  s1(r,0, lbl('🔴  Critical  —  pass rate  <'));
  s1(r,1, mkCell('(Warning threshold)', { fill:'FFE4E1', sz:9, italic:true, color:'721C24', align:'center' }));
  s1(r,2, mkCell('%  (below Warning threshold)', { sz:10, color:'555555' }));
  _xlMerge(ws1,r,2,r,3);
  s1(r,4, note('Significant data quality issue. Escalate per pipeline governance.'));
  _xlMerge(ws1,r,4,r,NC); r += 2;

  // ── F: Pipeline health score ──────────────────────────────────────────────
  s1(r,0, mkCell('PIPELINE HEALTH SCORE', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  var sFn = statusCell(passRate);
  var scoreLabel = passRate.toFixed(1) + '%  PASS RATE   '
    + (passRate >= T_HEALTHY ? '🟢  HEALTHY' : passRate >= T_WARN ? '🟡  WARNING' : '🔴  CRITICAL');
  var scoreC = sFn(scoreLabel);
  scoreC.s.font.sz = 14;
  s1(r,0, scoreC);
  _xlMerge(ws1,r,0,r,NC); r++;

  // counts row
  [['Total Entities',p.totalEntities,null],['✓ Valid',p.totalValid,'D4EDDA'],['✗ Invalid',p.totalInvalid,p.totalInvalid>0?'FFE0E0':'D4EDDA'],['Total Errors',p.totalErrors,p.totalErrors>0?'FFE0E0':'D4EDDA']].forEach(function(item,i) {
    s1(r, i*2,   mkCell(item[0], { bold:true, fill:'E9EFF7', sz:10, align:'center' }));
    s1(r, i*2+1, mkCell(item[1], { fill:item[2]||'EBF3FB', align:'center', sz:12, bold:true, color:item[2]==='FFE0E0'?'721C24':item[2]==='D4EDDA'?'155724':'000000' }));
  });
  r += 2;

  // ── G: Publisher snapshot ─────────────────────────────────────────────────
  s1(r,0, mkCell('PUBLISHER SNAPSHOT', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  ['Publisher','Total Entities','Valid','Invalid','Error Rate','Status',''].forEach(function(h,c){ s1(r,c,subhdr(h)); });
  r++;

  var byPub = {};
  if (p.results) {
    p.results.forEach(function(res) {
      var pub = p.publisher;
      if (!byPub[pub]) byPub[pub] = { total:0, valid:0 };
      byPub[pub].total++;
      if (res.valid) byPub[pub].valid++;
    });
  } else {
    byPub[p.publisher] = { total:p.totalEntities, valid:p.totalValid };
  }
  Object.keys(byPub).forEach(function(pub, i) {
    var d = byPub[pub];
    var pr = d.total > 0 ? (d.valid / d.total * 100) : 100;
    var er = (100 - pr).toFixed(1) + '%';
    var sf = statusCell(pr);
    var alt = i%2===0;
    var invalid = d.total - d.valid;
    s1(r,0, val(pub, alt));
    s1(r,1, val(d.total, alt, 'center'));
    s1(r,2, ok(d.valid));
    s1(r,3, invalid > 0 ? mkCell(invalid, { fill:'FFE0E0', color:'721C24', align:'center', sz:10 }) : ok(0));
    s1(r,4, sf === ok ? val(er,alt,'center') : sf(er));
    s1(r,5, sf(sf === ok ? '🟢  Healthy' : sf === wrn ? '🟡  Warning' : '🔴  Critical'));
    s1(r,6, mkCell('', { fill:alt?'EBF3FB':null, sz:10 }));
    r++;
  });
  r++;

  // ── H: Error summary by entity type ───────────────────────────────────────
  s1(r,0, mkCell('ERROR SUMMARY BY ENTITY TYPE', { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;
  ['Entity Type','Total','Invalid','Errors','Pass Rate','Top Error Fields',''].forEach(function(h,c){ s1(r,c,subhdr(h)); });
  r++;

  var byType = {};
  if (p.results) {
    p.results.forEach(function(res) {
      if (!byType[res.entityType]) byType[res.entityType] = { total:0, invalid:0, errors:0, fields:{} };
      byType[res.entityType].total++;
      if (!res.valid) byType[res.entityType].invalid++;
      byType[res.entityType].errors += res.errors.length;
      res.errors.forEach(function(e){ byType[res.entityType].fields[e.field] = (byType[res.entityType].fields[e.field]||0)+1; });
    });
  } else {
    p.errorRows.forEach(function(e) {
      if (!byType[e.entityType]) byType[e.entityType] = { total:0, invalid:0, errors:0, fields:{} };
      byType[e.entityType].errors++;
      byType[e.entityType].fields[e.field] = (byType[e.entityType].fields[e.field]||0)+1;
    });
    if (p.entityList) {
      p.entityList.forEach(function(ent) {
        if (!byType[ent.entityType]) byType[ent.entityType] = { total:0, invalid:0, errors:0, fields:{} };
        byType[ent.entityType].total++;
        byType[ent.entityType].invalid++;
      });
    }
  }
  Object.keys(byType).sort().forEach(function(et, i) {
    var d = byType[et];
    var pr = d.total > 0 ? (d.valid / d.total * 100) : (d.errors > 0 ? 0 : 100);
    var prLabel = d.total > 0 ? (((d.total - d.invalid) / d.total) * 100).toFixed(1) + '%' : '—';
    var sf = d.total > 0 ? statusCell((d.total - d.invalid) / d.total * 100) : val;
    var topFields = Object.keys(d.fields).sort(function(a,b){ return d.fields[b]-d.fields[a]; }).slice(0,3).join(', ');
    var alt = i%2===0;
    s1(r,0, val(et,    alt));
    s1(r,1, val(d.total||'—', alt, 'center'));
    s1(r,2, d.invalid > 0 ? mkCell(d.invalid, { fill:'FFE0E0', color:'721C24', align:'center', sz:10 }) : ok(0));
    s1(r,3, d.errors  > 0 ? mkCell(d.errors,  { fill:'FFE0E0', color:'721C24', align:'center', sz:10 }) : ok(0));
    s1(r,4, d.total > 0 ? sf(prLabel) : val('—', alt, 'center'));
    s1(r,5, val(topFields||'—', alt));
    s1(r,6, mkCell('', { fill:alt?'EBF3FB':null }));
    r++;
  });
  r++;

  // ── I: Trend (last 10 runs same publisher + market) ────────────────────────
  var histRuns = [];
  try { histRuns = loadHistory ? loadHistory() : []; } catch(e) {}
  var trendRuns = histRuns.filter(function(run) {
    return (run.publisher||'') === p.publisher && (run.market||'TX') === p.market;
  }).slice(0, 10);

  s1(r,0, mkCell('TREND — LAST ' + trendRuns.length + ' RUNS   (' + p.publisher + '  ·  ' + p.market + ')',
    { bold:true, fill:'1F3864', color:'FFFFFF', sz:10, align:'center' }));
  _xlMerge(ws1,r,0,r,NC); r++;

  if (trendRuns.length === 0) {
    s1(r,0, note('No trend data available. Run history is stored in this browser — export from the same browser used for validation to include trend data.'));
    _xlMerge(ws1,r,0,r,NC); r++;
  } else {
    ['Analysed (CATCH)','Submitted to AEP','Envelope ID','Entities','Errors','Pass Rate','Status'].forEach(function(h,c){ s1(r,c,subhdr(h)); });
    r++;
    trendRuns.forEach(function(run, i) {
      var total  = run.entityCount || 0;
      var errCt  = run.errorCount  || 0;
      var uEnt   = {};
      (run.errors||[]).forEach(function(e){ uEnt[(e.entityId||e.recordid||e.entityType)+'||'+e.entityType]=1; });
      var invCt  = Object.keys(uEnt).length || (errCt > 0 ? 1 : 0);
      var validCt = total - invCt;
      var pr     = total > 0 ? (validCt / total * 100) : 100;
      var sf     = statusCell(pr);
      var alt    = i%2===0;
      var envShort = (run.envelopeId||'—').length > 18 ? (run.envelopeId||'—').slice(0,18)+'…' : (run.envelopeId||'—');
      s1(r,0, val(run.timestamp||'—',        alt));
      s1(r,1, val(run.envelopeSubmittedAt||'—', alt));
      s1(r,2, val(envShort,                  alt));
      s1(r,3, val(total,                     alt, 'center'));
      s1(r,4, errCt > 0 ? mkCell(errCt,{ fill:'FFE0E0', color:'721C24', align:'center', sz:10 }) : ok(0));
      s1(r,5, sf(pr.toFixed(1)+'%'));
      s1(r,6, sf(pr >= T_HEALTHY ? '🟢  Healthy' : pr >= T_WARN ? '🟡  Warning' : '🔴  Critical'));
      r++;
    });
  }

  ws1['!ref']  = XLSX.utils.encode_range({r:0,c:0},{r:r,c:NC});
  ws1['!cols'] = [{wch:28},{wch:18},{wch:38},{wch:14},{wch:14},{wch:16},{wch:20},{wch:14}];
  ws1['!rows'] = [{hpt:28},{hpt:16}];

  // ═══════════════════════════════════════════════════════════════════════════
  // SHEET 2 – Error Log (with Fix Owner)
  // ═══════════════════════════════════════════════════════════════════════════
  var ws2 = {};
  function s2(row,c,cell){ ws2[XLSX.utils.encode_cell({r:row,c:c})] = cell; }

  s2(0,0, hdr('Error Log — Field-Level Validation Failures'));
  var errHdrs = p.isFromHistory
    ? ['Entity Type','Record ID','County','Field','OCA Ref','Fix Owner','Error Message','Translation']
    : ['Entity #','Entity Type','Record ID','County','Field','OCA Ref','Fix Owner','Error Message','Translation'];
  errHdrs.forEach(function(h,c){ s2(1,c,subhdr(h)); });

  if (p.errorRows.length === 0) {
    s2(2,0, mkCell('✓ No errors — all entities passed validation', { fill:'D4EDDA', bold:true, sz:10, color:'155724' }));
    _xlMerge(ws2,2,0,2,errHdrs.length-1);
  } else {
    p.errorRows.forEach(function(e, i) {
      var alt = i%2===0;
      var cols = p.isFromHistory
        ? [e.entityType, e.recordid, e.county, e.field, e.ref, e.fixOwner, e.msg, e.translation]
        : [e.entityNum,  e.entityType, e.recordid, e.county, e.field, e.ref, e.fixOwner, e.msg, e.translation];
      var msgIdx = cols.length - 2;
      cols.forEach(function(v, c) {
        s2(2+i, c, mkCell(v, { fill: c===msgIdx?'FFF8E1': alt?'EBF3FB':null, sz:10, wrap:c>=msgIdx }));
      });
    });
  }

  var ws2LastRow = Math.max(2, 1 + p.errorRows.length);
  var ws2Cols    = errHdrs.length - 1;
  ws2['!ref']        = XLSX.utils.encode_range({r:0,c:0},{r:ws2LastRow,c:ws2Cols});
  ws2['!merges']     = [{s:{r:0,c:0},e:{r:0,c:ws2Cols}}];
  ws2['!cols']       = p.isFromHistory
    ? [{wch:36},{wch:16},{wch:14},{wch:22},{wch:10},{wch:14},{wch:46},{wch:46}]
    : [{wch:8},{wch:36},{wch:16},{wch:14},{wch:22},{wch:10},{wch:14},{wch:46},{wch:46}];
  ws2['!rows']       = [{hpt:26},{hpt:18}];
  ws2['!freeze']     = {xSplit:0, ySplit:2};
  ws2['!autofilter'] = {ref:'A2:'+XLSX.utils.encode_col(ws2Cols)+'2'};

  // ═══════════════════════════════════════════════════════════════════════════
  // SHEET 3 – Entity Detail
  // ═══════════════════════════════════════════════════════════════════════════
  var ws3 = {};
  function s3(row,c,cell){ ws3[XLSX.utils.encode_cell({r:row,c:c})] = cell; }

  var entitySource = p.results || p.entityList || [];
  s3(0,0, hdr('Entity Detail — ' + (p.isFromHistory ? 'Entities with Errors (from history)' : 'All Validated Records')));
  ['Entity #','Entity Type','Record ID','County / Instance','Publisher','Status','Errors','Error Fields'].forEach(function(h,c){ s3(1,c,subhdr(h)); });

  entitySource.forEach(function(ent, i) {
    var row = 2 + i;
    var alt = i%2===0;
    var isValid, errCount, locationVal, errorFields;
    if (p.isFromHistory) {
      isValid = false; errCount = ent.errors.length;
      locationVal  = ent.county || '—';
      errorFields  = ent.errors.map(function(e){ return e.field; }).join(', ');
    } else {
      isValid = ent.valid; errCount = ent.errors.length;
      locationVal  = ent.market === 'IL' ? 'inst: ' + ent.instanceid + ' / local: ' + ent.localid : ent.county;
      errorFields  = ent.errors.map(function(e){ return e.field; }).join(', ') || '—';
    }
    s3(row,0, val(i+1, alt, 'center'));
    s3(row,1, val(p.isFromHistory ? ent.entityType : ent.entityType, alt));
    s3(row,2, val(p.isFromHistory ? ent.recordid   : ent.recordid,   alt));
    s3(row,3, val(locationVal, alt));
    s3(row,4, val(p.publisher, alt));
    s3(row,5, isValid ? ok('✓  VALID') : crt('✗  INVALID'));
    s3(row,6, errCount > 0 ? mkCell(errCount,{ fill:'FFE0E0', color:'721C24', align:'center', sz:10, bold:true }) : ok(0));
    s3(row,7, mkCell(errorFields, { fill: isValid?'D4EDDA':'FFE0E0', sz:10, wrap:true }));
  });

  var ws3LastRow = 1 + entitySource.length;
  ws3['!ref']        = XLSX.utils.encode_range({r:0,c:0},{r:ws3LastRow,c:7});
  ws3['!merges']     = [{s:{r:0,c:0},e:{r:0,c:7}}];
  ws3['!cols']       = [{wch:7},{wch:36},{wch:16},{wch:22},{wch:20},{wch:12},{wch:8},{wch:40}];
  ws3['!rows']       = [{hpt:26},{hpt:18}];
  ws3['!freeze']     = {xSplit:0, ySplit:2};
  ws3['!autofilter'] = {ref:'A2:H2'};

  // ═══════════════════════════════════════════════════════════════════════════
  // SHEET 4 – Error Catalog (deduplicated patterns in this run)
  // ═══════════════════════════════════════════════════════════════════════════
  var ws4 = {};
  function s4(row,c,cell){ ws4[XLSX.utils.encode_cell({r:row,c:c})] = cell; }

  s4(0,0, hdr('Error Catalog — Distinct Error Patterns in This Run'));
  ['OCA / BIS Ref','Field','Entity Type','Fix Owner','Occurrences','Error Pattern','Translation / Action'].forEach(function(h,c){ s4(1,c,subhdr(h)); });

  var lib = [];
  try { lib = loadLibrary ? loadLibrary() : []; } catch(e) {}

  var catMap = {};
  p.errorRows.forEach(function(e) {
    var key = e.field + '|||' + e.entityType;
    if (!catMap[key]) {
      var libMatch = null;
      for (var li = 0; li < lib.length; li++) {
        var le = lib[li];
        if (le.field && e.field && le.field.toLowerCase() === e.field.toLowerCase()) {
          if (!le.matchValue || (e.msg && e.msg.toLowerCase().indexOf((le.matchValue||'').toLowerCase()) !== -1)) {
            libMatch = le; break;
          }
        }
      }
      catMap[key] = {
        ref:        e.ref || (libMatch ? libMatch.ref : '') || '—',
        field:      e.field,
        entityType: e.entityType,
        fixOwner:   e.fixOwner || (libMatch ? libMatch.fixOwner : '') || '—',
        count:      0,
        msg:        e.msg,
        translation: e.translation || (libMatch ? libMatch.translation : '') || '',
        action:      libMatch ? (libMatch.action||'') : '',
      };
    }
    catMap[key].count++;
  });

  var catRows = Object.keys(catMap).map(function(k){ return catMap[k]; }).sort(function(a,b){ return b.count - a.count; });
  if (catRows.length === 0) {
    s4(2,0, mkCell('✓  No errors in this run — nothing to catalog', { fill:'D4EDDA', bold:true, sz:10, color:'155724' }));
    _xlMerge(ws4,2,0,2,6);
  } else {
    catRows.forEach(function(cat, i) {
      var alt = i%2===0;
      var ownerFill = { 'Odyssey':'FFF3CD','Publisher':'FFF3CD','D&I':'EDE7F6','BIS TPM':'E3F2FD','OCA':'E8F5E9' }[cat.fixOwner];
      var actionStr = cat.translation + (cat.action ? '\n→ ' + cat.action : '');
      s4(2+i, 0, val(cat.ref,        alt, 'center'));
      s4(2+i, 1, val(cat.field,      alt));
      s4(2+i, 2, val(cat.entityType, alt));
      s4(2+i, 3, mkCell(cat.fixOwner, { fill:ownerFill||'EBF3FB', sz:10, align:'center' }));
      s4(2+i, 4, mkCell(cat.count,   { fill:cat.count>5?'FFE0E0':alt?'EBF3FB':null, align:'center', sz:10, bold:cat.count>5, color:cat.count>5?'721C24':'000000' }));
      s4(2+i, 5, mkCell(cat.msg,     { fill:'FFF8E1', sz:10, wrap:true }));
      s4(2+i, 6, mkCell(actionStr,   { fill:alt?'EBF3FB':null, sz:10, wrap:true }));
    });
  }

  var ws4LastRow = Math.max(2, 1 + catRows.length);
  ws4['!ref']        = XLSX.utils.encode_range({r:0,c:0},{r:ws4LastRow,c:6});
  ws4['!merges']     = [{s:{r:0,c:0},e:{r:0,c:6}}];
  ws4['!cols']       = [{wch:14},{wch:26},{wch:36},{wch:14},{wch:12},{wch:46},{wch:50}];
  ws4['!rows']       = [{hpt:26},{hpt:18}];
  ws4['!freeze']     = {xSplit:0, ySplit:2};
  ws4['!autofilter'] = {ref:'A2:G2'};

  // ── Build & download workbook ───────────────────────────────────────────────
  var wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws1, '📊 Dashboard');
  XLSX.utils.book_append_sheet(wb, ws2, '🔍 Error Log');
  XLSX.utils.book_append_sheet(wb, ws3, '📋 Entity Detail');
  XLSX.utils.book_append_sheet(wb, ws4, '📚 Error Catalog');

  var safeEnv = (p.envelopeId !== '—' ? p.envelopeId.replace(/[^a-zA-Z0-9_-]/g,'_').slice(0,20) + '_' : '');
  XLSX.writeFile(wb, 'CATCH_ELT_Report_' + safeEnv + now.toISOString().slice(0,10) + '.xlsx');
}

// ── Result filter (errors only / show all) ─────────────────────────────────
var _activeResultFilter = 'all';
var _lastValidationResults = null;
var _lastValidationParsed  = null;
var _lastBatchRuns = [];

function applyResultFilter(type) {
  _activeResultFilter = type;
  var ra = document.getElementById('results-area');
  if (!ra) return;

  var cards = ra.querySelectorAll('.result-card');
  cards.forEach(function(card) {
    if (type === 'errors') {
      card.style.display = card.classList.contains('invalid') ? '' : 'none';
    } else {
      card.style.display = '';
    }
  });

  // Toggle active state on error button
  var errBtn = document.getElementById('sb-err-btn');
  if (errBtn) {
    if (type === 'errors') errBtn.classList.add('active-filter');
    else errBtn.classList.remove('active-filter');
  }

  // Show/hide the clear-filter button
  var clrBtn = document.getElementById('sb-clear-btn');
  if (clrBtn) {
    if (type === 'errors') clrBtn.classList.add('visible');
    else clrBtn.classList.remove('visible');
  }

  var heroRunMeta = document.getElementById('hero-run-meta');
  if (heroRunMeta) {
    heroRunMeta.textContent = type === 'errors' ? 'Filter: errors only' : 'Filter: all findings';
  }

  var allBtn = document.getElementById('results-filter-all');
  var errBtnModern = document.getElementById('results-filter-errors');
  if (allBtn) {
    if (type === 'all') allBtn.classList.add('active');
    else allBtn.classList.remove('active');
  }
  if (errBtnModern) {
    if (type === 'errors') errBtnModern.classList.add('active');
    else errBtnModern.classList.remove('active');
  }
}

// ── Format + Copy ────────────────────────────────────────────────────────────
function formatInput() {
  const ta = document.getElementById('input-area');
  try {
    const parsed = JSON.parse(ta.value.trim());
    ta.value = JSON.stringify(parsed, null, 2);
  } catch(e) {
    ta.style.borderColor = 'var(--red)';
    setTimeout(function() { ta.style.borderColor = ''; }, 1000);
  }
}

function copyResults() {
  const area = document.getElementById('results-area');
  if (!area) return;
  // Build plain-text version from visible result cards
  const cards = area.querySelectorAll('.result-card');
  if (cards.length === 0) return;
  let text = '';
  cards.forEach(function(card) {
    const status = card.querySelector('.status-valid, .status-invalid');
    const meta = card.querySelectorAll('.meta-row');
    const errors = card.querySelectorAll('.error-item');
    if (status) text += status.textContent.trim() + '\n';
    meta.forEach(function(m) { text += '  ' + m.textContent.trim() + '\n'; });
    if (errors.length === 0) {
      text += '  All checks passed.\n';
    } else {
      errors.forEach(function(e) {
        const field = e.querySelector('.error-field');
        const msg = e.querySelector('.error-msg');
        const trans = e.querySelector('.error-translation');
        if (field) text += '  [' + field.textContent.trim() + '] ';
        if (msg) text += msg.textContent.trim() + '\n';
        if (trans) text += '    → ' + trans.textContent.replace('↳ ','').trim() + '\n';
      });
    }
    text += '\n';
  });
  navigator.clipboard.writeText(text).then(function() {
    const btn = document.getElementById('copy-results-btn');
    if (btn) { btn.textContent = '✓ Copied'; setTimeout(function() { btn.textContent = '⎘ Copy Results'; }, 1500); }
  }).catch(function() {
    // Fallback for non-secure contexts
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    const btn = document.getElementById('copy-results-btn');
    if (btn) { btn.textContent = '✓ Copied'; setTimeout(function() { btn.textContent = '⎘ Copy Results'; }, 1500); }
  });
}

function onStateChange() {
  const sel = document.getElementById('state-select');
  const val = sel.value;
  const label = sel.options[sel.selectedIndex].dataset.label || val;
  const titleEl = document.getElementById('main-title');
  const aboutTitleEl = document.getElementById('about-title');
  if (titleEl) titleEl.textContent = 'CATCH · ' + label;
  if (aboutTitleEl) aboutTitleEl.textContent = 'CATCH · ' + label;
  document.title = 'CATCH · ' + label;
  _currentMarket = val;
  // Clear workspace on market switch
  const inputArea = document.getElementById('input-area');
  const resultsArea = document.getElementById('results-area');
  const summaryBar = document.getElementById('summary-bar');
  const resultCount = document.getElementById('result-count');
  if (inputArea) inputArea.value = '';
  if (resultsArea) resultsArea.innerHTML = '<div class="results-empty">Switched to ' + label + '. Paste a payload to validate.</div>';
  if (summaryBar) summaryBar.style.display = 'none';
  if (resultCount) resultCount.textContent = '';
  // Update schema reference panel
  updateSchemaReferencePanel();
}

function updateSchemaReferencePanel() {
  const market = _currentMarket;
  const panel = document.getElementById('panel-reference');
  if (!panel) return;
  // Show/hide market-specific sections
  panel.querySelectorAll('[data-market]').forEach(function(el) {
    el.style.display = (el.dataset.market === market || el.dataset.market === 'all') ? '' : 'none';
  });
}

function clearInput() {
  document.getElementById('input-area').value = '';
  document.getElementById('results-area').innerHTML = '<div class="results-empty">Paste a payload and click Run Validation.</div>';
  document.getElementById('summary-bar').style.display = 'none';
  document.getElementById('result-count').textContent = '';
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  // All panels including hidden ones (errors panel kept for JS compatibility)
  ['validate','batch','reference','errors','history','assoc','about','release'].forEach(p => {
    const el = document.getElementById('panel-' + p);
    if (!el) return;
    const isActive = p === tab;
    el.hidden = !isActive;
    if (isActive) { el.style.display = 'flex'; el.classList.add('active'); }
    else { el.style.display = 'none'; el.classList.remove('active'); }
  });
  if (tab === 'history') renderHistory();
  if (tab === 'assoc') renderCatalog();
  try { window.scrollTo({ top: 0, behavior: 'auto' }); } catch(e) {}
}

function clearBatchInput() {
  const input = document.getElementById('batch-input-area');
  const output = document.getElementById('batch-results-area');
  const count = document.getElementById('batch-result-count');
  if (input) input.value = '';
  if (output) output.innerHTML = '<div class="results-empty">Add two or more payloads to generate a batch summary, run cards, and quick links back into Single.</div>';
  if (count) count.textContent = '';
  _lastBatchRuns = [];
}

function loadBatchFiles(event) {
  const files = Array.prototype.slice.call((event && event.target && event.target.files) || []);
  if (!files.length) return;
  Promise.all(files.map(function(file) {
    return new Promise(function(resolve, reject) {
      const reader = new FileReader();
      reader.onload = function() { resolve(String(reader.result || '')); };
      reader.onerror = reject;
      reader.readAsText(file);
    });
  })).then(function(contents) {
    const input = document.getElementById('batch-input-area');
    if (!input) return;
    const merged = contents.map(function(part) { return String(part || '').trim(); }).filter(Boolean).join('\n\n');
    input.value = [input.value.trim(), merged].filter(Boolean).join('\n\n');
    if (event && event.target) event.target.value = '';
  }).catch(function(err) {
    console.error(err);
    alert('One or more files could not be read. Please try again.');
  });
}

function openBatchRunInValidate(index) {
  const run = _lastBatchRuns[index];
  if (!run) return;
  if (run.error) {
    openReaderContent('Batch payload detail', '<div class="schema-review-shell"><div class="schema-review-copy">This payload could not be parsed as valid JSON.</div><div class="rule-card"><div class="rule-row"><span class="rule-label" style="min-width:180px">Parse issue</span><span class="rule-note">' + escHtml(run.error) + '</span></div></div></div>');
    return;
  }
  function buildBatchPayloadSnippet(sourceText, entityData, fieldName, technicalMessage) {
    var entitySource = entityData && typeof entityData === 'object' ? JSON.stringify(entityData, null, 2) : '';
    var fallbackSource = String(sourceText || '');
    var raw = entitySource || fallbackSource;
    if (!raw) return '';
    var extractedValue = extractCurrentValueFromErrorMessage(technicalMessage);
    var searchTargets = ['"' + String(fieldName || '') + '"'];
    if (extractedValue !== undefined && extractedValue !== null && extractedValue !== '') {
      searchTargets.push('"' + String(extractedValue) + '"');
      searchTargets.push(': ' + String(extractedValue));
    }
    var targetIndex = -1;
    for (var i = 0; i < searchTargets.length; i++) {
      targetIndex = raw.indexOf(searchTargets[i]);
      if (targetIndex !== -1) break;
    }
    if (targetIndex === -1 && entitySource && fallbackSource) {
      raw = fallbackSource;
      for (var j = 0; j < searchTargets.length; j++) {
        targetIndex = raw.indexOf(searchTargets[j]);
        if (targetIndex !== -1) break;
      }
    }
    if (targetIndex === -1) return entitySource || '';
    var lineStart = raw.lastIndexOf('\n', targetIndex);
    lineStart = lineStart === -1 ? 0 : lineStart;
    var snippetStart = Math.max(0, lineStart - 120);
    var snippetEnd = raw.indexOf('\n', targetIndex);
    var lines = 0;
    while (snippetEnd !== -1 && lines < 5) {
      snippetEnd = raw.indexOf('\n', snippetEnd + 1);
      lines += 1;
    }
    if (snippetEnd === -1) snippetEnd = Math.min(raw.length, targetIndex + 320);
    var snippet = raw.slice(snippetStart, snippetEnd).trim();
    return snippet.length > 420 ? snippet.slice(0, 420).trim() + '\n...' : snippet;
  }
  var invalidResults = run.results.filter(function(result) { return !result.valid && Array.isArray(result.errors) && result.errors.length; });
  var quickJumpItems = [];
  invalidResults.forEach(function(result, resultIndex) {
    result.errors.forEach(function(err, errIndex) {
      quickJumpItems.push({
        id: 'batch-detail-' + index + '-' + resultIndex + '-' + errIndex,
        entityType: result.entityType,
        field: err.field,
        error: err.msg
      });
    });
  });
  var quickJumpHtml = quickJumpItems.length
    ? '<div class="batch-detail-jump-shell">' +
        '<div class="batch-detail-jump-copy">Jump directly to a surfaced issue.</div>' +
        '<div class="batch-detail-jump-grid">' +
          quickJumpItems.map(function(item) {
            return '<button class="batch-detail-jump-chip" type="button" onclick=\'(function(){var el=document.getElementById("' + item.id + '");if(el){el.scrollIntoView({behavior:"smooth",block:"start"});}})()\'>' + escHtml(item.field) + '</button>';
          }).join('') +
        '</div>' +
      '</div>'
    : '';

  var findingsHtml = invalidResults.map(function(result, resultIndex) {
    var summaryMeta = '<div class="meta-row"><span class="meta-key">entityType:</span><span class="meta-val">' + escHtml(result.entityType) + '</span></div>' +
      (result.entityId ? '<div class="meta-row"><span class="meta-key">entityId:</span><span class="meta-val">' + escHtml(result.entityId) + '</span></div>' : '') +
      '<div class="meta-row"><span class="meta-key">recordid:</span><span class="meta-val">' + escHtml(result.recordid) + '</span></div>' +
      '<div class="meta-row"><span class="meta-key">' + (result.market === 'IL' ? 'instance:' : 'county:') + '</span><span class="meta-val">' + escHtml(result.market === 'IL' ? (result.instanceid || '-') : (result.county || '-')) + '</span></div>';

    if (result.valid) {
      return '<div class="result-card valid" style="margin-bottom:14px;">' +
        '<div class="result-header"><span class="status-valid">✓ VALID · Entity ' + (resultIndex + 1) + '</span><span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 8px;" title="' + escHtml(result.entityType) + '">' + escHtml(result.entityType) + '</span></div>' +
        '<div class="result-meta">' + summaryMeta + '</div>' +
        '<div style="padding:6px 12px 12px;color:var(--green);font-size:10.5px">All checks passed.</div>' +
      '</div>';
    }

    var issueHtml = result.errors.map(function(err, errIndex) {
      var translation = getTranslation(err.field, err.msg, result) || 'No plain-English translation was matched for this issue yet.';
      var issueId = 'batch-detail-' + index + '-' + resultIndex + '-' + errIndex;
      var payloadSnippet = buildBatchPayloadSnippet(run.sourceText, result.raw, err.field, err.msg);
      return '<div class="error-item" style="padding-top:10px;">' +
        '<div id="' + issueId + '" class="error-field-row batch-detail-field-row"><span class="error-field">' + escHtml(err.field) + '</span></div>' +
        '<div class="finding-columns">' +
          '<div class="finding-panel finding-panel-technical">' +
            '<div class="finding-label">Technical error</div>' +
            '<div class="error-msg">' + escHtml(err.msg) + '</div>' +
          '</div>' +
          '<div class="finding-panel finding-panel-plain">' +
            '<div class="finding-label">Plain English</div>' +
            '<div class="error-translation">' + escHtml(translation) + '</div>' +
          '</div>' +
        '</div>' +
        (payloadSnippet ? '<div class="batch-detail-snippet"><div class="finding-label">Payload snippet</div><pre class="batch-detail-snippet-code">' + escHtml(payloadSnippet) + '</pre></div>' : '') +
      '</div>';
    }).join('');

    return '<div class="result-card invalid" style="margin-bottom:14px;">' +
      '<div class="result-header"><span class="status-invalid">✕ INVALID · Entity ' + (resultIndex + 1) + '</span><span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 8px;" title="' + escHtml(result.entityType) + '">' + escHtml(result.entityType) + '</span><span class="error-count">' + result.errors.length + ' error' + (result.errors.length > 1 ? 's' : '') + '</span></div>' +
      '<div class="result-meta">' + summaryMeta + '</div>' +
      '<div class="error-list">' + issueHtml + '</div>' +
    '</div>';
  }).join('');

  var html = '<div class="schema-review-shell batch-detail-shell">' +
    '<div class="schema-review-copy">Review technical findings and plain-English translations without leaving Batch. The queue stays intact while you inspect this payload in more detail.</div>' +
    '<div class="about-stat-grid" style="margin-bottom:18px;">' +
      '<div class="about-stat-card"><div class="about-stat-label">Envelope</div><div class="about-stat-value" style="font-size:16px;">' + escHtml((run.historyRun && run.historyRun.envelopeId) || 'Custom payload') + '</div></div>' +
      '<div class="about-stat-card"><div class="about-stat-label">Event type</div><div class="about-stat-value" style="font-size:16px;">' + escHtml(run.parsed.eventType || 'Single entity / custom payload') + '</div></div>' +
      '<div class="about-stat-card"><div class="about-stat-label">Entities</div><div class="about-stat-value" style="font-size:16px;">' + run.totalEntities + '</div></div>' +
      '<div class="about-stat-card"><div class="about-stat-label">Errors</div><div class="about-stat-value" style="font-size:16px;">' + run.totalErr + '</div></div>' +
    '</div>' +
    quickJumpHtml +
    '<details class="rule-card" style="margin-bottom:16px;"><summary style="cursor:pointer;list-style:none;font-family:var(--sans);font-size:12px;font-weight:700;color:var(--text);">View full raw payload</summary><pre class="trend-detail-code" style="margin-top:14px;">' + escHtml(run.sourceText || '') + '</pre></details>' +
    findingsHtml +
  '</div>';
  openReaderContent('Batch payload detail', html);
}

function renderBatchResults(batchRuns) {
  const host = document.getElementById('batch-results-area');
  const count = document.getElementById('batch-result-count');
  if (!host || !count) return;

  _lastBatchRuns = batchRuns.slice();
  if (!batchRuns.length) {
    count.textContent = '';
    host.innerHTML = '<div class="results-empty">Add two or more payloads to generate a batch summary, run cards, and quick links back into Single.</div>';
    return;
  }

  const successfulRuns = batchRuns.filter(function(run) { return !run.error; });
  const parseFailures = batchRuns.length - successfulRuns.length;
  const totalErrors = successfulRuns.reduce(function(sum, run) { return sum + run.totalErr; }, 0);
  const passedRuns = successfulRuns.filter(function(run) { return run.totalErr === 0; }).length;
  const publisherMap = {};
  successfulRuns.forEach(function(run) {
    const publisher = run.parsed.publisher || '(unknown)';
    publisherMap[publisher] = (publisherMap[publisher] || 0) + run.totalErr;
  });
  const topPublisher = Object.keys(publisherMap).sort(function(a, b) { return publisherMap[b] - publisherMap[a]; })[0] || 'None';
  const batchIdRun = batchRuns.find(function(run) {
    return run && (run.batchSessionId || (run.historyRun && run.historyRun.batchSessionId));
  });
  const batchSessionLabel = batchIdRun
    ? (batchIdRun.batchSessionId || (batchIdRun.historyRun && batchIdRun.historyRun.batchSessionId) || 'Not assigned')
    : 'Not assigned';

  count.textContent = batchRuns.length + ' payloads · ' + batchSessionLabel;

  let summaryHtml = '<div class="batch-summary-grid">' +
    '<div class="batch-summary-card"><span class="batch-summary-label">Payloads processed</span><div class="batch-summary-value">' + batchRuns.length + '</div><div class="batch-summary-note">' + passedRuns + ' passed cleanly' + (parseFailures ? ' · ' + parseFailures + ' parse issue' + (parseFailures > 1 ? 's' : '') : '') + '</div></div>' +
    '<div class="batch-summary-card"><span class="batch-summary-label">Total errors</span><div class="batch-summary-value">' + totalErrors + '</div><div class="batch-summary-note">Rolled up across all validated payloads in this batch.</div></div>' +
    '<div class="batch-summary-card"><span class="batch-summary-label">Most pressured publisher</span><div class="batch-summary-value" style="font-size:20px;line-height:1.1;">' + escHtml(topPublisher) + '</div><div class="batch-summary-note">Publisher with the highest current batch issue volume.</div></div>' +
    '</div>';

  count.textContent = batchRuns.length + ' payloads · ' + batchSessionLabel;
  var batchSummaryIdCard = '<div class="batch-summary-card"><span class="batch-summary-label">Batch ID</span><div class="batch-summary-value" style="font-size:20px;line-height:1.1;">' + escHtml(batchSessionLabel) + '</div><div class="batch-summary-note">Use this ID to connect these payloads with related History entries.</div></div>';
  summaryHtml = summaryHtml.replace('<div class="batch-summary-grid">', '<div class="batch-summary-grid">' + batchSummaryIdCard);
  count.textContent = batchRuns.length + ' payloads · ' + batchSessionLabel;

  const runsHtml = '<div class="batch-runs-list">' + batchRuns.map(function(run, index) {
    if (run.error) {
      return '<div class="batch-run-card">' +
        '<div class="batch-run-top">' +
          '<div>' +
            '<div class="batch-run-header"><span class="batch-run-index">Payload ' + (index + 1) + '</span><span class="batch-run-badge invalid">Parse issue</span></div>' +
            '<div class="batch-run-envelope">This payload could not be parsed as valid JSON.</div>' +
            '<div class="batch-inline-note">' + escHtml(run.error) + '</div>' +
          '</div>' +
          '<div class="batch-run-actions"><button class="batch-open-btn" type="button" onclick="openBatchRunInValidate(' + index + ')">Review findings</button></div>' +
        '</div>' +
      '</div>';
    }

    const firstIssue = run.results.reduce(function(found, row) {
      if (found || row.valid || !row.errors.length) return found;
      return row.errors[0];
    }, null);
    const statusClass = run.totalErr === 0 ? 'valid' : 'invalid';
    const statusLabel = run.totalErr === 0 ? 'All valid' : run.totalErr + ' error' + (run.totalErr > 1 ? 's' : '');
    return '<div class="batch-run-card">' +
      '<div class="batch-run-top">' +
        '<div style="flex:1 1 520px;min-width:0;">' +
          '<div class="batch-run-header">' +
            '<span class="batch-run-index">Payload ' + (index + 1) + '</span>' +
            '<span class="batch-run-envelope">' + escHtml((run.historyRun && run.historyRun.envelopeId) || run.parsed.eventType || 'Custom payload') + '</span>' +
            '<span class="batch-run-badge ' + statusClass + '">' + escHtml(statusLabel) + '</span>' +
          '</div>' +
          '<div class="batch-run-meta">' +
            (run.parsed.market ? '<span class="batch-run-chip">' + escHtml(run.parsed.market) + '</span>' : '') +
            (run.parsed.publisher ? '<span>' + escHtml(run.parsed.publisher) + '</span>' : '') +
            (run.parsed.eventType ? '<span>· ' + escHtml(run.parsed.eventType) + '</span>' : '') +
            '<span>· ' + run.totalEntities + ' entities</span>' +
            (run.submittedAt ? '<span>· submitted ' + escHtml(run.submittedAt) + '</span>' : '') +
          '</div>' +
        '</div>' +
        '<div class="batch-run-actions"><button class="batch-open-btn" type="button" onclick="openBatchRunInValidate(' + index + ')">Review findings</button></div>' +
      '</div>' +
      '<div class="batch-run-fields">' +
        '<div class="batch-run-field"><span class="batch-run-field-label">Top repeated field</span><div class="batch-run-field-value">' + escHtml(run.topField) + '</div></div>' +
        '<div class="batch-run-field"><span class="batch-run-field-label">Top fix owner</span><div class="batch-run-field-value">' + escHtml(run.topOwner) + '</div></div>' +
        '<div class="batch-run-field"><span class="batch-run-field-label">First issue surfaced</span><div class="batch-run-field-value">' + (firstIssue ? escHtml(firstIssue.field + ': ' + firstIssue.msg) : 'No issues surfaced in this payload.') + '</div></div>' +
        '<div class="batch-run-field"><span class="batch-run-field-label">Run timing</span><div class="batch-run-field-value">Analysed ' + escHtml(run.analysedAt) + (run.submittedAt ? '<br>Submitted ' + escHtml(run.submittedAt) : '') + '</div></div>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';

  host.innerHTML = summaryHtml + runsHtml;
}

function runBatchValidation() {
  const input = document.getElementById('batch-input-area');
  const btn = document.getElementById('batch-run-btn');
  if (!input || !btn) return;
  const text = input.value.trim();
  if (!text) return;

  const docs = splitBatchDocuments(text);
  if (!docs.length) return;

  btn.disabled = true;
  btn.textContent = 'Running Batch Validation';
  setTimeout(function() {
    const saveHistory = !!(document.getElementById('batch-save-history') && document.getElementById('batch-save-history').checked);
    const batchTimestamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 12);
    const batchNonce = Math.random().toString(36).slice(2, 6).toUpperCase();
    const batchSessionId = 'BATCH-' + batchTimestamp + '-' + batchNonce;
    const runs = docs.map(function(doc) {
      const run = buildValidationRunFromText(doc, {
        sourceMode: 'batch',
        batchSessionId: batchSessionId
      });
      if (!run.error) persistValidationRun(run, { saveHistory: saveHistory });
      return run;
    });
    renderBatchResults(runs);
    btn.disabled = false;
    btn.textContent = 'Run Batch Validation';
    updateTabBadges();
  }, 10);
}

// ── History / Export ─────────────────────────────────────────────────────────
const HISTORY_KEY = 'tx_oca_di_val_history_v1';

function loadHistory() {
  try {
    const raw = getStorage().getItem(HISTORY_KEY) || '[]';
    const all = JSON.parse(raw);
    return pruneExpiredRuns(Array.isArray(all) ? all : []);
  }
  catch(e) { return []; }
}

// Maximum chars to store per error message — prevents a single run with long
// enum-listing messages (e.g. 200-value valid-options list) from blowing the
// ~5 MB localStorage quota and causing a silent save failure.
const MAX_ERR_MSG_CHARS = 300;

function _trimRunForStorage(run) {
  // Deep-clone so we never mutate the live in-memory run
  const r = JSON.parse(JSON.stringify(run));
  if (Array.isArray(r.errors)) {
    r.errors = r.errors.map(function(e) {
      if (typeof e.msg === 'string' && e.msg.length > MAX_ERR_MSG_CHARS) {
        e.msg = e.msg.slice(0, MAX_ERR_MSG_CHARS) + '… [truncated for storage]';
      }
      return e;
    });
  }
  return r;
}

function saveHistory(runs) {
  try {
    getStorage().setItem(HISTORY_KEY, JSON.stringify(runs));
    // Clear any prior storage warning if save succeeded
    try { localStorage.removeItem('_catch_storage_warn'); } catch(e) {}
  } catch(e) {
    // QuotaExceededError — trim oldest runs one at a time and retry
    const trimmed = runs.slice();
    let saved = false;
    while (trimmed.length > 1) {
      trimmed.pop();
      try {
        getStorage().setItem(HISTORY_KEY, JSON.stringify(trimmed));
        saved = true;
        // Set a warning flag so the UI can alert the user
        try { localStorage.setItem('_catch_storage_warn', '1'); } catch(ex) {}
        break;
      } catch(ex) { /* keep trimming */ }
    }
    if (!saved) {
      // Storage is completely blocked or quota is extremely low — flag it
      try { localStorage.setItem('_catch_storage_warn', '1'); } catch(ex) {}
    }
  }
}

function addToHistory(run) {
  const runs = loadHistory();
  // Scrub PII first, then trim long messages before writing to storage
  runs.unshift(_trimRunForStorage(scrubRunPII(run)));
  if (runs.length > 200) runs.splice(200); // cap at 200 runs
  saveHistory(runs);
  // Surface a warning banner if storage had to trim runs
  _checkStorageWarning();
}

function _checkStorageWarning() {
  try {
    if (!localStorage.getItem('_catch_storage_warn')) return;
  } catch(e) { return; }
  var existing = document.getElementById('storage-warn-banner');
  if (existing) return;
  var banner = document.createElement('div');
  banner.id = 'storage-warn-banner';
  banner.style.cssText = 'position:fixed;bottom:0;left:0;right:0;z-index:9998;background:#3a1a00;border-top:1px solid var(--orange);color:var(--orange);font-family:var(--mono);font-size:10px;padding:7px 16px;display:flex;align-items:center;gap:10px;';
  banner.innerHTML = '<span>⚠ Browser storage is nearly full — oldest validation runs were dropped to make room. Export your history now to avoid losing data.</span>'
    + '<button onclick="exportCSV()" style="background:var(--orange);color:#000;border:none;padding:3px 10px;border-radius:3px;font-family:var(--mono);font-size:10px;cursor:pointer;flex-shrink:0;">↓ Export History</button>'
    + '<button onclick="this.parentNode.remove();try{localStorage.removeItem(\'_catch_storage_warn\');}catch(e){}" style="background:none;border:1px solid var(--orange);color:var(--orange);padding:3px 8px;border-radius:3px;font-family:var(--mono);font-size:10px;cursor:pointer;flex-shrink:0;">Dismiss</button>';
  document.body.appendChild(banner);
}

function clearHistory() {
  if (!confirm('Clear all validation history? This cannot be undone.')) return;
  getStorage().removeItem(HISTORY_KEY);
  renderHistory();
}

function renderHistory() {
  const runs = loadHistory();
  const filterEl = document.getElementById('history-filter');
  const filterVal = filterEl ? filterEl.value.trim().toLowerCase() : '';
  const list = document.getElementById('history-list');
  const countEl = document.getElementById('hist-run-count');
  const errEl = document.getElementById('hist-err-count');
  if (countEl) countEl.textContent = runs.length;
  const totalErrors = runs.reduce(function(s,r) { return s + r.errorCount; }, 0);
  if (errEl) errEl.textContent = totalErrors;

  if (runs.length === 0) {
    list.innerHTML = '<div class="history-empty">No validation runs recorded yet. Run a validation to start building history.</div>';
    return;
  }

  // Apply filter
  const filtered = filterVal ? runs.filter(function(run) {
    const searchStr = [
      run.envelopeId || '',
      run.publisher || '',
      run.eventType || '',
      run.errors.map(function(e) { return (e.county||'') + ' ' + (e.entityType||'') + ' ' + (e.field||''); }).join(' ')
    ].join(' ').toLowerCase();
    return searchStr.includes(filterVal);
  }) : runs;

  list.innerHTML = filtered.map((run, idx) => {
    const runId = 'hrun-' + idx;
    const isBatchRun = run.sourceMode === 'batch' || !!run.batchSessionId;
    const batchSessionLabel = isBatchRun && run.batchSessionId ? run.batchSessionId : '';
    const badge = run.errorCount === 0
      ? `<span class="history-badge-ok">✓ All valid</span>`
      : `<span class="history-badge-err" style="cursor:pointer;user-select:none;" title="Click to toggle error details" onclick="(function(){var el=document.getElementById('${runId}-errors');var tog=document.getElementById('${runId}-tog');if(el){var open=el.style.display!=='none';el.style.display=open?'none':'block';tog.textContent=open?'▶':'▼';}})()"><span id="${runId}-tog">▼</span> ✗ ${run.errorCount} error${run.errorCount>1?'s':''}</span>`;

    const errorRows = run.errors.map(e =>
      `<div class="history-error-row">
        <span class="history-entity-id">${escHtml(e.entityId || e.recordid || '—')}</span>
        <span style="color:var(--text3);min-width:60px">${escHtml(e.field)}</span>
        <span>${escHtml(e.msg.length > 80 ? e.msg.slice(0,80) + '...' : e.msg)}</span>
      </div>`
    ).join('');

    return `<div class="history-run">
      <div class="history-run-top">
        <div class="history-run-main">
          <div class="history-run-header">
        <span class="history-run-index">#${runs.length - idx}</span>
        <span class="history-envelope">${escHtml(run.envelopeId || 'No EnvelopeId')}</span>
        ${isBatchRun ? `<span class="history-badge-mode">Batch</span>` : ``}
        ${badge}
          </div>
          <div class="history-run-subline">
            ${isBatchRun ? `<span class="history-chip batch">Batch run</span>` : ''}
            ${run.market && run.market !== 'TX' ? `<span class="history-chip market">${escHtml(run.market)}</span>` : ''}
            ${run.envelopeSubmittedAt ? `<span class="history-chip submitted" title="Envelope OriginalTimestamp — when the AEP received the submission">AEP submission ${escHtml(run.envelopeSubmittedAt)}</span>` : ''}
            <span class="history-chip analysed" title="When CATCH analysed this envelope">CATCH analysed ${escHtml(run.timestamp)}</span>
            ${batchSessionLabel ? `<span class="history-chip batch-session" title="Shared batch session ID for runs validated together">${escHtml(batchSessionLabel)}</span>` : ''}
            <span class="history-run-meta"><strong>${run.entityCount}</strong> entities <span class="history-run-dot">·</span> ${escHtml(run.publisher || '—')} <span class="history-run-dot">·</span> ${escHtml(run.eventType || '—')}</span>
          </div>
        </div>
        <div class="history-run-actions">
          <button class="export-btn" style="padding:2px 10px;font-size:10px" onclick="exportRunCSV(${idx})">Workbook</button>
        <button class="export-btn" style="padding:2px 10px;font-size:10px" onclick="exportRunJSON(${idx})">JSON</button>
      </div>
        </div>
      ${run.errorCount > 0 ? `<div id="${runId}-errors" class="history-errors">${errorRows}</div>` : ''}
    </div>`;
  }).join('');
}

// ── Clean single-fire download helper ────────────────────────────────────────
function dlFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 500);
}
// ── Shared XLSX cell helpers (reused by history, error-log, and catalog exports) ─
const HISTORY_LEGEND_ROWS = [
  ['Column', 'Description', 'Example / Notes'],
  ['Run #', 'Sequential run number assigned by CATCH — newest run is #1. Consistent across bulk export.', '153'],
  ['Analysed At (CATCH)', "Date and time CATCH processed this envelope — the tool's own clock.", '03/25/2026, 11:16 AM'],
  ['Envelope Submitted At (AEP)', 'Date and time the Alliance Exchange Platform (AEP) received the submission. Converted from the raw Unix timestamp in the payload.', '03/24/2026, 08:08:27 PM CDT'],
  ['Market', 'Pipeline market the envelope was submitted to. TX = Texas OCA Community Pipeline. IL = Illinois AOIC Community Pipeline.', 'TX'],
  ['Envelope ID', 'Unique identifier for the envelope assigned by the D&I pipeline. Use this to look up the raw payload in the AEP or ACB logs.', '6cead12b-6969-47bb-…'],
  ['Event Type', 'The event type declared at the envelope level. Determines whether entities are new records or deletes.', 'di-texas-oca-new-record-event'],
  ['Publisher', 'The CMS vendor that submitted the envelope, as declared in the Publisher field of the payload.', 'Tyler Tech-Odyssey'],
  ['Entity Count', 'Total number of entities contained in the envelope.', '51'],
  ['Error Count', 'Number of entities in the envelope that failed validation. A run where Error Count = Entity Count means every entity failed.', '51'],
  ['Entity ID', 'The CMS-assigned identifier for the specific entity that triggered this error row. Set by the publisher in the EntityId field of the payload. Useful for looking up the record in the source CMS.', 'CaseStatusSC-1010208'],
  ['Record ID', 'The D&I pipeline record identifier (UUID) from inside the entity data. Distinct from Entity ID — this is the identifier used by the Alliance pipeline, not the CMS.', 'd89d63af-2a0d-4103-…'],
  ['County / Instance ID', 'TX payloads: the county field from the entity data — the Texas county the court record belongs to. IL payloads: the instanceid field — the court instance identifier used by the AOIC pipeline.', 'Eastland (TX) / instanceid value (IL)'],
  ['Entity Type', 'The schema entity type declared for this entity. Determines which contract schema is validated against. Must match an approved value for the pipeline and event type.', 'di-texas-oca-court-case-status'],
  ['Field', 'The specific field within the entity that triggered the validation error.', 'case_status_event'],
  ['Ref', 'OCA or BIS error reference number if this error has been previously logged and tracked. Blank if no reference has been assigned.', 'OCA-001'],
  ['Error', 'Full validation error message as generated by CATCH, including any invalid values and the list of allowed options.', 'Invalid value "Dismissal". Valid options: …'],
  ['Translation', 'Plain-English explanation of the error and recommended fix, including fix ownership (publisher, D&I, BIS).', 'The case status event value does not match the approved enum. Fix owner: submitting publisher.'],
];

function _xc(v, opts) {
  opts = opts || {};
  return {
    v: v, t: typeof v === 'number' ? 'n' : 's',
    s: {
      font:      { name:'Arial', sz:opts.sz||10, bold:!!opts.bold, italic:!!opts.italic, color:{ rgb:opts.color||'000000' } },
      fill:       opts.fill ? { fgColor:{ rgb:opts.fill }, patternType:'solid' } : { patternType:'none' },
      alignment: { horizontal:opts.align||'left', vertical:'center', wrapText:!!opts.wrap },
      border: {
        top:    { style:'thin', color:{ rgb:'7895A8' } },
        bottom: { style:'thin', color:{ rgb:'7895A8' } },
        left:   { style:'thin', color:{ rgb:'7895A8' } },
        right:  { style:'thin', color:{ rgb:'7895A8' } }
      }
    }
  };
}
function _xHdr(v)    { return _xc(v, { bold:true, fill:'1F3864', color:'FFFFFF', sz:11, align:'center' }); }
function _xCol(v)    { return _xc(v, { bold:true, fill:'2E75B6', color:'FFFFFF', sz:10, align:'center' }); }
function _xOk(v)     { return _xc(v, { fill:'D4EDDA', align:'center', sz:10, bold:true, color:'155724' }); }
function _xErr(v)    { return _xc(v, { fill:'FFE0E0', align:'center', sz:10, bold:true, color:'721C24' }); }
function _xAlt(v,i,align) { return _xc(v, { fill:i%2===0?'EBF3FB':null, align:align||'left', sz:10 }); }

function _buildLegendSheet(legendRows) {
  var ws = {};
  var cols = ['Column', 'Description', 'Example / Notes'];
  var colWidths = [22, 72, 40];
  cols.forEach(function(h, c) { ws[XLSX.utils.encode_cell({r:0,c:c})] = _xCol(h); });
  legendRows.slice(1).forEach(function(row, i) {
    row.forEach(function(v, c) {
      ws[XLSX.utils.encode_cell({r:i+1,c:c})] = _xc(v, { fill:i%2===0?'EBF3FB':null, sz:10, wrap:c===1 });
    });
  });
  ws['!ref'] = XLSX.utils.encode_range({r:0,c:0},{r:legendRows.length-1,c:2});
  ws['!cols'] = colWidths.map(function(w){ return {wch:w}; });
  ws['!rows'] = [{hpt:18}];
  ws['!freeze'] = {xSplit:0, ySplit:1};
  return ws;
}

function _buildHistoryDataSheet(runs, includeRunNum) {
  var ws = {};
  var hdrs = includeRunNum
    ? ['Run #','Analysed At (CATCH)','Envelope Submitted At (AEP)','Market','Envelope ID','Event Type','Publisher','Entity Count','Error Count','Entity ID','Record ID','County / Instance ID','Entity Type','Field','Ref','Error','Translation']
    : ['Analysed At (CATCH)','Envelope Submitted At (AEP)','Market','Envelope ID','Event Type','Publisher','Entity Count','Error Count','Entity ID','Record ID','County / Instance ID','Entity Type','Field','Ref','Error','Translation'];
  var colWidths = includeRunNum
    ? [7,22,26,8,38,32,20,13,12,22,18,20,36,22,10,48,48]
    : [22,26,8,38,32,20,13,12,22,18,20,36,22,10,48,48];

  hdrs.forEach(function(h,c){ ws[XLSX.utils.encode_cell({r:0,c:c})] = _xCol(h); });

  var dataRows = [];
  runs.forEach(function(run, idx) {
    var mkt = run.market || 'TX';
    var runNum = runs.length - idx;
    if (run.errors.length === 0) {
      var base = includeRunNum ? [runNum] : [];
      dataRows.push(base.concat([run.timestamp, run.envelopeSubmittedAt||'', mkt, run.envelopeId||'', run.eventType||'', run.publisher||'', run.entityCount, 0, '', '', '', '', '', '', '✓ All valid', '']));
    } else {
      run.errors.forEach(function(e) {
        var base = includeRunNum ? [runNum] : [];
        dataRows.push(base.concat([run.timestamp, run.envelopeSubmittedAt||'', mkt, run.envelopeId||'', run.eventType||'', run.publisher||'', run.entityCount, run.errorCount, e.entityId||'', e.recordid||'', e.county||e.instanceid||'', e.entityType||'', e.field||'', e.ref||'', e.msg||'', e.translation||'']));
      });
    }
  });

  var errColIdx  = hdrs.indexOf('Error');
  var transColIdx = hdrs.indexOf('Translation');
  dataRows.forEach(function(row, i) {
    row.forEach(function(v, c) {
      var isErr   = c === errColIdx && v && v !== '✓ All valid';
      var isOk    = c === errColIdx && v === '✓ All valid';
      var isCount = hdrs[c] === 'Error Count';
      var cell;
      if (isErr)        cell = _xc(v,  { fill:'FFE0E0', sz:10, wrap:true });
      else if (isOk)    cell = _xOk(v);
      else if (isCount && typeof v === 'number') cell = v > 0 ? _xErr(v) : _xOk(v);
      else              cell = _xAlt(v, i, (hdrs[c]==='Run #'||hdrs[c]==='Market'||hdrs[c]==='Entity Count'||hdrs[c]==='Error Count') ? 'center' : 'left');
      ws[XLSX.utils.encode_cell({r:i+1,c:c})] = cell;
    });
  });

  ws['!ref'] = XLSX.utils.encode_range({r:0,c:0},{r:Math.max(1,dataRows.length),c:hdrs.length-1});
  ws['!cols'] = colWidths.map(function(w){ return {wch:w}; });
  ws['!rows'] = [{hpt:20}];
  ws['!freeze'] = {xSplit:0, ySplit:1};
  return ws;
}

async function exportCSV() {
  const runs = loadHistory();
  if (runs.length === 0) { alert('No history to export.'); return; }
  if (!(await confirmExport('CATCH Validation History (.xlsx)'))) return;
  var wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, _buildHistoryDataSheet(runs, true),  '📋 Validation History');
  XLSX.utils.book_append_sheet(wb, _buildLegendSheet(HISTORY_LEGEND_ROWS), '📖 Legend');
  XLSX.writeFile(wb, 'CATCH_Validation_History_' + new Date().toISOString().slice(0,10) + '.xlsx');
}

async function exportJSON() {
  const runs = loadHistory();
  if (runs.length === 0) { alert('No history to export.'); return; }
  const blob = new Blob([JSON.stringify(runs, null, 2)], {type:'application/json'});
  dlFile(blob, 'TX_OCA_DI_Validation_History_' + new Date().toISOString().slice(0,10) + '.json');
}

async function exportRunCSV(idx) {
  const runs = loadHistory();
  const run = runs[idx];
  if (!run) return;
  if (!(await confirmExport('CATCH Run Export (.xlsx)'))) return;
  const mkt = run.market || 'TX';
  const envSlug = (run.envelopeId || 'no-envelope').slice(0,8);
  var wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, _buildHistoryDataSheet([run], false), '📋 Run Data');
  XLSX.utils.book_append_sheet(wb, _buildLegendSheet(HISTORY_LEGEND_ROWS), '📖 Legend');
  XLSX.writeFile(wb, 'CATCH_' + mkt + '_' + envSlug + '_' + new Date().toISOString().slice(0,10) + '.xlsx');
}

async function exportRunJSON(idx) {
  const runs = loadHistory();
  const run = runs[idx];
  if (!run) return;
  const mkt2 = run.market || 'TX';
  const envSlug2 = (run.envelopeId || 'no-envelope').slice(0,8);
  dlFile(new Blob([JSON.stringify(run, null, 2)], {type:'application/json'}), 'CATCH_' + mkt2 + '_' + envSlug2 + '_' + new Date().toISOString().slice(0,10) + '.json');
}

async function saveAllHistory() {
  const runs = loadHistory();
  if (runs.length === 0) { alert('No history to save.'); return; }
  dlFile(new Blob([JSON.stringify(runs, null, 2)], {type:'application/json'}), 'TX_OCA_DI_History_Backup_' + new Date().toISOString().slice(0,10) + '.json');
}

function importHistory(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const imported = JSON.parse(e.target.result);
      if (!Array.isArray(imported)) { alert('Invalid backup file — expected a JSON array.'); return; }
      const existing = loadHistory();
      // Merge: deduplicate by envelopeId + timestamp
      const seen = new Set(existing.map(r => r.envelopeId + '|' + r.timestamp));
      const newRuns = imported.filter(r => !seen.has((r.envelopeId||'') + '|' + (r.timestamp||'')));
      const merged = [...newRuns, ...existing].slice(0, 200);
      saveHistory(merged);
      renderHistory();
      alert('Imported ' + newRuns.length + ' run(s). ' + (imported.length - newRuns.length) + ' duplicate(s) skipped.');
    } catch(err) {
      alert('Could not read file: ' + err.message);
    }
    // Reset input so same file can be re-imported if needed
    event.target.value = '';
  };
  reader.readAsText(file);
}

// Build error log
const OCA_ERRORS = [
  {
    id:"OCA-006", date:"03/18/2026",
    envelope:"3f30f332-d88e-4e27-a4b3-8e50533f2ec9",
    entity:"di-texas-oca-court-charge (singular — invalid)",
    pub:"Tyler Tech-Odyssey",
    cause:"Entity type name is wrong — 'court-charge' (singular) does not exist. Valid options: di-texas-oca-court-charges (v3.0.0) or di-texas-oca-court-criminal-charges (v0.1). Odyssey must determine which and fix.",
    bis:"No schema change required.",
    priority:"High — blocks Grayson County data from landing in OCA"
  },
  {
    id:"OCA-007", date:"03/18/2026",
    envelope:"08c237d7-a88a-419f-9a15-e52ffd59d401",
    entity:"di-texas-oca-court-appointments",
    pub:"Tyler Tech-Odyssey",
    cause:"County 'Casey' is not a real TX county. Fields amount_approved, number_of_hours_billed, total_billed_expenses submitted as strings — must be number|null. ('Publisher not in allowed enum' was validator noise from wrong Source branch — not a real error.)",
    bis:"No schema change required.",
    priority:"Medium — demo/test data"
  },
  {
    id:"OCA-008", date:"03/18/2026",
    envelope:"993d44c9-e37b-4aa6-bc3d-599dc2bf4987",
    entity:"di-texas-oca-court-case-events",
    pub:"Tyler Tech-Odyssey",
    cause:"County 'Casey' is not a real TX county. Counties must be associated with the publisher's registered Source ID. ('Publisher not in allowed enum' was validator noise from wrong Source branch.)",
    bis:"No schema change required.",
    priority:"Medium — demo/test data"
  },
  {
    id:"OCA-009", date:"03/18/2026",
    envelope:"fe0a0864-817a-4228-998f-8a1b492cceed",
    entity:"di-texas-oca-court-case-events (×2: CaseEventCE-37488, CaseEventCE-37491)",
    pub:"Tyler Tech-Odyssey",
    cause:"Identical root cause to OCA-008. County 'Casey' is not a real TX county, both entities. Demo/test data submitted against unregistered Source + fake county.",
    bis:"No schema change required.",
    priority:"Medium — demo/test data"
  },
  {
    id:"OCA-010", date:"03/18/2026",
    envelope:"74d28300-85dc-4d66-87cf-b8a9970c322c",
    entity:"di-texas-oca-court-charge (singular — invalid, ×3: Charge-97687, Charge-117621, Charge-123812)",
    pub:"Tyler Tech-Odyssey",
    cause:"Same entity type naming error as OCA-006. Real data: Grayson County, cause 2632050. Additional downstream violations that will surface after entity type fix: (1) plea_type submitted as 'Guilty' — must be 'G - Guilty'; (2) field name 'filing_statute_citation' — correct name is 'statute_citation'; (3) field name 'filing_level_and_degree_of_prosecuted_offense' — correct name is 'level_and_degree_of_prosecuted_offense'.",
    bis:"No schema change required.",
    priority:"Critical — real Grayson County production data not landing in OCA"
  },
  {
    id:"OCA-011", date:"03/18/2026",
    envelope:"114650cc-2ad7-4017-b2c5-e968255c3c50",
    entity:"di-texas-oca-court-party (CaseParty-158327)",
    pub:"Tyler Tech-Odyssey",
    cause:"party_age_at_time_of_offense submitted as string '35' — must be number|null. party_race submitted as 'Not Available' — must be 'Not Available (Blank)'. Real production data: cause 2632050, Grayson County — same case as OCA-010. Both charge and party entity types failing for this case.",
    bis:"No schema change required.",
    priority:"Critical — same case as OCA-010, Grayson County"
  },
];

// Track manual edits to envelope override field
document.getElementById('envelope-override').addEventListener('input', function() {
  this.dataset.manuallySet = this.value.trim() ? '1' : '';
});

// Init history count on load
try { renderHistory(); } catch(e) {}

// ── TX Error Log — auto-logging + rendering ──────────────────────────────────
const ERROR_LOG_KEY     = 'catch_tx_error_log_v1';
const ERROR_LOG_CAP_KEY = 'catch_tx_error_log_cap_v1';
const DEFAULT_LOG_CAP   = 500;

function getLogCap() {
  try {
    var stored = parseInt(localStorage.getItem(ERROR_LOG_CAP_KEY));
    if (!isNaN(stored) && stored >= 100) return stored;
  } catch(e) {}
  return DEFAULT_LOG_CAP;
}

function saveLogCap() {
  var input = document.getElementById('log-cap-input');
  if (!input) return;
  var val = Math.max(100, Math.min(10000, parseInt(input.value) || DEFAULT_LOG_CAP));
  input.value = val;
  try { localStorage.setItem(ERROR_LOG_CAP_KEY, String(val)); } catch(e) {}
  var msg = document.getElementById('log-cap-message');
  if (msg) { msg.className = 'settings-msg ok'; msg.textContent = 'Cap updated to ' + val + ' entries.'; setTimeout(function(){ msg.textContent = ''; msg.className = ''; }, 2000); }
  updateLogCapUI();
}

function updateLogCapUI() {
  var cap = getLogCap();
  var input = document.getElementById('log-cap-input');
  if (input) input.value = cap;
  var countEl = document.getElementById('log-current-count');
  var pctEl   = document.getElementById('log-cap-pct');
  var badge   = document.getElementById('settings-cap-badge');
  if (countEl) {
    var current = loadErrorLog().length;
    countEl.textContent = current;
    var pct = cap > 0 ? Math.round((current / cap) * 100) : 0;
    var nearCap = current >= cap * 0.8;
    var atCap   = current >= cap;
    countEl.style.color = atCap ? 'var(--red)' : nearCap ? 'var(--orange)' : 'var(--text2)';
    if (pctEl) {
      if (pct >= 80) {
        pctEl.textContent = '(' + pct + '% full)';
        pctEl.style.color = atCap ? 'var(--red)' : 'var(--orange)';
      } else {
        pctEl.textContent = '(' + pct + '% full)';
        pctEl.style.color = 'var(--text3)';
      }
    }
    // Header cog badge
    if (badge) {
      if (pct >= 80) {
        badge.textContent = pct + '%';
        badge.style.display = 'inline-block';
        badge.style.background = atCap ? 'var(--red)' : 'var(--orange)';
        badge.style.color = '#fff';
      } else {
        badge.style.display = 'none';
      }
    }
  }
}

function loadErrorLog() {
  try {
    var stored = localStorage.getItem(ERROR_LOG_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch(e) { return []; }
}

function saveErrorLog(entries) {
  try { localStorage.setItem(ERROR_LOG_KEY, JSON.stringify(entries)); } catch(e) {}
}

// Convert a validation run result into error log entries
var _catalogSeenKeys = new Set();

function _checkForNewCatalogEntries() {
  try {
    var fresh = buildCatalogData();
    var newPatterns = [];
    fresh.forEach(function(entry) {
      var k = entry.field + '|||' + entry.errorCategory;
      if (!_catalogSeenKeys.has(k)) {
        _catalogSeenKeys.add(k);
        newPatterns.push(entry);
      }
    });
    if (newPatterns.length > 0) {
      var noun = newPatterns.length === 1 ? 'new error pattern' : 'new error patterns';
      var example = newPatterns[0].field ? ' (' + newPatterns[0].field + ')' : '';
      _showCatalogNewToast(newPatterns.length + ' ' + noun + ' captured in Error Catalog' + example);
    }
  } catch(e) {}
}

function _showCatalogNewToast(msg) {
  var existing = document.getElementById('catalog-new-toast');
  if (existing) existing.remove();
  var t = document.createElement('div');
  t.id = 'catalog-new-toast';
  t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;background:#0d2a1f;border:1px solid var(--green);border-radius:6px;padding:10px 14px;display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:11px;color:var(--green);box-shadow:0 4px 16px rgba(0,0,0,.5);cursor:pointer;max-width:340px;';
  t.innerHTML = '<span style="font-size:14px;">◈</span><span style="flex:1;">' + escHtml(msg) + '</span><span style="opacity:0.6;font-size:10px;white-space:nowrap;cursor:pointer;" onclick="switchTab(\'assoc\');document.getElementById(\'catalog-new-toast\').remove();">View →</span>';
  t.onclick = function(e) { if (e.target.tagName !== 'SPAN' || !e.target.onclick) { switchTab('assoc'); t.remove(); } };
  document.body.appendChild(t);
  setTimeout(function() { if (t.parentNode) t.remove(); }, 8000);
}

function autoLogRunToErrorLog(parsed, results, envelopeId, originalTimestamp) {
  var errorResults = results.filter(function(r) { return !r.valid; });
  if (errorResults.length === 0) return;

  var existing = loadErrorLog();
  var now = new Date().toLocaleString('en-US', {month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});

  // One entry per entity that had errors
  errorResults.forEach(function(r) {
    var entityTypes = [...new Set(r.errors.map(function(e) { return e.field; }))];
    var causeLines = r.errors.map(function(e) {
      var trans = getTranslation(e.field, e.msg, r);
      return '['  + e.field + '] ' + (trans || e.msg);
    }).join(' | ');
    var refs = [...new Set(r.errors.filter(function(e){ return e.ref; }).map(function(e){ return e.ref; }))].join(', ');

    var submittedAt = originalTimestamp ? formatUnixMs(originalTimestamp) : null;
    existing.unshift({
      id: 'AUTO-' + Date.now() + '-' + Math.random().toString(36).slice(2,6).toUpperCase(),
      source: 'auto',
      date: now,
      envelope: envelopeId || parsed.envelopeId || 'Unknown',
      pub: r.entityType ? (r.publisher || parsed.publisher || 'Unknown') : (parsed.publisher || 'Unknown'),
      entity: r.entityType + (r.entityId ? ' (' + r.entityId + ')' : ''),
      cause: causeLines,
      submittedAt: submittedAt || null,
      bis: 'Auto-logged from validation run. Review and update BIS position as needed.',
      priority: refs && refs.toLowerCase().indexOf('oca') !== -1 ? 'Review required' : 'Pending review',
      refs: refs
    });
  });

  var cap = getLogCap();
  if (existing.length > cap) {
    // Silently trim — no automatic file download. Use the ↓ CSV / ↓ JSON buttons
    // in the Error Log toolbar to manually export before cap is hit.
    existing = existing.slice(0, cap);
  }
  saveErrorLog(existing);
  updateLogCapUI();
  // Warn user when approaching or at cap
  try { maybeShowCapWarning(existing.length, cap); } catch(e) {}
  // Check if this run added new error patterns to the catalog
  try { _checkForNewCatalogEntries(); } catch(e) {}
}

// Merge pinned OCA_ERRORS + auto-logged entries for display
function getAllLogEntries() {
  var pinned = OCA_ERRORS.map(function(e) {
    return Object.assign({}, e, { source: 'pinned' });
  });
  var autoLogged = loadErrorLog();
  // Newest first: auto-logged already newest first, pinned go after
  return autoLogged.concat(pinned);
}

function renderErrorLog() {
  var pubFilter      = (document.getElementById('log-filter-pub')      || {}).value || '';
  var entityFilter   = (document.getElementById('log-filter-entity')   || {}).value || '';
  var priorityFilter = (document.getElementById('log-filter-priority') || {}).value || '';
  var sourceFilter   = (document.getElementById('log-filter-source')   || {}).value || '';

  var searchQ = ((document.getElementById('log-search') || {}).value || '').toLowerCase();
  var all = getAllLogEntries();

  var filtered = all.filter(function(e) {
    if (pubFilter    && e.pub    !== pubFilter)                                                        return false;
    if (entityFilter && e.entity.indexOf(entityFilter) === -1)                                         return false;
    if (priorityFilter === 'critical' && e.priority.toLowerCase().indexOf('critical') === -1)          return false;
    if (priorityFilter === 'medium'   && e.priority.toLowerCase().indexOf('medium')   === -1)          return false;
    if (sourceFilter  && e.source !== sourceFilter)                                                    return false;
    if (searchQ) {
      var haystack = [e.id||'', e.envelope||'', e.pub||'', e.entity||'', e.cause||'', e.bis||'', e.priority||''].join(' ').toLowerCase();
      if (haystack.indexOf(searchQ) === -1) return false;
    }
    return true;
  });

  var countEl = document.getElementById('log-count');
  if (countEl) countEl.textContent = filtered.length + ' of ' + all.length + ' entries';

  var container = document.getElementById('error-log-container');
  if (!container) return;

  if (filtered.length === 0) {
    container.innerHTML = '<div style="font-size:11px;color:var(--text3);padding:20px 0;">No entries match the selected filters.</div>';
    return;
  }

  container.innerHTML = filtered.map(function(e, idx) {
    var prioClass = (e.priority && e.priority.toLowerCase().indexOf('critical') !== -1) ? 'priority-crit' : 'priority-med';
    var sourceBadge = e.source === 'pinned'
      ? '<span style="font-size:9px;color:var(--blue);background:#0d1f3d;border:1px solid #1a3a6e;padding:1px 6px;border-radius:3px;flex-shrink:0;">Pinned</span>'
      : '<span style="font-size:9px;color:var(--green);background:#0d1f16;border:1px solid #1a3a2a;padding:1px 6px;border-radius:3px;flex-shrink:0;">Auto-logged</span>';
    var fixOwner = e.source === 'pinned' ? 'Open · Fix Owner: Odyssey' : 'Auto-logged · Pending review';
    var fixStyle = e.source === 'pinned' ? 'log-status-open' : 'font-size:9px;color:var(--text3);background:var(--bg3);border:1px solid var(--border2);padding:2px 6px;border-radius:3px;';

    return '<div class="log-card">' +
      '<div class="log-card-header">' +
        '<span class="log-id">' + escHtml(e.id) + '</span>' +
        sourceBadge +
        '<span class="log-pub">' + escHtml(e.pub) + '</span>' +
        (e.source === 'pinned'
          ? '<span class="log-status-open">' + escHtml(fixOwner) + '</span>'
          : '<span style="' + fixStyle + '">' + escHtml(fixOwner) + '</span>') +
        '<span class="log-date">' + escHtml(e.date) + (e.submittedAt ? ' <span style="color:var(--orange);font-size:9px;margin-left:6px;">⬆ ' + escHtml(e.submittedAt) + '</span>' : '') + '</span>' +
        '<button class="export-btn" style="margin-left:auto;padding:2px 7px;font-size:9px" onclick="exportSingleLogEntry(' + idx + ')">XLSX</button>' +
        '<button class="export-btn" style="margin-left:4px;padding:2px 7px;font-size:9px" onclick="exportSingleLogEntryJSON(' + idx + ')">JSON</button>' +
      '</div>' +
      '<div class="log-grid">' +
        '<div class="log-grid-label">Envelope</div>' +
        '<div class="log-grid-value mono">' + escHtml(e.envelope) + '</div>' +
      '</div>' +
      '<div class="log-grid">' +
        '<div class="log-grid-label">Entity</div>' +
        '<div class="log-grid-value entity">' + escHtml(e.entity) + '</div>' +
      '</div>' +
      '<div class="log-grid">' +
        '<div class="log-grid-label">Root Cause</div>' +
        '<div class="log-grid-value cause">' + escHtml(e.cause) + '</div>' +
      '</div>' +
      '<div class="log-grid">' +
        '<div class="log-grid-label">BIS Position</div>' +
        '<div class="log-grid-value bis">' + escHtml(e.bis) + '</div>' +
      '</div>' +
      '<div class="log-grid">' +
        '<div class="log-grid-label">Priority</div>' +
        '<div class="log-grid-value ' + prioClass + '">' + escHtml(e.priority) + '</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

// Per-entry export helpers
var _LOG_HDRS = ['Error ID','Source','Date','Envelope ID','Publisher','Entity Type','Root Cause','BIS Position','Priority'];
var _LOG_WIDTHS = [14, 12, 14, 38, 22, 38, 52, 52, 11];

function _buildErrorLogSheet(entries) {
  var ws = {};
  _LOG_HDRS.forEach(function(h,c){ ws[XLSX.utils.encode_cell({r:0,c:c})] = _xCol(h); });
  entries.forEach(function(e, i) {
    var row = [e.id||'', e.source||'', e.date||'', e.envelope||'', e.pub||'', e.entity||'', e.cause||'', e.bis||'', e.priority||''];
    row.forEach(function(v, c) {
      var wrap = c >= 6;
      ws[XLSX.utils.encode_cell({r:i+1,c:c})] = _xc(v, { fill:i%2===0?'EBF3FB':null, sz:10, wrap:wrap, align:c===8?'center':'left' });
    });
  });
  ws['!ref'] = XLSX.utils.encode_range({r:0,c:0},{r:Math.max(1,entries.length),c:_LOG_HDRS.length-1});
  ws['!cols'] = _LOG_WIDTHS.map(function(w){ return {wch:w}; });
  ws['!rows'] = [{hpt:20}];
  ws['!freeze'] = {xSplit:0, ySplit:1};
  return ws;
}

async function exportSingleLogEntry(idx) {
  var all = getAllLogEntries();
  var e = all[idx];
  if (!e) return;
  if (!(await confirmExport('CATCH Error Log Entry (.xlsx)'))) return;
  var wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, _buildErrorLogSheet([e]), '📋 Error Log Entry');
  XLSX.writeFile(wb, 'CATCH_ErrorLog_' + (e.id||'entry').replace(/\s/g,'-') + '_' + new Date().toISOString().slice(0,10) + '.xlsx');
}

async function exportSingleLogEntryJSON(idx) {
  var all = getAllLogEntries();
  var e = all[idx];
  if (!e) return;
  var blob = new Blob([JSON.stringify(e, null, 2)],{type:'application/json'});
  dlFile(blob, 'CATCH_ErrorLog_' + (e.id||'entry').replace(/\s/g,'-') + '_' + new Date().toISOString().slice(0,10) + '.json');
}

async function exportErrorLogCSV() {
  var all = getAllLogEntries();
  if (all.length === 0) { alert('No entries to export.'); return; }
  if (!(await confirmExport('CATCH Error Log (.xlsx)'))) return;
  var wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, _buildErrorLogSheet(all), '📋 Error Log');
  XLSX.writeFile(wb, 'CATCH_TX_ErrorLog_' + new Date().toISOString().slice(0,10) + '.xlsx');
}

async function exportErrorLogJSON() {
  var all = getAllLogEntries();
  if (all.length === 0) { alert('No entries to export.'); return; }
  var blob = new Blob([JSON.stringify(all, null, 2)],{type:'application/json'});
  dlFile(blob, 'CATCH_TX_ErrorLog_' + new Date().toISOString().slice(0,10) + '.json');
}

// Populate filter dropdowns from merged entry set
function initErrorLog() {
  var all = getAllLogEntries();
  var pubs = [...new Set(all.map(function(e){ return e.pub; }))].sort();
  var entities = [...new Set(all.map(function(e){
    var m = e.entity.match(/di-[a-z0-9-]+/);
    return m ? m[0] : e.entity;
  }))].sort();

  var pubSel = document.getElementById('log-filter-pub');
  if (pubSel) { pubSel.innerHTML = '<option value="">All</option>'; pubs.forEach(function(p){ var o=document.createElement('option');o.value=p;o.textContent=p;pubSel.appendChild(o); }); }

  var entSel = document.getElementById('log-filter-entity');
  if (entSel) { entSel.innerHTML = '<option value="">All</option>'; entities.forEach(function(et){ var o=document.createElement('option');o.value=et;o.textContent=et;entSel.appendChild(o); }); }

  renderErrorLog();
}

try { initErrorLog(); } catch(e) {}


// ── Schema Manager ────────────────────────────────────────────────────────────
const SCHEMA_OVERRIDE_PREFIX = 'bis_schema_overrides_';
const SCHEMA_BACKUP_PREFIX   = 'bis_schema_backup_';

let schemaOverrides = {};

function loadSchemaOverrides() {
  ['TX','IL'].forEach(m => {
    try {
      const raw = localStorage.getItem(SCHEMA_OVERRIDE_PREFIX + m);
      if (raw) schemaOverrides[m] = JSON.parse(raw);
    } catch(e) {}
  });
}

function saveSchemaOverrides(market) {
  try { localStorage.setItem(SCHEMA_OVERRIDE_PREFIX + market, JSON.stringify(schemaOverrides[market] || {})); } catch(e) {}
}

function snapshotSchemas(market) {
  try {
    const current = localStorage.getItem(SCHEMA_OVERRIDE_PREFIX + market) || '{}';
    localStorage.setItem(SCHEMA_BACKUP_PREFIX + market, current);
  } catch(e) {}
}

let queuedFiles = [];

function openSettingsToCap() {
  const panel = document.getElementById('settings-panel');
  const backdrop = document.getElementById('settings-backdrop');
  if (!panel) return;
  // Open the panel if not already open
  if (!panel.classList.contains('open')) {
    panel.classList.add('open');
    if (backdrop) backdrop.classList.add('open');
    renderSchemaInventory();
    try { renderLibrary(); } catch(e) {}
    try { updateLogCapUI(); } catch(e) {}
  }
  // Scroll to the cap section after a short paint delay
  setTimeout(function() {
    var sec = document.getElementById('log-cap-section');
    if (sec) {
      sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      // Flash the section border to draw the eye
      sec.style.outline = '2px solid var(--orange)';
      sec.style.borderRadius = '5px';
      setTimeout(function() {
        sec.style.transition = 'outline 0.5s';
        sec.style.outline = '2px solid transparent';
        setTimeout(function() { sec.style.outline = ''; sec.style.transition = ''; }, 600);
      }, 900);
    }
  }, 120);
}

// ── Cap proximity warning toast ───────────────────────────────────────────────
// Shows once per session when auto-log entries reach 80% of cap.
var _capWarnShown = false;
function maybeShowCapWarning(current, cap) {
  if (_capWarnShown) return;
  var pct = cap > 0 ? (current / cap) : 0;
  if (pct < 0.8) return;
  _capWarnShown = true;

  var atCap   = current >= cap;
  var pctLabel = Math.round(pct * 100) + '%';
  var color   = atCap ? 'var(--red)' : 'var(--orange)';
  var borderColor = atCap ? '#3d1515' : '#3a2a00';
  var bg      = atCap ? '#160b0b' : 'var(--orange-bg)';

  var toast = document.createElement('div');
  toast.id = 'cap-warn-toast';
  toast.style.cssText = [
    'position:fixed','bottom:16px','right:16px','z-index:9999',
    'background:' + bg,'border:1px solid ' + borderColor,
    'color:' + color,'font-family:var(--mono)','font-size:10px',
    'padding:10px 14px','border-radius:5px','max-width:340px',
    'line-height:1.7','box-shadow:0 4px 16px rgba(0,0,0,0.5)'
  ].join(';');

  var headline = atCap
    ? '&#9888; Error Log is full (' + current + '/' + cap + ' entries)'
    : '&#9888; Error Log is ' + pctLabel + ' full (' + current + '/' + cap + ' entries)';
  var body = atCap
    ? 'Oldest entries will be trimmed on the next validation run.'
    : 'Oldest entries will be trimmed when the cap is reached.';

  toast.innerHTML =
    '<div style="font-weight:700;margin-bottom:4px;">' + headline + '</div>' +
    '<div style="color:var(--text2);font-size:9.5px;">' + body + '</div>' +
    '<div style="margin-top:8px;display:flex;gap:10px;align-items:center;">' +
      '<span style="cursor:pointer;text-decoration:underline;font-size:9.5px;" onclick="openSettingsToCap();document.getElementById(\'cap-warn-toast\')&&document.getElementById(\'cap-warn-toast\').remove();">&#9881; Adjust cap in Settings</span>' +
      '<span style="cursor:pointer;color:var(--text3);font-size:9px;margin-left:auto;" onclick="this.closest(\'#cap-warn-toast\')||this.parentElement.parentElement.remove();">dismiss</span>' +
    '</div>';

  // Wire dismiss properly
  toast.querySelector('span:last-child').onclick = function() { toast.remove(); };

  document.body.appendChild(toast);
  // Auto-dismiss after 12 seconds
  setTimeout(function() { if (toast.parentNode) toast.remove(); }, 12000);
}

function toggleSettings() {
  const panel = document.getElementById('settings-panel');
  const backdrop = document.getElementById('settings-backdrop');
  if (!panel || !backdrop) return;
  const isOpen = panel.classList.contains('open');
  panel.classList.toggle('open', !isOpen);
  backdrop.classList.toggle('open', !isOpen);
  if (!isOpen) { renderSchemaInventory(); try { renderLibrary(); } catch(e) {} try { updateLogCapUI(); } catch(e) {} }
}

function onSchemaFilePick(event) {
  const files = Array.from(event.target.files);
  files.forEach(f => { if (!queuedFiles.find(q => q.name === f.name)) queuedFiles.push(f); });
  event.target.value = '';
  renderQueuedFiles();
}

function removeQueuedFile(name) {
  queuedFiles = queuedFiles.filter(f => f.name !== name);
  renderQueuedFiles();
}

function renderQueuedFiles() {
  const list = document.getElementById('queued-files-list');
  const btn = document.getElementById('apply-schemas-btn');
  if (!list) return;
  if (queuedFiles.length === 0) { list.innerHTML = ''; if (btn) btn.disabled = true; return; }
  if (btn) btn.disabled = false;
  list.innerHTML = queuedFiles.map(f =>
    '<div class="queued-file"><span class="queued-file-name">' + f.name + '</span><span class="queued-remove" onclick="removeQueuedFile(' + "'" + f.name + "'" + ')">✕</span></div>'
  ).join('');
}

function applyUploadedSchemas() {
  const marketSel = document.getElementById('upload-market').value;
  const customInput = document.getElementById('custom-market-input');
  const market = marketSel === 'custom' ? (customInput.value.trim().toUpperCase() || 'CUSTOM') : marketSel;
  const msgEl = document.getElementById('upload-message');

  if (queuedFiles.length === 0) {
    msgEl.className = 'settings-msg warn';
    msgEl.textContent = 'No files queued. Drop or select schema JSON files first.';
    return;
  }

  let pending = queuedFiles.length;
  let loaded = [];
  let errors = [];

  queuedFiles.forEach(function(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
      try {
        const schema = JSON.parse(e.target.result);
        const entityType = schema.entityType && schema.entityType.const;
        if (!entityType) throw new Error('Missing entityType.const — is this a contract schema?');
        if (!schema.properties) throw new Error('Missing properties — is this a contract schema?');
        loaded.push({ entityType: entityType, schema: schema, file: file.name });
      } catch(err) {
        errors.push(file.name + ': ' + err.message);
      }
      pending--;
      if (pending === 0) finalizeUpload(market, loaded, errors, msgEl);
    };
    reader.readAsText(file);
  });
}

function finalizeUpload(market, loaded, errors, msgEl) {
  if (loaded.length === 0) {
    msgEl.className = 'settings-msg err';
    msgEl.innerHTML = 'No valid schemas loaded.<br>' + errors.join('<br>');
    return;
  }
  snapshotSchemas(market);
  if (!schemaOverrides[market]) schemaOverrides[market] = {};
  loaded.forEach(function(item) { schemaOverrides[market][item.entityType] = item.schema; });
  saveSchemaOverrides(market);
  queuedFiles = [];
  renderQueuedFiles();
  renderSchemaInventory();
  var msg = 'Applied ' + loaded.length + ' schema(s) to ' + market + '.';
  if (errors.length > 0) msg += ' ' + errors.length + ' file(s) skipped: ' + errors.join('; ');
  msgEl.className = 'settings-msg ok';
  msgEl.textContent = msg;
  var rollbackSel = document.getElementById('rollback-market');
  if (rollbackSel && !Array.from(rollbackSel.options).find(function(o) { return o.value === market; })) {
    var opt = document.createElement('option');
    opt.value = market; opt.textContent = market;
    rollbackSel.appendChild(opt);
  }
}

function rollbackSchemas() {
  const market = document.getElementById('rollback-market').value;
  const msgEl = document.getElementById('rollback-message');
  try {
    const backup = localStorage.getItem(SCHEMA_BACKUP_PREFIX + market);
    if (!backup) { msgEl.className = 'settings-msg warn'; msgEl.textContent = 'No rollback snapshot found for ' + market + '.'; return; }
    snapshotSchemas(market);
    schemaOverrides[market] = JSON.parse(backup);
    saveSchemaOverrides(market);
    renderSchemaInventory();
    msgEl.className = 'settings-msg ok';
    msgEl.textContent = market + ' schemas rolled back to previous snapshot.';
  } catch(e) { msgEl.className = 'settings-msg err'; msgEl.textContent = 'Rollback failed: ' + e.message; }
}

function resetToBuiltIn() {
  const market = document.getElementById('rollback-market').value;
  const msgEl = document.getElementById('rollback-message');
  if (!confirm('Reset ' + market + ' to built-in schemas? All uploaded overrides will be removed.')) return;
  snapshotSchemas(market);
  schemaOverrides[market] = {};
  saveSchemaOverrides(market);
  renderSchemaInventory();
  msgEl.className = 'settings-msg ok';
  msgEl.textContent = market + ' reset to built-in schemas.';
}

function renderSchemaInventory() {
  const list = document.getElementById('schema-inventory-list');
  if (!list) return;
  const marketEl = document.getElementById('upload-market');
  const market = marketEl ? marketEl.value : 'TX';
  const overrides = schemaOverrides[market] || {};
  const rows = ALL_VALID.map(function(et) {
    const isOverridden = !!overrides[et];
    const version = isOverridden ? ((overrides[et].version && overrides[et].version.const) || 'custom') : (VALID_V3.includes(et) ? 'v3.0.0' : 'v0.1');
    const srcClass = isOverridden ? 'schema-inv-source-uploaded' : 'schema-inv-source-builtin';
    const srcLabel = isOverridden ? '● Uploaded' : '○ Built-in';
    return '<div class="schema-inv-row"><span class="schema-inv-entity">' + et + '</span><span class="schema-inv-version">' + version + '</span><span class="' + srcClass + '">' + srcLabel + '</span></div>';
  }).join('');
  const extras = Object.keys(overrides).filter(function(et) { return !ALL_VALID.includes(et); });
  const extraRows = extras.map(function(et) {
    const version = (overrides[et].version && overrides[et].version.const) || 'custom';
    return '<div class="schema-inv-row"><span class="schema-inv-entity" style="color:var(--orange)">' + et + ' ★</span><span class="schema-inv-version">' + version + '</span><span class="schema-inv-source-uploaded">● Uploaded (new)</span></div>';
  }).join('');
  list.innerHTML = rows + (extraRows ? '<div style="margin-top:6px;font-size:9px;color:var(--text3)">★ New entity types from upload</div>' + extraRows : '');
}

// Drag and drop
document.addEventListener('DOMContentLoaded', function() {
  const dz = document.getElementById('drop-zone');
  if (!dz) return;
  dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', function() { dz.classList.remove('drag-over'); });
  dz.addEventListener('drop', function(e) {
    e.preventDefault();
    dz.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer.files).filter(function(f) { return f.name.endsWith('.json'); });
    files.forEach(function(f) { if (!queuedFiles.find(function(q) { return q.name === f.name; })) queuedFiles.push(f); });
    renderQueuedFiles();
  });
  const uploadMarket = document.getElementById('upload-market');
  if (uploadMarket) {
    uploadMarket.addEventListener('change', function() {
      const custom = document.getElementById('custom-market-input');
      if (custom) custom.style.display = this.value === 'custom' ? 'block' : 'none';
    });
  }
});

try { loadSchemaOverrides(); } catch(e) {}

// ── Error Library ─────────────────────────────────────────────────────────────
const LIB_KEY = 'catch_error_library_v1';
const FIX_OWNERS = ['Odyssey','Publisher','D&I','BIS TPM','OCA'];
const MATCH_TYPES = ['field_value','field_name','contains'];
const TRUST_STATUSES = ['draft','reviewed','trusted'];

// Seed library with the known BIS errors (OCA-006 through OCA-011)
const DEFAULT_LIBRARY = [
  { id:'BIS-001', entityType:'di-texas-oca-court-charge', field:'entityType', matchType:'field_name', matchValue:'', translation:'The entity type name is singular — it does not exist. Use di-texas-oca-court-charges for new-record-event or di-texas-oca-court-criminal-charges for delete-record-event.', fixOwner:'Odyssey', action:'Update the EntityType field in the CMS mapping to the correct plural form based on the event type being submitted.', ref:'OCA-006, OCA-010' },
  { id:'BIS-002', entityType:'All', field:'county', matchType:'field_value', matchValue:'Casey', translation:'"Casey" is not a Texas county. This is test or demo data using a fake county name. Submissions with this county will never land in OCA.', fixOwner:'Odyssey', action:'Replace "Casey" with a real registered Texas county before resubmitting. Do not use fake county names in any environment.', ref:'OCA-007, OCA-008, OCA-009' },
  { id:'BIS-003', entityType:'di-texas-oca-court-charges', field:'plea_type', matchType:'field_value', matchValue:'Guilty', translation:'The plea_type value is in plain-English format. The schema requires the coded format "G - Guilty" — not just "Guilty".', fixOwner:'Odyssey', action:'Update the plea_type mapping to use the OCA code format: G - Guilty, N - Not Guilty, C - No Contest or Nolo Contendere, etc.', ref:'OCA-010' },
  { id:'BIS-004', entityType:'All', field:'party_race', matchType:'field_value', matchValue:'Not Available', translation:'"Not Available" is close but not exact. The approved value is "Not Available (Blank)" — the schema requires exact string match including the parenthetical.', fixOwner:'Odyssey', action:'Update the party_race mapping to send "Not Available (Blank)" exactly as written.', ref:'OCA-011' },
  { id:'BIS-005', entityType:'All', field:'filing_statute_citation', matchType:'field_name', matchValue:'', translation:'This field name is wrong. The correct field name is "statute_citation". The filing_ prefix does not exist in the contract schema.', fixOwner:'Odyssey', action:'Rename the field from filing_statute_citation to statute_citation in the CMS data mapping.', ref:'OCA-010' },
  { id:'BIS-006', entityType:'All', field:'filing_level_and_degree_of_prosecuted_offense', matchType:'field_name', matchValue:'', translation:'This field name is wrong. The correct field name is "level_and_degree_of_prosecuted_offense". The filing_ prefix does not exist in the contract schema.', fixOwner:'Odyssey', action:'Rename the field from filing_level_and_degree_of_prosecuted_offense to level_and_degree_of_prosecuted_offense in the CMS data mapping.', ref:'OCA-010' }
];

function loadLibrary() {
  try {
    const raw = localStorage.getItem(LIB_KEY);
    const base = raw ? JSON.parse(raw) : JSON.parse(JSON.stringify(DEFAULT_LIBRARY));
    return base.map(function(entry) {
      return Object.assign({
        trustStatus: 'trusted',
        notes: ''
      }, entry, {
        trustStatus: entry.trustStatus || 'trusted',
        notes: entry.notes || ''
      });
    });
  } catch(e) {
    return JSON.parse(JSON.stringify(DEFAULT_LIBRARY)).map(function(entry) {
      entry.trustStatus = entry.trustStatus || 'trusted';
      entry.notes = entry.notes || '';
      return entry;
    });
  }
}

function saveLibrary(entries) {
  try { localStorage.setItem(LIB_KEY, JSON.stringify(entries)); } catch(e) {}
}

function generateLibId() {
  const entries = loadLibrary();
  const nums = entries.map(function(e) {
    const m = e.id.match(/BIS-(\d+)/);
    return m ? parseInt(m[1]) : 0;
  });
  const next = nums.length > 0 ? Math.max.apply(null, nums) + 1 : 1;
  return 'BIS-' + String(next).padStart(3, '0');
}

function renderLibrary() {
  const list = document.getElementById('lib-entries-list');
  if (!list) return;
  const allEntries = loadLibrary();
  const q = (document.getElementById('lib-search') ? (document.getElementById('lib-search').value || '').toLowerCase() : '');
  const entries = q ? allEntries.filter(function(e) {
    return [e.field||'', e.translation||'', e.entityType||'', e.fixOwner||'', e.matchValue||'', e.action||'', e.id||'', e.trustStatus||'', e.notes||''].join(' ').toLowerCase().includes(q);
  }) : allEntries;
  if (allEntries.length === 0) {
    list.innerHTML = '<div class="lib-empty">No entries yet. Click + New Entry to add one.</div>';
    return;
  }
  if (entries.length === 0) {
    list.innerHTML = '<div class="lib-empty">No entries match &ldquo;' + escHtml(q) + '&rdquo;.</div>';
    return;
  }
  const totalLabel = q ? ' <span style="color:var(--text3);font-size:9px;">(' + entries.length + ' of ' + allEntries.length + ')</span>' : '';
  list.innerHTML = (q ? '<div style="font-size:9.5px;color:var(--text3);margin-bottom:6px;">Showing ' + entries.length + ' of ' + allEntries.length + ' entries</div>' : '') + entries.map(function(entry, idx) {
  const realIdx = allEntries.indexOf(entry);
    const ownColor = { 'Odyssey':'var(--orange)', 'Publisher':'var(--cyan)', 'D&I':'var(--purple)', 'BIS TPM':'var(--blue)', 'OCA':'var(--green)' }[entry.fixOwner] || 'var(--text2)';
    const trustLabel = (entry.trustStatus || 'trusted').toUpperCase();
    return '<div class="lib-entry" id="lib-entry-' + idx + '">' +
      '<div class="lib-entry-header" onclick="toggleLibEntry(' + idx + ')">' +
        '<span class="lib-entry-id">' + (entry.id||'') + '</span>' +
        '<span class="lib-match-badge">' + (entry.matchType||'') + '</span>' +
        '<span class="lib-entry-field">' + (entry.field||'') + (entry.matchValue ? ' = "' + entry.matchValue + '"' : '') + '</span>' +
        '<span class="lib-match-badge">' + trustLabel + '</span>' +
        '<span class="lib-entry-owner" style="color:' + ownColor + ';border-color:' + ownColor + '">' + (entry.fixOwner||'') + '</span>' +
      '</div>' +
      '<div class="lib-entry-body" id="lib-body-' + realIdx + '">' +
        '<div class="lib-form-row-2">' +
          '<div class="lib-form-row"><div class="lib-form-label">Entry ID</div><input class="lib-form-input" id="lib-' + realIdx + '-id" value="' + esc(entry.id) + '" /></div>' +
          '<div class="lib-form-row"><div class="lib-form-label">Fix Owner</div><select class="lib-form-select" id="lib-' + realIdx + '-owner">' + FIX_OWNERS.map(function(o) { return '<option' + (o===entry.fixOwner?' selected':'') + '>' + o + '</option>'; }).join('') + '</select></div>' +
        '</div>' +
        '<div class="lib-form-row-2">' +
          '<div class="lib-form-row"><div class="lib-form-label">Entity Type</div><input class="lib-form-input" id="lib-' + realIdx + '-et" value="' + esc(entry.entityType) + '" placeholder="All" /></div>' +
          '<div class="lib-form-row"><div class="lib-form-label">Field</div><input class="lib-form-input" id="lib-' + realIdx + '-field" value="' + esc(entry.field) + '" /></div>' +
        '</div>' +
        '<div class="lib-form-row-2">' +
          '<div class="lib-form-row"><div class="lib-form-label">Match Type</div><select class="lib-form-select" id="lib-' + realIdx + '-match">' + MATCH_TYPES.map(function(m) { return '<option' + (m===entry.matchType?' selected':'') + '>' + m + '</option>'; }).join('') + '</select></div>' +
          '<div class="lib-form-row"><div class="lib-form-label">Match Value (leave blank for field_name)</div><input class="lib-form-input" id="lib-' + realIdx + '-val" value="' + esc(entry.matchValue||'') + '" /></div>' +
        '</div>' +
        '<div class="lib-form-row-2">' +
          '<div class="lib-form-row"><div class="lib-form-label">Trust Status</div><select class="lib-form-select" id="lib-' + realIdx + '-trust">' + TRUST_STATUSES.map(function(t) { return '<option' + (t===entry.trustStatus?' selected':'') + '>' + t + '</option>'; }).join('') + '</select></div>' +
          '<div class="lib-form-row"><div class="lib-form-label">Reference (e.g. OCA-010)</div><input class="lib-form-input" id="lib-' + realIdx + '-ref" value="' + esc(entry.ref||'') + '" /></div>' +
        '</div>' +
        '<div class="lib-form-row"><div class="lib-form-label">Plain-English Translation</div><textarea class="lib-form-textarea" id="lib-' + realIdx + '-trans">' + esc(entry.translation) + '</textarea></div>' +
        '<div class="lib-form-row"><div class="lib-form-label">Recommended Action</div><textarea class="lib-form-textarea" id="lib-' + realIdx + '-action">' + esc(entry.action) + '</textarea></div>' +
        '<div class="lib-form-row"><div class="lib-form-label">Notes</div><textarea class="lib-form-textarea" id="lib-' + realIdx + '-notes">' + esc(entry.notes||'') + '</textarea></div>' +
        '<div class="lib-entry-actions">' +
          '<button class="lib-save-btn" onclick="saveLibEntry(' + realIdx + ')">Save</button>' +
          '<button class="lib-delete-btn" onclick="deleteLibEntry(' + realIdx + ')">Delete</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function toggleLibEntry(idx) {
  const body = document.getElementById('lib-body-' + idx);
  if (body) body.classList.toggle('open');
}

function addLibraryEntry() {
  const entries = loadLibrary();
  entries.push({ id: generateLibId(), entityType:'All', field:'', matchType:'field_value', matchValue:'', translation:'', fixOwner:'Odyssey', action:'', ref:'', trustStatus:'draft', notes:'' });
  saveLibrary(entries);
  renderLibrary();
  // Open the new entry
  const newIdx = entries.length - 1;
  setTimeout(function() { toggleLibEntry(newIdx); }, 50);
}

function saveLibEntry(idx) {
  const entries = loadLibrary();
  entries[idx] = {
    id:          document.getElementById('lib-' + idx + '-id').value.trim(),
    entityType:  document.getElementById('lib-' + idx + '-et').value.trim() || 'All',
    field:       document.getElementById('lib-' + idx + '-field').value.trim(),
    matchType:   document.getElementById('lib-' + idx + '-match').value,
    matchValue:  document.getElementById('lib-' + idx + '-val').value.trim(),
    trustStatus: document.getElementById('lib-' + idx + '-trust').value,
    translation: document.getElementById('lib-' + idx + '-trans').value.trim(),
    fixOwner:    document.getElementById('lib-' + idx + '-owner').value,
    action:      document.getElementById('lib-' + idx + '-action').value.trim(),
    ref:         document.getElementById('lib-' + idx + '-ref').value.trim(),
    notes:       document.getElementById('lib-' + idx + '-notes').value.trim()
  };
  saveLibrary(entries);
  renderLibrary();
  const msg = document.getElementById('lib-message');
  if (msg) { msg.className = 'settings-msg ok'; msg.textContent = entries[idx].id + ' saved.'; setTimeout(function() { msg.textContent = ''; msg.className = ''; }, 2000); }
}

function deleteLibEntry(idx) {
  const entries = loadLibrary();
  if (!confirm('Delete ' + (entries[idx].id||'this entry') + '?')) return;
  entries.splice(idx, 1);
  saveLibrary(entries);
  renderLibrary();
}

async function exportLibrary() {
  const entries = loadLibrary();
  const blob = new Blob([JSON.stringify(entries, null, 2)], {type:'application/json'});
  dlFile(blob, 'CATCH_Error_Library_' + new Date().toISOString().slice(0,10) + '.json');
}

function importLibrary(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const imported = JSON.parse(e.target.result);
      if (!Array.isArray(imported)) { alert('Invalid file — expected a JSON array of library entries.'); return; }
      const existing = loadLibrary();
      const existingIds = new Set(existing.map(function(e) { return e.id; }));
      const added = imported.filter(function(e) { return !existingIds.has(e.id); });
      const merged = existing.concat(added);
      saveLibrary(merged);
      renderLibrary();
      const msg = document.getElementById('lib-message');
      if (msg) { msg.className = 'settings-msg ok'; msg.textContent = 'Imported ' + added.length + ' new entries. ' + (imported.length - added.length) + ' duplicate IDs skipped.'; }
    } catch(err) { alert('Could not read file: ' + err.message); }
    event.target.value = '';
  };
  reader.readAsText(file);
}

// ── Library matching ───────────────────────────────────────────────────────────
// Called by getTranslation — checks library for a match before generic fallback
function matchLibraryEntry(field, msg, entity) {
  const entries = loadLibrary();
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    // Entity type filter
    if (e.entityType && e.entityType !== 'All' && e.entityType !== entity.entityType) continue;
    // Field filter
    if (e.field && e.field !== field) continue;
    // Match type
    var matched = false;
    if (e.matchType === 'field_name') {
      matched = true; // field already matched above
    } else if (e.matchType === 'field_value') {
      var val = entity[field];
      matched = val !== undefined && String(val) === String(e.matchValue);
    } else if (e.matchType === 'contains') {
      var val2 = entity[field];
      matched = val2 !== undefined && String(val2).toLowerCase().indexOf(String(e.matchValue).toLowerCase()) !== -1;
    }
    if (matched && (e.translation || e.action)) {
      var result = '';
      if (e.translation) result += e.translation;
      if (e.action) result += (result ? ' ' : '') + e.action;
      return result;
    }
  }
  return null;
}

try { renderLibrary(); } catch(e) {}



// ── Error Catalog ─────────────────────────────────────────────────────────────
// Deduplicated error catalog: one row per unique (field + msg + entityType)
// Each row shows all publishers who sent it, occurrence count, first/last seen.

var _catalogData = [];

function buildCatalogData() {
  const runs = loadHistory();
  if (!runs || runs.length === 0) return [];

  // Key: field + errorCategory + entityType
  // Grouping by category rather than full message collapses noise like
  // "received string \"30\"" / "received string \"31\"" into one row.
  const map = {};

  // Extract the specific bad value from common error message patterns
  function extractBadValue(msg) {
    // Matches: Invalid value "X", received string "X", or leading "X" is not a valid county
    const m = msg.match(/Invalid value ["\u201c"']([^"\u201c"']+)["\u201c"']/) ||
              msg.match(/received string ["\u201c"']([^"\u201c"']+)["\u201c"']/) ||
              msg.match(/^["\u201c"']([^"\u201c"']+)["\u201c"']/);
    return m ? m[1] : null;
  }

  // Strip the specific bad value to produce a canonical template for dedup
  function canonicalMsg(msg) {
    return msg
      .replace(/Invalid value ["\u201c"'][^"\u201c"']+["\u201c"']\.?\s*/g, 'Invalid value <BAD_VALUE>. ')
      .replace(/received string ["\u201c"'][^"\u201c"']+["\u201c"']/g, 'received string <BAD_VALUE>')
      .replace(/^["\u201c"'][^"\u201c"']+["\u201c"']\s+is not a valid county[^.]*/g, '<BAD_VALUE> is not a valid county')
      .replace(/^["\u201c"'][^"\u201c"']+["\u201c"']\s+is not a Texas county[^.]*/g, '<BAD_VALUE> is not a Texas county')
      .trim();
  }

  
  runs.forEach(run => {
    const runPublisher = (run.publisher || '').trim();
    const IL_VENDOR_NAMES = ['Journal Technologies', 'Goodin & Associates', 'DuPage County', 'JANO Justice Systems', 'Tyler Technologies (Enterprise Justice)', 'Justice Systems', 'Tracker - Solution Specialties'];
    const publisherIsIL = IL_VENDOR_NAMES.some(v => runPublisher.includes(v));
    const market = (run.market && run.market !== 'TX') ? run.market
                 : publisherIsIL ? 'IL'
                 : run.market || 'TX';
    const ts = run.timestamp || '';
    const envelopeId = run.envelopeId || '';
    const runSubmittedAt = run.envelopeSubmittedAt || null;

    (run.errors || []).forEach(e => {
      const field = e.field || '';
      const msg = e.msg || '';
      const entityType = e.entityType || '';
      const category = classifyErrorCatalog(msg);
      const key = field + '|||' + category;

      const badVal = extractBadValue(msg);
      const template = canonicalMsg(msg);

      if (!map[key]) {
        map[key] = {
          field,
          msg: template,          // canonical (value-stripped) message
          entityType,
          entityTypes: new Set(), // all affected entity types
          errorCategory: category,
          count: 0,
          badValues: new Set(),   // distinct bad values seen
          publishers: new Set(),
          markets: new Set(),
          envelopeIds: new Set(),
          firstSeen: ts,
          submittedAt: runSubmittedAt,
          lastSeen: ts,
          ref: e.ref || '',
          translation: e.translation || '',
        };
      }

      const entry = map[key];
      entry.count++;
      if (badVal) entry.badValues.add(badVal);
      if (entityType) entry.entityTypes.add(entityType);
      const errPublisher = (e.publisher && e.publisher.trim()) ? e.publisher.trim() : (runPublisher || '(unknown)');
      entry.publishers.add(errPublisher);
      entry.markets.add(market);
      if (envelopeId) entry.envelopeIds.add(envelopeId);
      if (ts && ts < entry.firstSeen) {
        entry.firstSeen = ts;
        entry.submittedAt = runSubmittedAt;
      }
      if (ts && ts > entry.lastSeen) entry.lastSeen = ts;
      // Keep the most descriptive translation (prefer ones with OCA refs)
      if (!entry.translation && e.translation) entry.translation = e.translation;
      if (e.ref && !entry.ref) entry.ref = e.ref;
    });
  });

  return Object.values(map)
    .map(e => ({
      ...e,
      badValues: Array.from(e.badValues).sort(),
      entityTypes: Array.from(e.entityTypes).sort(),
      publishers: Array.from(e.publishers).sort(),
      markets: Array.from(e.markets).sort(),
      envelopeIds: Array.from(e.envelopeIds),
    }))
    .sort((a, b) => b.count - a.count);
}

function classifyErrorCatalog(msg) {
  if (!msg) return 'Other';
  if (msg.includes('Missing') || msg.includes('missing') || msg.includes('Required') || msg.includes('required')) return 'Missing Field';
  if (msg.includes('not in the allowed') || msg.includes('Invalid value') || msg.includes('not a valid') || msg.includes('not in the valid') || msg.includes('not a recognized')) return 'Enum / Invalid Value';
  if (msg.includes('Must be number') || msg.includes('must be a number') || msg.includes('number, not a string')) return 'Type Error';
  if (msg.includes('additionalProperties') || msg.includes('Additional property')) return 'Extra Field';
  if (msg.includes('Wrong field name')) return 'Wrong Field Name';
  if (msg.includes('entityType') && (msg.includes('not in') || msg.includes('not a recognized') || msg.includes('Invalid'))) return 'Invalid Entity Type';
  return 'Other';
}

var _catalogFiltered = [];

function renderCatalog() {
  _catalogData = buildCatalogData();
  _catalogFiltered = _catalogData;
  _renderCatalogStats();
  if (typeof updateTrendsSpotlights === 'function') updateTrendsSpotlights();
  _applyFilterAndRender();
}

function filterCatalog() {
  if (!_catalogData.length) return;
  const q = (document.getElementById('catalog-search').value || '').toLowerCase();
  const mkt = (document.getElementById('catalog-market-filter').value || '').toUpperCase();

  _catalogFiltered = _catalogData.filter(e => {
    const matchMkt = !mkt || e.markets.includes(mkt);
    const matchQ = !q || [
      e.field,
      e.msg,
      e.entityType,
      ...(e.publishers || []),
      ...(e.envelopeIds || []),
      ...(e.badValues || []),
      ...(e.entityTypes || []),
      e.errorCategory,
      e.firstSeen,
      e.submittedAt
    ].join(' ').toLowerCase().includes(q);
    return matchMkt && matchQ;
  });

  if (typeof updateTrendsSpotlights === 'function') updateTrendsSpotlights();
  _applyFilterAndRender();
}

function _renderCatalogStats() {
  const statsEl = document.getElementById('catalog-stats');
  if (!statsEl || !_catalogData.length) return;

  const totalOccurrences = _catalogData.reduce((s, e) => s + e.count, 0);
  const uniquePublishers = new Set(_catalogData.flatMap(e => e.publishers)).size;
  const uniqueFields = new Set(_catalogData.map(e => e.field)).size;
  const cats = {};
  _catalogData.forEach(e => { cats[e.errorCategory] = (cats[e.errorCategory] || 0) + e.count; });
  const topCat = Object.entries(cats).sort((a, b) => b[1] - a[1])[0];

  const stat = (label, val, colorClass) => `<div class="trends-kpi-card">
    <span class="trends-kpi-label">${label}</span>
    <span class="trends-kpi-value ${colorClass || ''}">${val}</span>
  </div>`;

  statsEl.innerHTML =
    stat('Unique Errors', _catalogData.length.toLocaleString(), '') +
    stat('Total Occurrences', totalOccurrences.toLocaleString(), '') +
    stat('Publishers', uniquePublishers, '') +
    stat('Fields Affected', uniqueFields, '') +
    (topCat ? stat('Most Common Type', topCat[0], 'emphasis') : '');
}

const CAT_COLORS = {
  'Missing Field': '#e06c75',
  'Enum / Invalid Value': '#e5c07b',
  'Type Error': '#61afef',
  'Extra Field': '#c678dd',
  'Wrong Field Name': '#56b6c2',
  'Invalid Entity Type': '#d19a66',
  'Other': '#5c6370',
};

function _applyFilterAndRender() {
  const container = document.getElementById('catalog-table-container');
  if (!container) return;
  const activeEl = document.activeElement;
  const activeId = activeEl && activeEl.id ? activeEl.id : '';
  const selectionStart = activeEl && typeof activeEl.selectionStart === 'number' ? activeEl.selectionStart : null;
  const selectionEnd = activeEl && typeof activeEl.selectionEnd === 'number' ? activeEl.selectionEnd : null;

  let html = `<div class="trends-table-toolbar">
    <div class="trends-table-title">Trend table</div>
    <div class="trends-table-tools">
      <input id="catalog-search-inline" class="envelope-input" placeholder="Search field, message, publisher, envelope, entity…" value="${escHtml(document.getElementById('catalog-search') ? document.getElementById('catalog-search').value : '')}" oninput="document.getElementById('catalog-search').value=this.value;filterCatalog()" style="width:360px;font-size:10.5px;" />
      <select id="catalog-market-filter-inline" onchange="document.getElementById('catalog-market-filter').value=this.value;filterCatalog()" style="background:var(--bg2);border:1px solid var(--border2);color:var(--text2);font-size:10.5px;padding:4px 8px;border-radius:4px;font-family:var(--sans);">
        <option value="" ${!(document.getElementById('catalog-market-filter') && document.getElementById('catalog-market-filter').value) ? 'selected' : ''}>All Markets</option>
        <option value="TX" ${(document.getElementById('catalog-market-filter') && document.getElementById('catalog-market-filter').value === 'TX') ? 'selected' : ''}>TX</option>
        <option value="IL" ${(document.getElementById('catalog-market-filter') && document.getElementById('catalog-market-filter').value === 'IL') ? 'selected' : ''}>IL</option>
      </select>
      <button class="export-btn" onclick="exportCatalogCSV()">↓ Export CSV</button>
      <button class="export-btn" onclick="renderCatalog()">↺ Refresh</button>
    </div>
  </div>
  <div style="padding:12px 20px 0;font-size:10px;color:var(--text3);">Showing ${_catalogFiltered.length.toLocaleString()} of ${_catalogData.length.toLocaleString()} unique errors</div>`;

  if (!_catalogFiltered.length) {
    html += `<div style="padding:20px;font-size:11px;color:var(--text3);">No errors match the current filter.</div>`;
    container.innerHTML = html;
    if (activeId === 'catalog-search-inline' || activeId === 'catalog-search') {
      const refreshedInlineInput = document.getElementById('catalog-search-inline');
      if (refreshedInlineInput) {
        refreshedInlineInput.focus();
        if (selectionStart !== null && selectionEnd !== null) {
          refreshedInlineInput.setSelectionRange(selectionStart, selectionEnd);
        }
      }
    }
    return;
  }

  html += `<div style="overflow-x:auto;padding:12px 20px 0;">
  <table style="width:100%;border-collapse:collapse;font-size:10.5px;">
    <thead>
      <tr style="background:var(--bg3);border-bottom:2px solid var(--border2);position:sticky;top:0;z-index:1;">
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);white-space:nowrap;min-width:84px;">Details</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);white-space:nowrap;min-width:140px;">Field</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:160px;">Publisher</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:90px;">Category</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:180px;">Description</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:110px;">Bad Values</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:100px;">Entity Type</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:140px;">Fix Owner</th>
        <th style="text-align:right;padding:7px 10px;font-weight:600;color:var(--text3);">Count</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);white-space:nowrap;">First Seen</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--orange);white-space:nowrap;">Submitted</th>
        <th style="text-align:left;padding:7px 10px;font-weight:600;color:var(--text3);min-width:100px;">Envelopes</th>
      </tr>
    </thead>
    <tbody>`;

  _catalogFiltered.forEach((e, idx) => {
    const rowBg = idx % 2 === 0 ? 'var(--bg)' : 'var(--bg2)';
    const catColor = CAT_COLORS[e.errorCategory] || '#5c6370';

    // Extract fix owner from translation text
    function extractFixOwner(trans) {
      if (!trans) return '—';
      const m = trans.match(/[Ff]ix owner[:\s]+([^.]+)/);
      if (m) return m[1].trim().replace(/\.$/, '');
      if (/D&I ticket|Submit.*ticket/i.test(trans)) return 'D&I ticket — OCA';
      return '—';
    }
    const fixOwner = extractFixOwner(e.translation);

    // Publisher + market combined pill
    const pubMarket = e.publishers.map((p, pi) => {
      const mkt = e.markets[pi] || e.markets[0] || '';
      return `<span style="display:inline-block;background:rgba(69,123,157,0.10);color:var(--text);border:1px solid rgba(69,123,157,0.16);border-radius:999px;padding:4px 10px;font-size:9px;margin:1px 6px 1px 0;white-space:nowrap;font-weight:700;">${escHtml(p)}${mkt ? ' <span style=\'color:var(--text2);font-weight:600;\'>&middot; ' + escHtml(mkt) + '</span>' : ''}</span>`;
    }).join('');

    const etDisplay = e.entityType;

    // Description: canonical message with first bad value subbed in
    const rawMsg = e.msg.replace('<BAD_VALUE>', e.badValues && e.badValues.length ? '"' + e.badValues[0] + '"' : '<value>');
    const msgDisplay = rawMsg.length > 100 ? rawMsg.slice(0, 100) + '…' : rawMsg;

    // Bad values — compact chips
    const badValsDisplay = (e.badValues && e.badValues.length > 0)
      ? e.badValues.slice(0, 4).map(v => `<span style="display:inline-block;background:var(--red-bg);color:var(--red);border:1px solid #3d1515;border-radius:3px;padding:0px 4px;font-size:9px;font-family:var(--mono);margin:1px 2px 1px 0;white-space:nowrap;">${escHtml(String(v).length > 14 ? String(v).slice(0,14)+'…' : String(v))}</span>`).join('') + (e.badValues.length > 4 ? `<span style="font-size:9px;color:var(--text3);">+${e.badValues.length - 4}</span>` : '')
      : '<span style="color:var(--text3);font-size:9px;">—</span>';

    // Envelope IDs — just count + first ID as tooltip anchor
    const envIds = e.envelopeIds || [];
    const envDisplay = envIds.length === 0 ? '<span style="color:var(--text3);font-size:9px;">—</span>'
      : `<span style="font-size:9px;color:var(--text2);font-family:var(--mono);" title="${escHtml(envIds.join('\n'))}">${escHtml(envIds[0].slice(0,8))}…${envIds.length > 1 ? ' <span style=\'color:var(--text3);\'>+' + (envIds.length - 1) + '</span>' : ''}</span>`;

    html += `<tr style="background:${rowBg};border-bottom:1px solid var(--border);" title="${escHtml(rawMsg)}">
      <td style="padding:7px 10px;vertical-align:top;">
        <button class="trends-detail-btn" type="button" onclick="openTrendDetail(${idx})">View</button>
      </td>
      <td style="padding:7px 10px;font-family:var(--mono);color:var(--cyan);font-size:10px;vertical-align:top;white-space:nowrap;">${escHtml(e.field)}</td>
      <td style="padding:7px 10px;vertical-align:top;">${pubMarket}</td>
      <td style="padding:7px 10px;vertical-align:top;"><span style="display:inline-block;background:${catColor}22;color:${catColor};border:1px solid ${catColor}44;border-radius:3px;padding:2px 7px;font-size:9px;white-space:nowrap;">${escHtml(e.errorCategory)}</span></td>
      <td style="padding:7px 10px;color:var(--text2);font-size:10px;vertical-align:top;max-width:220px;" title="${escHtml(rawMsg)}">${escHtml(msgDisplay)}</td>
      <td style="padding:7px 10px;vertical-align:top;">${badValsDisplay}</td>
      <td style="padding:7px 10px;color:var(--text2);font-size:9.5px;vertical-align:top;">
        ${(e.entityTypes && e.entityTypes.length > 1
          ? e.entityTypes.map(et => `<span style="display:block;font-size:9px;color:var(--text2);white-space:nowrap;">${escHtml(et)}</span>`).join('')
          : `<span style="font-size:9.5px;color:var(--text2);">${escHtml(etDisplay)}</span>`)}
      </td>
      <td style="padding:7px 10px;color:var(--text2);font-size:9.5px;vertical-align:top;max-width:160px;">${escHtml(fixOwner)}</td>
      <td style="padding:7px 10px;text-align:right;font-weight:700;color:${e.count >= 500 ? 'var(--red)' : e.count >= 100 ? 'var(--orange)' : 'var(--text2)'};vertical-align:top;white-space:nowrap;">${e.count.toLocaleString()}</td>
      <td style="padding:7px 10px;font-size:9px;white-space:nowrap;vertical-align:top;color:var(--text2);">${escHtml(e.firstSeen || '—')}</td>
      <td style="padding:7px 10px;font-size:9px;white-space:nowrap;vertical-align:top;">${e.submittedAt ? `<span style='color:var(--orange);'>⬆ ${escHtml(e.submittedAt)}</span>` : `<span style='color:var(--text3);'>${escHtml(e.firstSeen)}</span>`}</td>
      <td style="padding:7px 10px;vertical-align:top;">${envDisplay}</td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += `<div style="margin-top:10px;font-size:9.5px;color:var(--text3);">${_catalogFiltered.length} issues · sorted by occurrence count · generated ${new Date().toLocaleString('en-US',{month:'2-digit',day:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'})}</div>`;

  container.innerHTML = html;
  if (activeId === 'catalog-search-inline' || activeId === 'catalog-search') {
    const refreshedInlineInput = document.getElementById('catalog-search-inline');
    if (refreshedInlineInput) {
      refreshedInlineInput.focus();
      if (selectionStart !== null && selectionEnd !== null) {
        refreshedInlineInput.setSelectionRange(selectionStart, selectionEnd);
      }
    }
  }
}

// ── Click-to-jump: error item → field in JSON textarea ───────────────────────
function parseTrendRunDate(run) {
  if (!run) return null;
  if (run.analysedAt) {
    var iso = new Date(run.analysedAt);
    if (!isNaN(iso.getTime())) return iso;
  }
  if (run.timestamp) {
    var parsed = new Date(run.timestamp);
    if (!isNaN(parsed.getTime())) return parsed;
  }
  return null;
}

function runErrorMatchesTrendFilters(err, run, searchText, marketFilter) {
  var normalizedMarket = (marketFilter || '').trim();
  if (normalizedMarket) {
    var runMarket = (run && run.market) ? run.market : 'TX';
    if (runMarket !== normalizedMarket) return false;
  }
  if (!searchText) return true;
  var category = classifyErrorCatalog((err && err.msg) || '');
  var badValue = ((err && err.msg) || '').match(/Invalid value ["\u201c"']([^"\u201c"']+)["\u201c"']/) ||
    ((err && err.msg) || '').match(/received string ["\u201c"']([^"\u201c"']+)["\u201c"']/) ||
    ((err && err.msg) || '').match(/^["\u201c"']([^"\u201c"']+)["\u201c"']/);
  var haystack = [
    err && err.field || '',
    err && err.msg || '',
    err && err.entityType || '',
    err && err.translation || '',
    run && run.publisher || '',
    run && run.envelopeId || '',
    run && run.market || '',
    run && run.envelopeSubmittedAt || '',
    run && run.timestamp || '',
    category || '',
    badValue ? badValue[1] : ''
  ].join(' ').toLowerCase();
  return haystack.indexOf(searchText) !== -1;
}

function jumpToField(fieldName, entityIdx) {
  var ta = document.getElementById('input-area');
  if (!ta) return;

  // If textarea is empty, nothing to jump to
  var raw = ta.value.trim();
  if (!raw) {
    _showJumpMsg('Payload is empty — paste a payload and run validation first.', 'warn');
    return;
  }

  // Format to pretty JSON so every field is on its own line
  try {
    var pretty = JSON.stringify(JSON.parse(raw), null, 2);
    if (pretty !== ta.value) ta.value = pretty;
  } catch(e) {}

  var text = ta.value;
  var needle = '"' + fieldName + '"';
  var positions = [];
  var p = 0;

  // Find all positions where this is a JSON key (followed by colon)
  while ((p = text.indexOf(needle, p)) !== -1) {
    var after = text.slice(p + needle.length);
    if (/^\s*:/.test(after)) positions.push(p);
    p += needle.length;
  }
  // Fallback: any occurrence
  if (positions.length === 0) {
    p = 0;
    while ((p = text.indexOf(needle, p)) !== -1) {
      positions.push(p);
      p += needle.length;
    }
  }

  if (positions.length === 0) {
    _showJumpMsg('"' + fieldName + '" not in payload — may be a missing required field.', 'warn');
    // Flash textarea border red
    ta.style.border = '2px solid var(--red)';
    setTimeout(function() { ta.style.border = ''; }, 800);
    return;
  }

  var targetPos = positions[Math.min(entityIdx, positions.length - 1)];
  var lineEnd   = text.indexOf('\n', targetPos + needle.length);
  var selectEnd = lineEnd !== -1 ? lineEnd : text.length;

  // Count lines before target to compute scroll position
  var linesBefore = text.substring(0, targetPos).split('\n').length - 1;
  var lineHeightPx = parseFloat(window.getComputedStyle(ta).lineHeight) || (11.5 * 1.7);
  var paddingTop   = parseFloat(window.getComputedStyle(ta).paddingTop) || 14;
  var desiredScrollTop = Math.max(0, paddingTop + (linesBefore * lineHeightPx) - Math.floor(ta.clientHeight / 3));

  // Switch to validate tab if not already active, then jump
  var validatePanel = document.getElementById('panel-validate');
  if (validatePanel && !validatePanel.classList.contains('active')) {
    switchTab('validate');
  }

  // Apply selection and scroll synchronously
  ta.focus();
  ta.setSelectionRange(targetPos, selectEnd);
  ta.scrollTop = desiredScrollTop;

  // Use setTimeout(0) to re-apply scrollTop after browser processes focus
  setTimeout(function() {
    ta.scrollTop = desiredScrollTop;
    // Flash textarea border blue — border overrides outline:none
    ta.style.border = '2px solid var(--blue)';
    setTimeout(function() { ta.style.border = ''; }, 1200);
  }, 0);

  _showJumpMsg('Jumped to "' + fieldName + '" — line ' + (linesBefore + 1), 'ok');
}

function _showJumpMsg(msg, type) {
  var existing = document.getElementById('jump-toast');
  if (existing) existing.remove();
  var t = document.createElement('div');
  t.id = 'jump-toast';
  var bg = type === 'ok' ? 'var(--bg3)' : 'var(--red-bg)';
  var border = type === 'ok' ? 'var(--border2)' : '#3d1515';
  var color = type === 'ok' ? 'var(--text2)' : 'var(--red)';
  t.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:9999;background:' + bg + ';border:1px solid ' + border + ';color:' + color + ';font-family:var(--mono);font-size:10px;padding:7px 16px;border-radius:5px;white-space:nowrap;pointer-events:none;';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(function() { if (t.parentNode) t.remove(); }, 2500);
}

function exportCatalogCSV() {
  // Use filtered data if a filter is active, otherwise full catalog
  const data = (_catalogFiltered.length ? _catalogFiltered : _catalogData);
  if (!data.length) {
    alert('No catalog data to export. Run a validation first, then click ↺ Refresh on the Error Catalog tab.');
    return;
  }

  const val = v => '"' + String(v || '').replace(/"/g, '""') + '"';
  const header = ['Field','Publisher','Market','Error Category','Description','Bad Values','Entity Type','Fix Owner','Occurrence Count','OCA Ref','Submitted At (AEP)','Envelope IDs'];
  const rows = [header];

  data.forEach(e => {
    const csvFixOwner = (function(t) {
      if (!t) return '';
      const m = t.match(/[Ff]ix owner[:\s]+([^.]+)/);
      if (m) return m[1].trim();
      if (/D&I ticket|Submit.*ticket/i.test(t)) return 'D&I ticket — OCA';
      return '';
    })(e.translation);
    const csvMsg = (e.msg || '').replace('<BAD_VALUE>', (e.badValues && e.badValues.length) ? e.badValues[0] : '<value>');
    rows.push([
      val(e.field),
      val(e.publishers.join('; ')),
      val(e.markets.join('; ')),
      val(e.errorCategory),
      val(csvMsg),
      val((e.badValues || []).join('; ')),
      val((e.entityTypes && e.entityTypes.length ? e.entityTypes.join('; ') : e.entityType)),
      val(csvFixOwner),
      e.count,
      val(e.ref),
      val(e.submittedAt || e.firstSeen),
      val(e.envelopeIds.slice(0, 10).join('; ') + (e.envelopeIds.length > 10 ? ' (+' + (e.envelopeIds.length - 10) + ' more)' : '')),
    ]);
  });

  const csv = rows.map(r => r.join(',')).join('\n');
  const suffix = (_catalogFiltered.length && _catalogFiltered.length !== _catalogData.length) ? '_filtered' : '';
  dlFile(new Blob(['\uFEFF' + csv], {type:'text/csv;charset=utf-8'}), 'CATCH_Error_Catalog' + suffix + '_' + new Date().toISOString().slice(0,10) + '.csv');
}

function buildTrendDetailText(entry) {
  if (!entry) return '';
  const lines = [
    'Field: ' + (entry.field || '—'),
    'Category: ' + (entry.errorCategory || '—'),
    'Occurrences: ' + (entry.count != null ? entry.count : '—'),
    'Publishers: ' + ((entry.publishers || []).join(', ') || '—'),
    'Markets: ' + ((entry.markets || []).join(', ') || '—'),
    'Entity Types: ' + ((entry.entityTypes || []).join(', ') || entry.entityType || '—'),
    'Bad Values: ' + formatTrendBadValues(entry),
    'Fix Owner: ' + (((entry.translation || '').match(/[Ff]ix owner[:\s]+([^.]+)/) || [])[1] || '—'),
    'Submitted: ' + (entry.submittedAt || entry.firstSeen || '—'),
    'Envelopes: ' + ((entry.envelopeIds || []).join(', ') || '—'),
    '',
    'Description:',
    (entry.msg || '').replace('<BAD_VALUE>', (entry.badValues && entry.badValues.length) ? '"' + entry.badValues[0] + '"' : '<value>'),
    '',
    'Plain English / Translation:',
    entry.translation || 'No plain-English translation is currently stored for this trend.'
  ];
  return lines.join('\n');
}

function openReaderContent(title, html) {
  var modal = document.getElementById('reader-modal');
  var backdrop = document.getElementById('reader-modal-backdrop');
  var titleNode = document.getElementById('reader-modal-title');
  var bodyNode = document.getElementById('reader-modal-body');
  if (!modal || !backdrop || !titleNode || !bodyNode) return;
  titleNode.textContent = title;
  bodyNode.innerHTML = html;
  modal.classList.add('open');
  backdrop.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function buildCategoryDefinitionsMarkup() {
  var defs = [
    ['Type Error', 'The value was submitted in the wrong data type, such as a string instead of a number.', 'Usually caused by serialization or source-system formatting.', 'Example: string "350.00" sent where number | null is expected.'],
    ['Missing Field', 'A contract-required field was not included in the payload.', 'Usually caused by incomplete source data or mapping gaps.', 'Example: recordid or county missing from the entity.'],
    ['Enum / Invalid Value', 'The submitted value is not one of the approved allowed values in the schema.', 'Usually caused by source values not matching contract enums exactly.', 'Example: a county, race, or event code outside the allowed list.'],
    ['Extra Field', 'The payload included a field that is not part of the loaded contract for that entity type.', 'Usually caused by stale mappings or fields sent under the wrong entity type.', 'Example: appointment data sent on a case-status entity.'],
    ['Wrong Field Name', 'The payload used a field name that does not exist in the contract, often when a near-match field does exist.', 'Usually caused by legacy mappings or contract naming drift.', 'Example: filing_statute_citation instead of statute_citation.'],
    ['Invalid Entity Type', 'The entityType does not match a supported contract entity for the current event.', 'Usually caused by source-system mapping or event/entity mismatches.', 'Example: using a singular entity type that is not part of the contract.']
  ];
  return '<div class="schema-review-shell"><div class="schema-review-copy">These definitions explain how CATCH groups recurring issues in Trends so project teams and leadership can interpret the dashboard consistently.</div><div class="schema-review-grid">' + defs.map(function(def) {
    return '<div class="schema-review-card"><div class="schema-review-block-header"><div><div class="schema-review-block-title">' + escHtml(def[0]) + '</div><div class="schema-review-block-copy">' + escHtml(def[1]) + '</div></div></div><div class="schema-review-note"><strong>Usually caused by:</strong> ' + escHtml(def[2]) + '</div><div class="schema-review-note"><strong>Example:</strong> ' + escHtml(def[3]) + '</div></div>';
  }).join('') + '</div></div>';
}

function buildPublisherDetailMarkup(publisherName) {
  var target = publisherName || '';
  var sourceData = Array.isArray(_catalogFiltered) && _catalogFiltered.length ? _catalogFiltered : _catalogData;
  var rows = sourceData.filter(function(entry) {
    return (entry.publishers || []).indexOf(target) !== -1;
  });
  if (!rows.length) {
    return '<div class="schema-review-copy">No recurring trends are currently associated with this publisher in the active Trends slice.</div>';
  }
  var byField = {};
  var byCategory = {};
  var totalOccurrences = 0;
  rows.forEach(function(entry) {
    totalOccurrences += entry.count || 0;
    byField[entry.field] = (byField[entry.field] || 0) + (entry.count || 0);
    byCategory[entry.errorCategory] = (byCategory[entry.errorCategory] || 0) + (entry.count || 0);
  });
  var topField = Object.entries(byField).sort(function(a,b){ return b[1]-a[1]; })[0];
  var topCategory = Object.entries(byCategory).sort(function(a,b){ return b[1]-a[1]; })[0];
  var oldest = rows.slice().sort(function(a,b){ return new Date(a.firstSeen || 0) - new Date(b.firstSeen || 0); })[0];
  var latest = rows.slice().sort(function(a,b){ return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0); })[0];
  return '<div class="schema-review-shell"><div class="schema-review-summary">' +
    '<div class="schema-review-stat"><div class="schema-review-stat-label">Publisher</div><div class="schema-review-stat-value">' + escHtml(target) + '</div></div>' +
    '<div class="schema-review-stat"><div class="schema-review-stat-label">Recurring trends</div><div class="schema-review-stat-value">' + rows.length + '</div></div>' +
    '<div class="schema-review-stat"><div class="schema-review-stat-label">Occurrences</div><div class="schema-review-stat-value">' + totalOccurrences + '</div></div>' +
    '</div><div class="schema-review-grid">' +
    '<div class="schema-review-card"><div class="schema-review-block-title">Top field</div><div class="schema-review-note">' + escHtml(topField ? topField[0] : '—') + (topField ? ' · ' + topField[1] + ' occurrences' : '') + '</div></div>' +
    '<div class="schema-review-card"><div class="schema-review-block-title">Dominant issue class</div><div class="schema-review-note">' + escHtml(topCategory ? topCategory[0] : '—') + (topCategory ? ' · ' + topCategory[1] + ' occurrences' : '') + '</div></div>' +
    '<div class="schema-review-card"><div class="schema-review-block-title">Oldest recurring trend</div><div class="schema-review-note">' + escHtml(oldest ? (oldest.field + ' since ' + (oldest.firstSeen || '—')) : '—') + '</div></div>' +
    '<div class="schema-review-card"><div class="schema-review-block-title">Latest activity</div><div class="schema-review-note">' + escHtml(latest ? ((latest.lastSeen || '—') + ' · ' + latest.field) : '—') + '</div></div>' +
    '</div></div>';
}

window.openCategoryDefinitions = function () {
  openReaderContent('Trend Category Definitions', buildCategoryDefinitionsMarkup());
};

window.openPublisherDetail = function (publisherName) {
  if (!publisherName || publisherName === 'None yet' || publisherName === 'Awaiting history') return;
  openReaderContent(publisherName + ' publisher detail', buildPublisherDetailMarkup(publisherName));
};

window.openTrendDetail = function (idx) {
  var entry = _catalogFiltered && _catalogFiltered[idx];
  var modal = document.getElementById('trend-detail-modal');
  var backdrop = document.getElementById('trend-detail-backdrop');
  var title = document.getElementById('trend-detail-title');
  var body = document.getElementById('trend-detail-body');
  if (!entry || !modal || !backdrop || !title || !body) return;

  var fixOwnerMatch = (entry.translation || '').match(/[Ff]ix owner[:\s]+([^.]+)/);
  var fixOwner = fixOwnerMatch ? fixOwnerMatch[1].trim().replace(/\.$/, '') : 'Not specified';
  var detailText = buildTrendDetailText(entry);
  var refinePayload = JSON.stringify({
    source: "trend",
    entityType: ((entry.entityTypes || [entry.entityType])[0]) || "All",
    field: entry.field || "",
    message: (entry.msg || '').replace('<BAD_VALUE>', (entry.badValues && entry.badValues.length) ? '"' + entry.badValues[0] + '"' : '<value>'),
    translation: entry.translation || "",
    fixOwner: fixOwner === 'Not specified' ? 'Odyssey' : fixOwner,
    action: "",
    ref: entry.ref || "",
    matchValue: (entry.badValues && entry.badValues[0]) ? String(entry.badValues[0]) : "",
    matchType: (entry.badValues && entry.badValues.length) ? "field_value" : "contains"
  });
  window.__trendDetailClipboard = detailText;

  title.textContent = (entry.field || 'Trend detail') + ' trend detail';
  body.innerHTML = `
    <div class="trend-detail-actions">
      <button class="trend-detail-copy-btn" type="button" onclick="copyTrendDetail()">Copy to clipboard</button>
      <button class="trend-detail-copy-btn" type="button" onclick='openRefineErrorModal(${JSON.stringify(refinePayload)})'>Refine in library</button>
    </div>
    <div class="trend-detail-grid">
      <div class="trend-detail-block">
        <span class="trend-detail-label">Summary</span>
        <div class="trend-detail-value">${escHtml((entry.msg || '').replace('<BAD_VALUE>', (entry.badValues && entry.badValues.length) ? '"' + entry.badValues[0] + '"' : '<value>'))}</div>
      </div>
      <div class="trend-detail-block">
        <span class="trend-detail-label">Plain English</span>
        <div class="trend-detail-value">${escHtml(entry.translation || 'No plain-English translation is currently stored for this trend.')}</div>
      </div>
      <div class="trend-detail-block">
        <span class="trend-detail-label">Signals</span>
        <div class="trend-detail-value">Category: ${escHtml(entry.errorCategory || '—')}<br>Occurrences: ${escHtml(String(entry.count != null ? entry.count : '—'))}<br>Bad value: ${escHtml(formatTrendBadValues(entry))}<br>Fix owner: ${escHtml(fixOwner)}</div>
      </div>
      <div class="trend-detail-block">
        <span class="trend-detail-label">Coverage</span>
        <div class="trend-detail-value">Publishers: ${escHtml(((entry.publishers || []).join(', ')) || '—')}<br>Markets: ${escHtml(((entry.markets || []).join(', ')) || '—')}<br>Entity types: ${escHtml(((entry.entityTypes || []).join(', ')) || entry.entityType || '—')}<br>Envelopes: ${escHtml(((entry.envelopeIds || []).join(', ')) || '—')}</div>
      </div>
      <div class="trend-detail-block">
        <span class="trend-detail-label">Clipboard preview</span>
        <pre class="trend-detail-code">${escHtml(detailText)}</pre>
      </div>
    </div>
  `;
  modal.classList.add('open');
  backdrop.classList.add('open');
  document.body.style.overflow = 'hidden';
};

window.copyTrendDetail = function () {
  var text = window.__trendDetailClipboard || '';
  if (!text || !navigator.clipboard) return;
  navigator.clipboard.writeText(text);
};

(function () {
    document.title = "CATCH Modern";

    var headerLeft = document.querySelector(".header-left");
    if (headerLeft) {
      headerLeft.innerHTML = `
        <div class="catch-brand">
          <div class="catch-brand-copy">
            <div class="catch-wordmark">CATCH</div>
            <div class="catch-tagline">Stop guessing. Start catching.</div>
            <div class="catch-pill">Version 3.0</div>
          </div>
        </div>
      `;
    }

    var header = document.querySelector(".header");
    var stateSelect = document.getElementById("state-select");
    var settingsBtn = document.getElementById("settings-btn");
    var sessionToggle = document.getElementById("session-only-toggle");
    var sessionLabel = document.getElementById("session-only-label");
    var sessionContainer = sessionToggle ? sessionToggle.closest("div[title]") : null;
    var workspaceControlSource = document.getElementById("workspace-control-source");

    if (header && settingsBtn) {
      settingsBtn.textContent = "Settings";
      header.appendChild(settingsBtn);
    }

    if (stateSelect && sessionToggle && sessionLabel) {
      var workspaceAnchor = document.getElementById("workspace-settings-anchor");
      if (workspaceAnchor && !document.getElementById("workspace-settings-panel")) {
        workspaceAnchor.innerHTML = `
          <div class="settings-section-title">Workspace Preferences</div>
          <div class="workspace-settings-grid" id="workspace-settings-panel"></div>
        `;

        var panel = document.getElementById("workspace-settings-panel");

        var marketCard = document.createElement("div");
        marketCard.className = "workspace-settings-card";
        marketCard.innerHTML = `<label class="workspace-settings-label">Validation Market</label>`;
        marketCard.appendChild(stateSelect);

        var privacyCard = document.createElement("div");
        privacyCard.className = "workspace-settings-card";
        privacyCard.innerHTML = `
          <div class="workspace-settings-label">Privacy Mode</div>
          <div class="settings-switch-row">
            <label class="settings-switch-label"></label>
            <div class="settings-switch-note">Keep history only for the current browser session.</div>
          </div>
        `;
        var switchLabel = privacyCard.querySelector(".settings-switch-label");
        switchLabel.appendChild(sessionToggle);
        var switchText = document.createElement("span");
        switchText.textContent = "Session Only";
        switchLabel.appendChild(switchText);
        privacyCard.querySelector(".settings-switch-note").appendChild(sessionLabel);

        panel.appendChild(marketCard);
        panel.appendChild(privacyCard);
        if (workspaceControlSource) {
          workspaceControlSource.remove();
        }
      }
    }

    var infoPanel = document.getElementById("panel-about");
    var releasePanel = document.getElementById("panel-release");
    var settingsBody = document.querySelector(".settings-body");
    if (settingsBody && !document.getElementById("settings-support-section")) {
      var supportSection = document.createElement("div");
      supportSection.id = "settings-support-section";
      supportSection.className = "settings-section";
      supportSection.innerHTML = `
        <div class="settings-section-title">Support Content</div>
        <div class="settings-link-list">
          <button class="settings-link-btn" id="open-about-from-settings">
            <span>
              About CATCH
              <span class="settings-link-meta">Reference overview, product context, and guidance.</span>
            </span>
            <span>Open</span>
          </button>
          <button class="settings-link-btn" id="open-release-from-settings">
            <span>
              Product Updates
              <span class="settings-link-meta">Release notes and recent changes to the validator experience.</span>
            </span>
            <span>Open</span>
          </button>
        </div>
      `;
      settingsBody.appendChild(supportSection);

      var openAbout = document.getElementById("open-about-from-settings");
      var openRelease = document.getElementById("open-release-from-settings");

      var readerModal = document.getElementById("reader-modal");
      var readerBackdrop = document.getElementById("reader-modal-backdrop");
      var readerTitle = document.getElementById("reader-modal-title");
      var readerBody = document.getElementById("reader-modal-body");
      var readerClose = document.getElementById("reader-modal-close");

      function openReader(title, panel) {
        if (!readerModal || !readerBackdrop || !readerTitle || !readerBody || !panel) return;
        readerTitle.textContent = title;
        readerBody.innerHTML = panel.innerHTML;
        readerModal.classList.add("open");
        readerBackdrop.classList.add("open");
        document.body.style.overflow = "hidden";
      }

      function closeReader() {
        if (!readerModal || !readerBackdrop || !readerBody) return;
        readerModal.classList.remove("open");
        readerBackdrop.classList.remove("open");
        readerBody.innerHTML = "";
        document.body.style.overflow = "";
      }

      if (readerClose) {
        readerClose.addEventListener("click", closeReader);
      }
      if (readerBackdrop) {
        readerBackdrop.addEventListener("click", closeReader);
      }
      document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") closeReader();
      });

      if (openAbout && infoPanel) {
        openAbout.addEventListener("click", function () {
          if (typeof toggleSettings === "function") toggleSettings();
          openReader("About CATCH", infoPanel);
        });
      }

      if (openRelease && releasePanel) {
        openRelease.addEventListener("click", function () {
          if (typeof toggleSettings === "function") toggleSettings();
          openReader("Product Updates", releasePanel);
        });
      }
    }

    if (sessionContainer && document.body.contains(sessionContainer)) {
      sessionContainer.remove();
    }

    var preview = document.getElementById("entity-preview");
    if (preview) {
      preview.textContent = "Validate one payload and review findings side by side";
    }

    var content = document.querySelector(".content");
    if (content && !document.getElementById("workspace-hero")) {
      var hero = document.createElement("section");
      hero.id = "workspace-hero";
      hero.className = "workspace-hero";
      hero.innerHTML = `
        <article class="hero-card">
          <div class="hero-eyebrow">Validation market</div>
          <div class="hero-market-display">
            <div class="hero-market-code" id="hero-market-code">TX</div>
            <div class="hero-market-name" id="hero-market-name">OCA</div>
          </div>
          <div class="hero-market-meta">All schema review, validation logic, and findings align to this active market.</div>
        </article>
        <div class="hero-stat-grid">
          <article class="hero-stat-card">
            <div class="hero-stat-label">Event type</div>
            <div class="hero-stat-value results-kpi-text" id="hero-event-type">Awaiting payload</div>
            <div class="hero-stat-copy">The detected event type for the current payload.</div>
          </article>
          <article class="hero-stat-card">
            <div class="hero-stat-label">AEP submission</div>
            <div class="hero-stat-value results-kpi-text" id="hero-submitted-at">—</div>
            <div class="hero-stat-copy">When the AEP received the envelope, when available.</div>
          </article>
          <article class="hero-stat-card">
            <div class="hero-stat-label">CATCH submission</div>
            <div class="hero-stat-value results-kpi-text" id="hero-analysed-at">—</div>
            <div class="hero-stat-copy">The time this payload was last validated in CATCH.</div>
          </article>
          <article class="hero-stat-card">
            <div class="hero-stat-label">Run summary</div>
            <div class="hero-stat-value results-kpi-text" id="hero-run-summary">0 entities · 0 errors</div>
            <div class="hero-stat-copy" id="hero-run-meta">Filter: all findings</div>
          </article>
        </div>
      `;
      content.insertBefore(hero, content.firstChild);
    }

    var resultEmpty = document.querySelector(".results-empty");
    if (resultEmpty) {
      resultEmpty.textContent = "Paste a payload and run validation to see technical issues and plain-English translations side by side.";
    }

    var schemaBackdrop = document.createElement("div");
    schemaBackdrop.id = "schema-modal-backdrop";
    schemaBackdrop.className = "reader-modal-backdrop";
    var schemaModal = document.createElement("div");
    schemaModal.id = "schema-modal";
    schemaModal.className = "reader-modal";
    schemaModal.innerHTML = `
      <div class="reader-modal-header">
        <div>
          <div class="hero-eyebrow">Schema review</div>
          <div class="reader-modal-title" id="schema-modal-title">Current event schema</div>
        </div>
        <button class="reader-modal-close" id="schema-modal-close" aria-label="Close schema review">x</button>
      </div>
      <div class="reader-modal-body" id="schema-modal-body"></div>
    `;
    document.body.appendChild(schemaBackdrop);
    document.body.appendChild(schemaModal);

    var trendDetailBackdrop = document.createElement("div");
    trendDetailBackdrop.id = "trend-detail-backdrop";
    trendDetailBackdrop.className = "reader-modal-backdrop";
    var trendDetailModal = document.createElement("div");
    trendDetailModal.id = "trend-detail-modal";
    trendDetailModal.className = "reader-modal";
    trendDetailModal.innerHTML = `
      <div class="reader-modal-header">
        <div>
          <div class="hero-eyebrow">Trend detail</div>
          <div class="reader-modal-title" id="trend-detail-title">Trend detail</div>
        </div>
        <button class="reader-modal-close" id="trend-detail-close" aria-label="Close trend detail">x</button>
      </div>
      <div class="reader-modal-body" id="trend-detail-body"></div>
    `;
    document.body.appendChild(trendDetailBackdrop);
    document.body.appendChild(trendDetailModal);

    var refineBackdrop = document.createElement("div");
    refineBackdrop.id = "refine-error-backdrop";
    refineBackdrop.className = "reader-modal-backdrop";
    var refineModal = document.createElement("div");
    refineModal.id = "refine-error-modal";
    refineModal.className = "reader-modal";
    refineModal.innerHTML = `
      <div class="reader-modal-header">
        <div>
          <div class="hero-eyebrow">Error refinement</div>
          <div class="reader-modal-title" id="refine-error-title">Refine this error</div>
        </div>
        <button class="reader-modal-close" id="refine-error-close" aria-label="Close refinement">x</button>
      </div>
      <div class="reader-modal-body" id="refine-error-body"></div>
    `;
    document.body.appendChild(refineBackdrop);
    document.body.appendChild(refineModal);

    function closeSchemaModal() {
      schemaModal.classList.remove("open");
      schemaBackdrop.classList.remove("open");
      document.body.style.overflow = "";
    }

    function closeTrendDetail() {
      trendDetailModal.classList.remove("open");
      trendDetailBackdrop.classList.remove("open");
      document.body.style.overflow = "";
    }

    function closeRefineErrorModal() {
      refineModal.classList.remove("open");
      refineBackdrop.classList.remove("open");
      document.body.style.overflow = "";
    }
    window.closeRefineErrorModal = closeRefineErrorModal;

    window.openRefineErrorModal = function (payload) {
      var parsedPayload = payload;
      while (typeof parsedPayload === "string") {
        try { parsedPayload = JSON.parse(parsedPayload); } catch (err) { parsedPayload = {}; break; }
      }
      var body = document.getElementById("refine-error-body");
      var title = document.getElementById("refine-error-title");
      if (!body || !title) return;
      title.textContent = "Refine this error";
      body.innerHTML = `
        <div class="refine-help">Convert a raw validator issue into a reusable translation-library entry. This will keep future findings more human-readable and easier to triage.</div>
        <div class="refine-grid">
          <div class="refine-grid-2">
            <div class="lib-form-row"><div class="lib-form-label">Entity Type</div><input class="lib-form-input" id="refine-entity-type" value="${escHtml(parsedPayload.entityType || 'All')}" /></div>
            <div class="lib-form-row"><div class="lib-form-label">Field</div><input class="lib-form-input" id="refine-field" value="${escHtml(parsedPayload.field || '')}" /></div>
          </div>
          <div class="refine-grid-2">
            <div class="lib-form-row"><div class="lib-form-label">Match Type</div><select class="lib-form-select" id="refine-match-type">${MATCH_TYPES.map(function(m){ return '<option' + ((parsedPayload.matchType || 'contains') === m ? ' selected' : '') + '>' + m + '</option>'; }).join('')}</select></div>
            <div class="lib-form-row"><div class="lib-form-label">Match Value</div><input class="lib-form-input" id="refine-match-value" value="${escHtml(parsedPayload.matchValue || '')}" placeholder="Leave blank for field_name" /></div>
          </div>
          <div class="refine-grid-2">
            <div class="lib-form-row"><div class="lib-form-label">Fix Owner</div><select class="lib-form-select" id="refine-fix-owner">${FIX_OWNERS.map(function(o){ return '<option' + ((parsedPayload.fixOwner || 'Odyssey') === o ? ' selected' : '') + '>' + o + '</option>'; }).join('')}</select></div>
            <div class="lib-form-row"><div class="lib-form-label">Trust Status</div><select class="lib-form-select" id="refine-trust-status">${TRUST_STATUSES.map(function(t){ return '<option' + ((parsedPayload.trustStatus || 'draft') === t ? ' selected' : '') + '>' + t + '</option>'; }).join('')}</select></div>
          </div>
          <div class="lib-form-row"><div class="lib-form-label">Technical Error</div><textarea class="lib-form-textarea" id="refine-technical" readonly>${escHtml(parsedPayload.message || '')}</textarea></div>
          <div class="lib-form-row"><div class="lib-form-label">Plain-English Translation</div><textarea class="lib-form-textarea" id="refine-translation">${escHtml(parsedPayload.translation || '')}</textarea></div>
          <div class="lib-form-row"><div class="lib-form-label">Recommended Action</div><textarea class="lib-form-textarea" id="refine-action">${escHtml(parsedPayload.action || '')}</textarea></div>
          <div class="refine-grid-2">
            <div class="lib-form-row"><div class="lib-form-label">Reference</div><input class="lib-form-input" id="refine-ref" value="${escHtml(parsedPayload.ref || '')}" /></div>
            <div class="lib-form-row"><div class="lib-form-label">Notes</div><input class="lib-form-input" id="refine-notes" value="${escHtml(parsedPayload.notes || '')}" placeholder="Optional review notes" /></div>
          </div>
          <div class="lib-entry-actions">
            <button class="lib-save-btn" type="button" onclick="saveRefinedError()">Save to library</button>
            <button class="lib-delete-btn" type="button" onclick="closeRefineErrorModal()">Cancel</button>
          </div>
        </div>
      `;
      refineModal.classList.add("open");
      refineBackdrop.classList.add("open");
      document.body.style.overflow = "hidden";
    };

    window.saveRefinedError = function () {
      var entries = loadLibrary();
      entries.push({
        id: generateLibId(),
        entityType: (document.getElementById("refine-entity-type").value || 'All').trim() || 'All',
        field: (document.getElementById("refine-field").value || '').trim(),
        matchType: document.getElementById("refine-match-type").value,
        matchValue: (document.getElementById("refine-match-value").value || '').trim(),
        translation: (document.getElementById("refine-translation").value || '').trim(),
        fixOwner: document.getElementById("refine-fix-owner").value,
        action: (document.getElementById("refine-action").value || '').trim(),
        ref: (document.getElementById("refine-ref").value || '').trim(),
        trustStatus: document.getElementById("refine-trust-status").value,
        notes: (document.getElementById("refine-notes").value || '').trim()
      });
      saveLibrary(entries);
      try { renderLibrary(); } catch (err) {}
      closeRefineErrorModal();
    };

    function schemaVersionForEntity(entityType, market) {
      var overrides = (typeof schemaOverrides !== "undefined" && schemaOverrides[market]) ? schemaOverrides[market] : {};
      if (overrides[entityType]) {
        return (overrides[entityType].version && overrides[entityType].version.const) || "custom";
      }
      if (market === "IL") return "v3.1.0";
      return (typeof VALID_V3 !== "undefined" && VALID_V3.includes(entityType)) ? "v3.0.0" : "v0.1";
    }

    function schemaObjectForEntity(entityType, market) {
      var overrides = (typeof schemaOverrides !== "undefined" && schemaOverrides[market]) ? schemaOverrides[market] : {};
      if (overrides[entityType]) return overrides[entityType];
      if (market === "IL" && typeof IL_ENTITY_RULES !== "undefined") return IL_ENTITY_RULES[entityType] || null;
      if (typeof ENTITY_RULES !== "undefined") return ENTITY_RULES[entityType] || null;
      return null;
    }

    function schemaFieldRowsForEntity(entityType, market) {
      var viewMode = window._schemaReviewMode || "merged";
      var includeWorkbook = viewMode !== "contract";
      var includeContract = viewMode !== "workbook";
      var schemaObject = includeContract ? (schemaObjectForEntity(entityType, market) || {}) : {};
      var allowedFields = includeContract && (typeof ALLOWED_FIELDS !== "undefined" && ALLOWED_FIELDS[entityType]) ? Array.from(ALLOWED_FIELDS[entityType]) : [];
      var workbookRows = workbookSchemaRowsForEntity(entityType, market);
      var workbookByField = {};
      var rules = schemaObject;
      var requiredSet = new Set();
      var rows = [];

      if (includeWorkbook) workbookRows.forEach(function (row) {
        if (!row || !row.field) return;
        workbookByField[row.field] = row;
        if (row.required) requiredSet.add(row.field);
      });

      if (includeContract && schemaObject && Array.isArray(schemaObject.required)) {
        schemaObject.required.forEach(function (field) { requiredSet.add(field); });
      } else if (includeContract && schemaObject && schemaObject.required && typeof schemaObject.required.forEach === "function") {
        schemaObject.required.forEach(function (field) { requiredSet.add(field); });
      }

      function normalizeType(def, field) {
        var workbookRow = workbookByField[field];
        if (workbookRow && workbookRow.type) {
          if (String(workbookRow.type).toLowerCase() === "date") return "date string";
          if (String(workbookRow.type).toLowerCase() === "enum") return "string enum";
          return String(workbookRow.type);
        }
        if (!def) {
          if (rules.numOrNull && rules.numOrNull.includes(field)) return "number | null";
          if (rules.dateFields && rules.dateFields.includes(field)) return "date string";
          if (rules.enums && rules.enums[field]) return "string enum";
          return "contract field";
        }
        if (Array.isArray(def.type)) return def.type.join(" | ");
        if (def.type) return String(def.type);
        if (Array.isArray(def.enum) && def.enum.length) return typeof def.enum[0] === "number" ? "number enum" : "string enum";
        if (Array.isArray(def.anyOf) && def.anyOf.length) {
          return def.anyOf.map(function (entry) { return entry.type || "value"; }).filter(Boolean).join(" | ");
        }
        if (Array.isArray(def.oneOf) && def.oneOf.length) {
          return def.oneOf.map(function (entry) { return entry.type || "value"; }).filter(Boolean).join(" | ");
        }
        return "contract field";
      }

      function buildConstraintBits(field, def) {
        var bits = [];
        var workbookRow = workbookByField[field];
        var enumValues = def && Array.isArray(def.enum) ? def.enum : ((rules.enums && rules.enums[field]) || null);
        if (enumValues && enumValues.length) bits.push("Enum (" + enumValues.length + " values)");
        if (rules.numOrNull && rules.numOrNull.includes(field)) bits.push("Number or null");
        if (rules.dateFields && rules.dateFields.includes(field)) bits.push("Date field");
        if (def && def.format) bits.push("Format: " + def.format);
        if (def && typeof def.maxLength === "number") bits.push("Max length " + def.maxLength);
        if (def && typeof def.minLength === "number") bits.push("Min length " + def.minLength);
        if (workbookRow && workbookRow.type === "enum" && workbookRow.values && workbookRow.values.trim() && workbookRow.values.trim() !== "Â ") {
          var workbookEnum = workbookRow.values.split(";").map(function (value) { return value.trim(); }).filter(Boolean);
          if (workbookEnum.length) bits.push("Workbook enum (" + workbookEnum.length + " values)");
        }
        if (workbookRow && workbookRow.regex && workbookRow.regex.trim() && workbookRow.regex.trim() !== "Â " && workbookRow.regex !== "System.Xml.XmlElement") {
          bits.push("Workbook pattern available");
        }
        return bits;
      }

      function buildNotes(field, def) {
        var workbookRow = workbookByField[field];
        var enumValues = def && Array.isArray(def.enum) ? def.enum : ((rules.enums && rules.enums[field]) || null);
        if (workbookRow && workbookRow.definition && workbookRow.definition !== "System.Xml.XmlElement") {
          return workbookRow.definition;
        }
        if (enumValues && enumValues.length) {
          return enumValues.slice(0, 5).join(", ") + (enumValues.length > 5 ? " +" + (enumValues.length - 5) + " more" : "");
        }
        if (def && def.description) return def.description;
        if (rules.badFields && rules.badFields[field]) return "Preferred field: " + rules.badFields[field];
        if (rules.refs && rules.refs[field]) return "Reference: " + rules.refs[field];
        return "No additional notes";
      }

      if (includeContract && schemaObject && schemaObject.properties && typeof schemaObject.properties === "object") {
        Object.keys(schemaObject.properties).sort().forEach(function (field) {
          var def = schemaObject.properties[field] || {};
          var workbookRow = workbookByField[field] || null;
          rows.push({
            field: field,
            label: workbookRow && workbookRow.label ? workbookRow.label : field,
            type: normalizeType(def, field),
            required: requiredSet.has(field),
            priority: workbookRow && workbookRow.priority ? workbookRow.priority : "",
            workbook: !!workbookRow,
            constraints: buildConstraintBits(field, def),
            note: buildNotes(field, def)
          });
        });
        Object.keys(workbookByField).sort().forEach(function (field) {
          if (schemaObject.properties[field]) return;
          var workbookOnly = workbookByField[field];
          rows.push({
            field: field,
            label: workbookOnly && workbookOnly.label ? workbookOnly.label : field,
            type: normalizeType(null, field),
            required: requiredSet.has(field),
            priority: workbookOnly && workbookOnly.priority ? workbookOnly.priority : "",
            workbook: true,
            constraints: buildConstraintBits(field, null),
            note: buildNotes(field, null)
          });
        });
        return {
          rows: rows,
          source: viewMode === "workbook"
            ? "Approved workbook v3.0.0"
            : (workbookRows.length ? "Approved workbook v3.0.0 + full schema properties" : "Full schema properties")
        };
      }

      var fields = Array.from(new Set([]
        .concat(allowedFields)
        .concat(includeContract && rules.enums ? Object.keys(rules.enums) : [])
        .concat(includeContract ? (rules.numOrNull || []) : [])
        .concat(includeContract ? (rules.dateFields || []) : [])
        .concat(Object.keys(workbookByField))
        .concat(Array.from(requiredSet))
      )).sort();

      fields.forEach(function (field) {
        var workbookRow = workbookByField[field] || null;
        rows.push({
          field: field,
          label: workbookRow && workbookRow.label ? workbookRow.label : field,
          type: normalizeType(null, field),
          required: requiredSet.has(field),
          priority: workbookRow && workbookRow.priority ? workbookRow.priority : "",
          workbook: !!workbookRow,
          constraints: buildConstraintBits(field, null),
          note: buildNotes(field, null)
        });
      });

      return {
        rows: rows,
        source: viewMode === "workbook"
          ? "Approved workbook v3.0.0"
          : (viewMode === "contract"
            ? (allowedFields.length ? "Built-in contract rules + field inventory" : "Built-in contract rules")
            : (workbookRows.length
              ? "Approved workbook v3.0.0 + built-in contract rules"
              : (allowedFields.length ? "Built-in contract rules + field inventory" : "Built-in contract rules")))
      };
    }

    function buildSchemaSpreadsheet(entityType, market) {
      var schemaSheet = schemaFieldRowsForEntity(entityType, market);
      if (!schemaSheet.rows.length) {
        return `
          <div class="schema-review-matrix">
            <div class="schema-review-matrix-header">
              <div class="schema-review-matrix-title">Field schema guide</div>
              <div class="schema-review-matrix-copy">No spreadsheet-style field data is available for this entity in the current file.</div>
            </div>
          </div>
        `;
      }

      var body = schemaSheet.rows.map(function (row) {
        var constraintMarkup = row.constraints.length
          ? `<div class="schema-review-constraint">${row.constraints.map(function (item) { return `<span class="schema-review-chip">${item}</span>`; }).join("")}</div>`
          : `<span class="schema-review-note">No special constraints</span>`;

        return `
          <tr>
            <td>
              <div class="schema-review-label">${row.label || row.field}</div>
              <div class="schema-review-field">${row.field}</div>
            </td>
            <td><div class="schema-review-type">${row.type}</div></td>
            <td><span class="schema-review-required ${row.required ? "yes" : "no"}">${row.required ? "Required" : "Optional"}</span></td>
            <td>
              ${row.priority ? `<div class="schema-review-note"><strong>Workbook priority:</strong> ${row.priority}</div>` : ``}
              ${constraintMarkup}
              <div class="schema-review-note" style="margin-top:8px">${row.note}</div>
            </td>
          </tr>
        `;
      }).join("");

      return `
        <div class="schema-review-matrix">
          <div class="schema-review-matrix-header">
            <div class="schema-review-matrix-title">Field schema guide</div>
            <div class="schema-review-matrix-copy">${schemaSheet.rows.length} fields from ${schemaSheet.source}</div>
          </div>
          <div class="schema-review-table-wrap">
            <table class="schema-review-table">
              <thead>
                <tr>
                  <th>Field</th>
                  <th>Expected type</th>
                  <th>Required</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>${body}</tbody>
            </table>
          </div>
        </div>
      `;
    }

    function buildSchemaModalMarkup() {
      var parsed = (typeof _lastValidationParsed !== "undefined" && _lastValidationParsed) ? _lastValidationParsed : null;
      var market = parsed && parsed.market ? parsed.market : ((stateSelect && stateSelect.value) || "TX");
      var eventType = parsed && parsed.eventType ? parsed.eventType : "No event selected";
      var schemaViewMode = window._schemaReviewMode || "merged";
      var payloadEntities = parsed && parsed.entities
        ? Array.from(new Set(parsed.entities.map(function (entity) { return entity.entityType; }).filter(Boolean)))
        : [];
      var marketSchemas = market === "IL"
        ? ((typeof IL_VALID_ENTITY_TYPES !== "undefined") ? IL_VALID_ENTITY_TYPES.slice() : [])
        : ((typeof ALL_VALID !== "undefined") ? ALL_VALID.slice() : []);
      var rows = (payloadEntities.length ? payloadEntities : marketSchemas).map(function (entityType) {
        var overrides = (typeof schemaOverrides !== "undefined" && schemaOverrides[market]) ? schemaOverrides[market] : {};
        var isUploaded = !!overrides[entityType];
        var inPayload = payloadEntities.includes(entityType);
        var hasWorkbook = workbookSchemaRowsForEntity(entityType, market).length > 0;
        var version = schemaVersionForEntity(entityType, market);
        var sourceLabel = isUploaded ? "Uploaded override" : "Built-in";
        var payloadLabel = inPayload ? `<span class="schema-review-badge payload">In current payload</span>` : "";
        var schemaObject = schemaObjectForEntity(entityType, market);
        var schemaJson = schemaObject ? JSON.stringify(schemaObject, null, 2) : "Schema not available for this entity type.";
        return `
          <div class="schema-review-block">
            <div class="schema-review-row-top">
              <div class="schema-review-entity">${entityType}</div>
              <div class="schema-review-badges">
                ${payloadLabel}
                <span class="schema-review-badge ${isUploaded ? "uploaded" : "builtin"}">${sourceLabel}</span>
                ${hasWorkbook ? `<span class="schema-review-badge builtin">Approved workbook v3.0.0</span>` : ``}
                <span class="schema-review-badge builtin">${version}</span>
              </div>
            </div>
            <div class="schema-review-block-copy">
              ${inPayload
                ? "This entity type is active in the currently loaded payload and is part of the validation run in focus."
                : "This schema is currently available for the selected market, even if it is not present in the active payload."}
            </div>
            ${buildSchemaSpreadsheet(entityType, market)}
            <details class="schema-review-toggle">
              <summary>
                <span class="schema-review-toggle-title">
                  <span class="schema-review-toggle-label">Full schema</span>
                  <span class="schema-review-toggle-copy">Open the full contract only when you need the raw structure.</span>
                </span>
                <span class="schema-review-toggle-action"></span>
              </summary>
              <div class="schema-review-json">
              <div class="schema-review-json-header">
                <span class="schema-review-json-label">Raw schema JSON</span>
                <span class="schema-review-json-meta">${sourceLabel} · ${version}</span>
              </div>
              <pre class="schema-review-pre">${schemaJson.replace(/[&<>]/g, function (char) {
                return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[char];
              })}</pre>
              </div>
            </details>
          </div>
        `;
      }).join("");

      return `
        <div class="schema-review-shell">
          <div class="schema-review-summary">
            <div class="schema-review-stat">
              <div class="schema-review-stat-label">Event type</div>
              <div class="schema-review-stat-value">${eventType}</div>
            </div>
            <div class="schema-review-stat">
              <div class="schema-review-stat-label">Market</div>
              <div class="schema-review-stat-value">${market}</div>
            </div>
            <div class="schema-review-stat">
              <div class="schema-review-stat-label">Schema focus</div>
              <div class="schema-review-stat-value">${payloadEntities.length ? payloadEntities.length + " entity types in this payload" : "All active schemas for this market"}</div>
            </div>
          </div>
          <div class="schema-review-toolbar">
            <div class="schema-review-copy">
              ${payloadEntities.length
                ? "These are the active entity schemas CATCH used for the current validation run. Use the source toggle to compare the approved workbook against the contract view."
                : "Run a validation to narrow this view to the specific entity schemas used by the current event type. Until then, this view shows the active schema inventory for the selected market."}
            </div>
            <div class="schema-review-toggle-group" role="tablist" aria-label="Schema source">
              <button class="schema-review-view-btn ${schemaViewMode === "merged" ? "active" : ""}" data-schema-view="merged" type="button">Merged</button>
              <button class="schema-review-view-btn ${schemaViewMode === "workbook" ? "active" : ""}" data-schema-view="workbook" type="button">Workbook</button>
              <button class="schema-review-view-btn ${schemaViewMode === "contract" ? "active" : ""}" data-schema-view="contract" type="button">Contract</button>
            </div>
          </div>
          <div class="schema-review-grid">${rows}</div>
        </div>
      `;
    }

    function openSchemaModal() {
      var title = document.getElementById("schema-modal-title");
      var body = document.getElementById("schema-modal-body");
      if (title) title.textContent = "Current event schema";
      if (body) body.innerHTML = buildSchemaModalMarkup();
      if (body) {
        body.querySelectorAll("[data-schema-view]").forEach(function (button) {
          button.addEventListener("click", function () {
            window._schemaReviewMode = this.getAttribute("data-schema-view") || "merged";
            openSchemaModal();
          });
        });
      }
      schemaModal.classList.add("open");
      schemaBackdrop.classList.add("open");
      document.body.style.overflow = "hidden";
    }

    var schemaClose = document.getElementById("schema-modal-close");
    if (schemaClose) schemaClose.addEventListener("click", closeSchemaModal);
    schemaBackdrop.addEventListener("click", closeSchemaModal);
    var trendDetailClose = document.getElementById("trend-detail-close");
    if (trendDetailClose) trendDetailClose.addEventListener("click", closeTrendDetail);
    trendDetailBackdrop.addEventListener("click", closeTrendDetail);
    var refineClose = document.getElementById("refine-error-close");
    if (refineClose) refineClose.addEventListener("click", closeRefineErrorModal);
    refineBackdrop.addEventListener("click", closeRefineErrorModal);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeSchemaModal();
      if (event.key === "Escape") closeTrendDetail();
      if (event.key === "Escape") closeRefineErrorModal();
    });

    var eventCard = document.getElementById("hero-event-type");
    if (eventCard && eventCard.closest(".hero-stat-card")) {
      var eventCardContainer = eventCard.closest(".hero-stat-card");
      eventCardContainer.classList.add("clickable-card");
      eventCardContainer.setAttribute("tabindex", "0");
      var eventCardCopy = eventCardContainer.querySelector(".hero-stat-copy");
      if (eventCardCopy) eventCardCopy.textContent = "Click to review the active schemas behind this event type.";
      eventCardContainer.addEventListener("click", openSchemaModal);
      eventCardContainer.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openSchemaModal();
        }
      });
    }

    var validateTab = document.querySelector('.tab[data-tab="validate"]');
    var batchTab = document.querySelector('.tab[data-tab="batch"]');
    var historyTab = document.querySelector('.tab[data-tab="history"]');
    var trendsTab = document.querySelector('.tab[data-tab="assoc"]');
    var aboutTab = document.querySelector('.tab[data-tab="about"]');
    var releaseTab = document.querySelector('.tab[data-tab="release"]');
    if (validateTab) validateTab.childNodes[0].textContent = "Single";
    if (batchTab) batchTab.childNodes[0].textContent = "Batch";
    if (historyTab) historyTab.childNodes[0].textContent = "History ";
    if (trendsTab) trendsTab.childNodes[0].textContent = "Trends ";
    if (aboutTab) aboutTab.style.display = "none";
    if (releaseTab) releaseTab.style.display = "none";

    var runBtn = document.getElementById("run-btn");
    if (runBtn) {
      runBtn.textContent = "Run Validation";
    }

    var copyBtn = document.getElementById("copy-results-btn");
    if (copyBtn) {
      copyBtn.textContent = "Copy Findings";
    }

    var paneLabels = document.querySelectorAll(".pane-label");
    if (paneLabels[0]) paneLabels[0].textContent = "Payload input";
    if (paneLabels[1]) paneLabels[1].textContent = "Validation findings";

    var historyPanel = document.getElementById("panel-history");
    if (historyPanel && !document.getElementById("history-feed-intro")) {
      var historyIntro = document.createElement("div");
      historyIntro.id = "history-feed-intro";
      historyIntro.className = "hero-card";
      historyIntro.style.padding = "18px 20px";
      historyIntro.style.marginBottom = "14px";
      historyIntro.innerHTML = `
        <div class="hero-eyebrow">Run history</div>
        <div class="hero-title" style="font-size:22px;">Review previous validation sessions</div>
        <div class="hero-copy" style="font-size:13px;max-width:none;">
          Each saved run is presented as a readable activity card so teams can revisit what failed, when it happened, and what should be reviewed next.
        </div>
      `;
      historyPanel.insertBefore(historyIntro, historyPanel.firstChild);
    }

    var historyExplainer = historyPanel ? historyPanel.querySelector('div[style*="max-width:900px"]') : null;
    if (historyExplainer) {
      historyExplainer.innerHTML = 'Every validation run saved in this session — one card per envelope, showing which entities failed and why. Use this to debug a specific submission. For a cross-run summary of recurring issues, see the <span style="color:var(--text2);cursor:pointer;text-decoration:underline;" onclick="switchTab(\'assoc\')">Trends</span>. Export runs individually or in bulk using the buttons above.';
    }

    var historyPrimaryToolbar = historyPanel ? historyPanel.querySelector(".history-toolbar-primary") : null;
    if (historyPrimaryToolbar && !historyPrimaryToolbar.getAttribute("data-modernized")) {
      var exportWorkbookBtn = historyPrimaryToolbar.querySelector('button[onclick="exportCSV()"]');
      var exportJsonBtn = historyPrimaryToolbar.querySelector('button[onclick="exportJSON()"]');
      var healthBtn = historyPrimaryToolbar.querySelector('button[onclick="exportELTReport()"]');
      var backupBtn = historyPrimaryToolbar.querySelector('button[onclick="saveAllHistory()"]');
      var restoreBtn = historyPrimaryToolbar.querySelector('button[onclick*="import-input"]');
      var clearBtn = historyPrimaryToolbar.querySelector('button[onclick="clearHistory()"]');
      var existingActions = historyPrimaryToolbar.querySelector(".history-actions");

      if (!existingActions) {
        existingActions = document.createElement("div");
        existingActions.className = "history-actions";
        historyPrimaryToolbar.appendChild(existingActions);
      }

      if (exportWorkbookBtn && exportJsonBtn && healthBtn && backupBtn && restoreBtn && clearBtn) {
        existingActions.innerHTML = "";

        exportWorkbookBtn.textContent = "Workbook";
        exportJsonBtn.textContent = "JSON";
        healthBtn.textContent = "Health Report";
        healthBtn.classList.add("history-health-btn");
        healthBtn.removeAttribute("style");

        backupBtn.textContent = "Backup";
        restoreBtn.textContent = "Restore";
        clearBtn.textContent = "Clear";

        var exportCluster = document.createElement("div");
        exportCluster.className = "history-action-cluster";
        exportCluster.innerHTML = `<span class="history-action-label">Exports</span>`;
        var exportButtons = document.createElement("div");
        exportButtons.className = "history-action-buttons";
        exportButtons.appendChild(exportWorkbookBtn);
        exportButtons.appendChild(exportJsonBtn);
        exportButtons.appendChild(healthBtn);
        exportCluster.appendChild(exportButtons);

        var backupCluster = document.createElement("div");
        backupCluster.className = "history-action-cluster";
        backupCluster.innerHTML = `<span class="history-action-label">Browser backup</span>`;
        var backupButtons = document.createElement("div");
        backupButtons.className = "history-action-buttons";
        backupButtons.appendChild(backupBtn);
        backupButtons.appendChild(restoreBtn);
        backupButtons.appendChild(clearBtn);
        backupCluster.appendChild(backupButtons);

        existingActions.appendChild(exportCluster);
        existingActions.appendChild(backupCluster);
        historyPrimaryToolbar.setAttribute("data-modernized", "true");
      }
    }

    var trendsPanel = document.getElementById("panel-assoc");
    if (trendsPanel && !document.getElementById("trends-hero")) {
      var trendsHero = document.createElement("section");
      trendsHero.id = "trends-hero";
      trendsHero.className = "trends-hero";
      trendsHero.innerHTML = `
        <article class="trends-card">
          <div class="hero-eyebrow">Issue trends</div>
          <div class="trends-title">Recurring validation patterns across runs</div>
          <div class="trends-copy">
            Use this view to spot where issue volume is concentrating, which publishers are driving it, and what should be addressed first.
          </div>
          <div class="trends-summary-strip" id="trends-summary-strip">Trend summary will appear here as validation history grows.</div>
        </article>
        <div class="trends-mini-grid">
          <article class="trends-mini">
            <span class="trends-mini-label">Trend health score</span>
            <span class="trends-mini-value" id="trends-health-score">100</span>
            <span class="trends-mini-copy" id="trends-health-copy">A lightweight internal score that drops as recurring issue volume concentrates across history.</span>
          </article>
          <article class="trends-mini">
            <span class="trends-mini-label">Current posture</span>
            <span class="trends-mini-value" id="trends-health-posture">Healthy</span>
            <span class="trends-mini-copy" id="trends-health-posture-copy">Use the spotlight cards and row details below to decide what should be fixed upstream first.</span>
          </article>
          <article class="trends-mini">
            <span class="trends-mini-label">7-day movement</span>
            <span class="trends-mini-value" id="trends-movement-value">Stable</span>
            <span class="trends-mini-copy" id="trends-movement-copy">Run more validations to compare the latest seven days to the previous seven.</span>
          </article>
          <article class="trends-mini">
            <span class="trends-mini-label">Longest-running issue</span>
            <span class="trends-mini-value" id="trends-aging-value">—</span>
            <span class="trends-mini-copy" id="trends-aging-copy">This highlights the oldest recurring issue still visible in the current Trends slice.</span>
          </article>
        </div>
      `;
      trendsPanel.insertBefore(trendsHero, trendsPanel.firstChild);
    }

    var trendsHeaderBar = trendsPanel ? trendsPanel.querySelector('div[style*="border-bottom:1px solid"]') : null;
    if (trendsHeaderBar) {
      var headerSpans = trendsHeaderBar.querySelectorAll("span");
      if (headerSpans[0]) {
        headerSpans[0].remove();
      }
      if (headerSpans[1]) headerSpans[1].remove();

      trendsHeaderBar.style.display = "none";
    }

    if (trendsPanel && !document.getElementById("trends-spotlights")) {
      var trendsSpotlights = document.createElement("section");
      trendsSpotlights.id = "trends-spotlights";
      trendsSpotlights.className = "trends-spotlights";
      trendsSpotlights.innerHTML = `
        <article class="trends-spotlight">
          <span class="trends-spotlight-label">Highest pressure field</span>
          <span class="trends-spotlight-value" id="trends-top-field">Awaiting history</span>
          <span class="trends-spotlight-copy" id="trends-top-field-copy">Run validations to surface which field repeats most across submissions.</span>
        </article>
        <article class="trends-spotlight">
          <span class="trends-spotlight-label">Largest publisher concentration</span>
          <span class="trends-spotlight-value" id="trends-top-publisher">Awaiting history</span>
          <span class="trends-spotlight-copy" id="trends-top-publisher-copy">This spot helps teams see where repeated issue volume is accumulating.</span>
        </article>
        <article class="trends-spotlight">
          <span class="trends-spotlight-label">Dominant issue class</span>
          <span class="trends-spotlight-value" id="trends-top-category">Awaiting history</span>
          <span class="trends-spotlight-copy" id="trends-top-category-copy">Use this to decide whether you are dealing with completeness, enum, or type quality problems.</span>
        </article>
        <article class="trends-spotlight">
          <span class="trends-spotlight-label">Most affected entity</span>
          <span class="trends-spotlight-value" id="trends-top-entity">Awaiting history</span>
          <span class="trends-spotlight-copy" id="trends-top-entity-copy">High concentration here usually points to the best upstream cleanup opportunity.</span>
        </article>
      `;
      trendsPanel.appendChild(trendsSpotlights);
    }

    var trendsStats = document.getElementById("catalog-stats");
    if (trendsStats && !document.getElementById("trends-overview")) {
      trendsStats.removeAttribute("style");
      trendsStats.className = "trends-kpi-grid";

      var trendsOverview = document.createElement("section");
      trendsOverview.id = "trends-overview";
      trendsOverview.className = "trends-overview";
      trendsOverview.innerHTML = `
        <div class="trends-overview-top">
          <div class="trends-kpi-panel">
            <div class="hero-eyebrow">Trend overview</div>
            <div class="trends-chart-copy" style="max-width:none;margin:6px 0 14px;">
              Use these signals to track recurring issue volume, publisher concentration, and the patterns most likely to need upstream remediation.
              <button class="trends-inline-link" type="button" onclick="openCategoryDefinitions()">Category definitions</button>
            </div>
            <div id="trends-kpi-host"></div>
          </div>
          <article class="trends-chart-card">
            <div class="trends-chart-header">
              <div>
                <div class="trends-chart-title">Issue mix</div>
                <div class="trends-chart-copy">A category-level view of recurring issue pressure across the current Trends slice.</div>
              </div>
            </div>
            <div class="trends-chart-shell">
              <div class="trends-pie" id="trends-pie">
                <div class="trends-pie-center">
                  <div class="trends-pie-value" id="trends-pie-total">0</div>
                  <div class="trends-pie-label">Occurrences</div>
                </div>
              </div>
              <div class="trends-legend" id="trends-legend"></div>
            </div>
          </article>
        </div>
      `;
      var trendsTableShellExisting = trendsPanel.querySelector(".trends-table-shell");
      trendsPanel.insertBefore(trendsOverview, trendsTableShellExisting || trendsPanel.lastChild);
      var kpiHost = document.getElementById("trends-kpi-host");
      if (kpiHost) kpiHost.appendChild(trendsStats);
    }

    window.updateTrendsSpotlights = function () {
      var trendsHealthScore = document.getElementById("trends-health-score");
      var trendsHealthCopy = document.getElementById("trends-health-copy");
      var trendsHealthPosture = document.getElementById("trends-health-posture");
      var trendsHealthPostureCopy = document.getElementById("trends-health-posture-copy");
      var trendsMovementValue = document.getElementById("trends-movement-value");
      var trendsMovementCopy = document.getElementById("trends-movement-copy");
      var trendsAgingValue = document.getElementById("trends-aging-value");
      var trendsAgingCopy = document.getElementById("trends-aging-copy");
      var trendsSummaryStrip = document.getElementById("trends-summary-strip");
      var topField = document.getElementById("trends-top-field");
      var topFieldCopy = document.getElementById("trends-top-field-copy");
      var topPublisher = document.getElementById("trends-top-publisher");
      var topPublisherCopy = document.getElementById("trends-top-publisher-copy");
      var topCategory = document.getElementById("trends-top-category");
      var topCategoryCopy = document.getElementById("trends-top-category-copy");
      var topEntity = document.getElementById("trends-top-entity");
      var topEntityCopy = document.getElementById("trends-top-entity-copy");
      var trendsPie = document.getElementById("trends-pie");
      var trendsPieTotal = document.getElementById("trends-pie-total");
      var trendsLegend = document.getElementById("trends-legend");
      if (!topField || !topPublisher || !topCategory || !topEntity) return;

      var activeData = Array.isArray(_catalogFiltered) ? _catalogFiltered : [];
      var hasTrendFilters = !!((document.getElementById("catalog-search") && document.getElementById("catalog-search").value) ||
        (document.getElementById("catalog-market-filter") && document.getElementById("catalog-market-filter").value));
      var sourceData = hasTrendFilters ? activeData : _catalogData;

      if (!sourceData || !sourceData.length) {
        if (trendsHealthScore) trendsHealthScore.textContent = "100";
        if (trendsHealthCopy) trendsHealthCopy.textContent = "A lightweight internal score that drops as recurring issue volume concentrates across history.";
        if (trendsHealthPosture) trendsHealthPosture.textContent = "Healthy";
        if (trendsHealthPostureCopy) trendsHealthPostureCopy.textContent = "Use the spotlight cards and row details below to decide what should be fixed upstream first.";
        if (trendsMovementValue) trendsMovementValue.textContent = "Stable";
        if (trendsMovementCopy) trendsMovementCopy.textContent = "Run more validations to compare the last seven days to the previous seven.";
        if (trendsAgingValue) trendsAgingValue.textContent = "—";
        if (trendsAgingCopy) trendsAgingCopy.textContent = "Once recurring issues are stored, this will show the oldest active trend in the current slice.";
        if (trendsSummaryStrip) trendsSummaryStrip.textContent = "Run and retain validations to generate an executive summary of recurring issue pressure, concentration, and movement.";
        topField.textContent = "Awaiting history";
        topPublisher.textContent = "Awaiting history";
        topCategory.textContent = "Awaiting history";
        topEntity.textContent = "Awaiting history";
        if (topFieldCopy) topFieldCopy.textContent = "Run validations to surface which field repeats most across submissions.";
        if (topPublisherCopy) topPublisherCopy.textContent = "This spot helps teams see where repeated issue volume is accumulating.";
        if (topCategoryCopy) topCategoryCopy.textContent = "Use this to decide whether you are dealing with completeness, enum, or type quality problems.";
        if (topEntityCopy) topEntityCopy.textContent = "High concentration here usually points to the best upstream cleanup opportunity.";
        if (trendsPie) trendsPie.style.background = "conic-gradient(#dbe3ef 0deg 360deg)";
        if (trendsPieTotal) trendsPieTotal.textContent = "0";
        if (trendsLegend) trendsLegend.innerHTML = '<div class="trends-legend-row"><span class="trends-legend-label"><span class="trends-legend-dot" style="background:#dbe3ef"></span>No trend data yet</span><span class="trends-legend-value">0%</span></div>';
        return;
      }

      var byPublisher = {};
      var byCategory = {};
      var byEntity = {};
      var totalOccurrences = 0;
      sourceData.forEach(function (entry) {
        totalOccurrences += entry.count || 0;
        (entry.publishers || []).forEach(function (publisher) {
          byPublisher[publisher] = (byPublisher[publisher] || 0) + entry.count;
        });
        byCategory[entry.errorCategory] = (byCategory[entry.errorCategory] || 0) + entry.count;
        (entry.entityTypes || [entry.entityType]).forEach(function (entityType) {
          if (!entityType) return;
          byEntity[entityType] = (byEntity[entityType] || 0) + entry.count;
        });
      });

      var topFieldEntry = sourceData[0];
      var topPublisherEntry = Object.entries(byPublisher).sort(function (a, b) { return b[1] - a[1]; })[0];
      var topCategoryEntry = Object.entries(byCategory).sort(function (a, b) { return b[1] - a[1]; })[0];
      var topEntityEntry = Object.entries(byEntity).sort(function (a, b) { return b[1] - a[1]; })[0];
      var scorePenalty = Math.min(45, Math.floor(totalOccurrences / 8)) + Math.min(20, sourceData.length * 3);
      var healthScore = Math.max(18, 100 - scorePenalty);
      var posture = healthScore >= 80 ? "Healthy" : healthScore >= 60 ? "Watch" : healthScore >= 40 ? "Needs attention" : "At risk";
      var now = new Date();
      var searchText = ((document.getElementById("catalog-search") && document.getElementById("catalog-search").value) || "").trim().toLowerCase();
      var marketFilter = ((document.getElementById("catalog-market-filter") && document.getElementById("catalog-market-filter").value) || "").trim();
      var sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      var fourteenDaysAgo = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);
      var historyRuns = loadHistory();
      var recentWindowCount = 0;
      var previousWindowCount = 0;
      historyRuns.forEach(function (run) {
        var runDate = parseTrendRunDate(run);
        if (!runDate) return;
        var matchingErrors = (run.errors || []).filter(function (err) {
          return runErrorMatchesTrendFilters(err, run, searchText, marketFilter);
        }).length;
        if (!matchingErrors) return;
        if (runDate >= sevenDaysAgo) recentWindowCount += matchingErrors;
        else if (runDate >= fourteenDaysAgo) previousWindowCount += matchingErrors;
      });
      var movementDelta = recentWindowCount - previousWindowCount;
      var movementLabel = movementDelta > 0 ? "+" + movementDelta : movementDelta < 0 ? String(movementDelta) : "Flat";
      var oldestEntry = sourceData.slice().sort(function (a, b) {
        return new Date(a.firstSeen || a.lastSeen || 0) - new Date(b.firstSeen || b.lastSeen || 0);
      })[0];
      var oldestDate = oldestEntry ? new Date(oldestEntry.firstSeen || oldestEntry.lastSeen || now) : null;
      var oldestDays = oldestDate && !isNaN(oldestDate.getTime()) ? Math.max(0, Math.floor((now.getTime() - oldestDate.getTime()) / (24 * 60 * 60 * 1000))) : null;

      if (trendsHealthScore) trendsHealthScore.textContent = String(healthScore);
      if (trendsHealthCopy) trendsHealthCopy.textContent = totalOccurrences + " recurring issue occurrences across " + sourceData.length + " distinct trends are influencing this score.";
      if (trendsHealthPosture) trendsHealthPosture.textContent = posture;
      if (trendsHealthPostureCopy) trendsHealthPostureCopy.textContent = (topCategoryEntry ? topCategoryEntry[0] : "Recurring issues") + " is currently the strongest pressure point in history.";
      if (trendsMovementValue) trendsMovementValue.textContent = movementLabel;
      if (trendsMovementCopy) trendsMovementCopy.textContent = recentWindowCount + " matched occurrences in the last 7 days versus " + previousWindowCount + " in the previous 7-day window.";
      if (trendsAgingValue) trendsAgingValue.textContent = oldestDays == null ? "—" : oldestDays + "d";
      if (trendsAgingCopy) trendsAgingCopy.textContent = oldestEntry ? '"' + oldestEntry.field + '" has been recurring since ' + (oldestEntry.firstSeen || oldestEntry.lastSeen || 'the first stored run') + '.' : "Once recurring issues are stored, this will show the oldest active trend in the current slice.";
      if (trendsSummaryStrip) trendsSummaryStrip.textContent = sourceData.length + " recurring issues account for " + totalOccurrences + " occurrences in the current Trends view. " + (topCategoryEntry ? topCategoryEntry[0] : "This issue class") + " is the dominant pattern, and " + (topPublisherEntry ? topPublisherEntry[0] : "the top publisher") + " carries the highest visible concentration.";

      topField.textContent = topFieldEntry ? topFieldEntry.field : "None yet";
      topPublisher.textContent = topPublisherEntry ? topPublisherEntry[0] : "None yet";
      topCategory.textContent = topCategoryEntry ? topCategoryEntry[0] : "None yet";
      topEntity.textContent = topEntityEntry ? topEntityEntry[0] : "None yet";

      if (topFieldCopy && topFieldEntry) topFieldCopy.textContent = topFieldEntry.count + " occurrences across " + (topFieldEntry.envelopeIds ? topFieldEntry.envelopeIds.length : 0) + " envelopes; fixing this field offers the biggest immediate payoff.";
      if (topPublisherCopy && topPublisherEntry) topPublisherCopy.textContent = topPublisherEntry[1] + " issue occurrences currently tie back to this publisher across stored history.";
      if (topCategoryCopy && topCategoryEntry) topCategoryCopy.textContent = topCategoryEntry[1] + " occurrences currently roll up into this issue class.";
      if (topEntityCopy && topEntityEntry) topEntityCopy.textContent = topEntityEntry[1] + " occurrences currently map to this entity type, making it the strongest remediation target.";
      var topPublisherCard = topPublisher ? topPublisher.closest(".trends-spotlight") : null;
      if (topPublisherCard) {
        topPublisherCard.classList.add("clickable");
        topPublisherCard.setAttribute("tabindex", "0");
        topPublisherCard.onclick = function () { openPublisherDetail(topPublisher.textContent || ""); };
        topPublisherCard.onkeydown = function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openPublisherDetail(topPublisher.textContent || "");
          }
        };
      }

      var palette = {
        "Missing Field": "#d96b15",
        "Enum / Invalid Value": "#2d5e78",
        "Type Error": "#c44536",
        "Extra Field": "#7b5cff",
        "Wrong Field Name": "#1d6b7d",
        "Invalid Entity Type": "#7f5539",
        "Other": "#8d99ae"
      };
      var orderedCategories = Object.entries(byCategory).sort(function (a, b) { return b[1] - a[1]; });
      var angle = 0;
      var gradientParts = [];
      var legendHtml = [];
      orderedCategories.forEach(function (entry) {
        var label = entry[0];
        var value = entry[1];
        var slice = totalOccurrences ? (value / totalOccurrences) * 360 : 0;
        var nextAngle = angle + slice;
        var color = palette[label] || palette.Other;
        gradientParts.push(color + " " + angle + "deg " + nextAngle + "deg");
        legendHtml.push('<div class="trends-legend-row"><span class="trends-legend-label"><span class="trends-legend-dot" style="background:' + color + '"></span>' + escHtml(label) + '</span><span class="trends-legend-value">' + Math.round((value / totalOccurrences) * 100) + '%</span></div>');
        angle = nextAngle;
      });
      if (trendsPie) trendsPie.style.background = "conic-gradient(" + gradientParts.join(", ") + ")";
      if (trendsPieTotal) trendsPieTotal.textContent = String(totalOccurrences);
      if (trendsLegend) trendsLegend.innerHTML = legendHtml.join("");
    };

    var catalogContainer = document.getElementById("catalog-table-container");
    if (catalogContainer && !catalogContainer.parentElement.classList.contains("trends-table-shell")) {
      var tableShell = document.createElement("div");
      tableShell.className = "trends-table-shell";
      catalogContainer.parentNode.insertBefore(tableShell, catalogContainer);
      tableShell.appendChild(catalogContainer);
    }

    var trendsSpotlightsPanel = document.getElementById("trends-spotlights");
    var trendsTableShell = trendsPanel ? trendsPanel.querySelector(".trends-table-shell") : null;
    if (trendsPanel && trendsSpotlightsPanel && trendsTableShell) {
      trendsPanel.insertBefore(trendsSpotlightsPanel, trendsTableShell);
    }

    var paneHeaders = document.querySelectorAll(".pane-header");
    if (paneHeaders[0] && !paneHeaders[0].querySelector(".hero-eyebrow")) {
      paneHeaders[0].style.padding = "16px 18px";
    }
    if (paneHeaders[1]) {
      paneHeaders[1].style.padding = "16px 18px";
    }

    var summaryBar = document.getElementById("summary-bar");
    if (summaryBar) {
      summaryBar.setAttribute("data-modernized", "true");
    }

    stateSelect = document.getElementById("state-select");
    if (stateSelect) {
      stateSelect.style.minWidth = "180px";
    }

    var settingsTitles = document.querySelectorAll(".settings-section-title");
    settingsTitles.forEach(function (node) {
      if (node.textContent.indexOf("Error Library") !== -1) {
        node.textContent = "Error Translation Library";
      }
    });

    var settingsTitle = document.querySelector(".settings-title");
    if (settingsTitle) {
      settingsTitle.textContent = "Workspace Settings";
    }

    if (typeof window.onStateChange === "function" && !window.__modernStateWrapped) {
      var originalOnStateChange = window.onStateChange;
      window.onStateChange = function () {
        originalOnStateChange();
        var select = document.getElementById("state-select");
        var heroMarket = null;
        var heroMarketCode = document.getElementById("hero-market-code");
        var heroMarketName = document.getElementById("hero-market-name");
        if (select && heroMarket) {
          var label = select.options[select.selectedIndex].dataset.label || select.value;
          heroMarket.textContent = label.replace(/·/g, "").replace(/\s{2,}/g, " ").trim();
        }
        if (select && heroMarketCode && heroMarketName) {
          var marketLabel = (select.options[select.selectedIndex].dataset.label || select.value).replace(/Â·/g, "").replace(/\s{2,}/g, " ").trim();
          marketLabel = marketLabel.replace(/[^A-Za-z0-9 ]/g, " ").replace(/\s{2,}/g, " ").trim();
          var parts = marketLabel.split(" ");
          heroMarketCode.textContent = parts[0] || select.value;
          heroMarketName.textContent = parts.slice(1).join(" ") || "Active market";
        }
      };
      window.__modernStateWrapped = true;
    }

    if (typeof window.onStateChange === "function") {
      window.onStateChange();
    }

    if (typeof window.updateTrendsSpotlights === "function") {
      window.updateTrendsSpotlights();
    }

    function enableScrollHandoff(element) {
      if (!element || element.getAttribute("data-scroll-handoff") === "true") return;
      element.addEventListener("wheel", function (event) {
        var delta = event.deltaY;
        if (!delta) return;
        var atTop = element.scrollTop <= 0;
        var atBottom = Math.ceil(element.scrollTop + element.clientHeight) >= element.scrollHeight;
        if ((delta < 0 && atTop) || (delta > 0 && atBottom)) {
          event.preventDefault();
          window.scrollBy({ top: delta, behavior: "auto" });
        }
      }, { passive: false });
      element.setAttribute("data-scroll-handoff", "true");
    }

    enableScrollHandoff(document.getElementById("input-area"));
    enableScrollHandoff(document.getElementById("results-area"));
    enableScrollHandoff(document.getElementById("history-list"));
  })();
