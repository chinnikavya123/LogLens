
const $ = id => document.getElementById(id);

let logs = [];
let currentPage = 1;
const pageSize = 12;
let compareA = null;
let compareB = null;
let toastTimer;

const severityOrder = {CRITICAL:0,ERROR:1,WARNING:2,INFO:3};
const colors = {
  CRITICAL:"#ff5576",ERROR:"#ff9867",WARNING:"#f2c96b",INFO:"#648dff"
};

function notify(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"),2800);
}

function classify(message) {
  const text = message.toLowerCase();

  if (/\b(fatal|critical|emergency|panic|out of memory|database corruption)\b/.test(text)) return "CRITICAL";
  if (/\b(error|exception|failed|failure|traceback|refused|denied|timeout|500|502|503|504)\b/.test(text)) return "ERROR";
  if (/\b(warn|warning|deprecated|retry|slow|unavailable|rate limit)\b/.test(text)) return "WARNING";
  return "INFO";
}

function extractTimestamp(line) {
  const match = line.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/);
  if (!match) return null;

  const date = new Date(match[0].replace(" ","T"));
  return Number.isNaN(date.getTime()) ? null : date;
}

function extractService(line) {
  const patterns = [
    /\bservice[=: ]+([a-zA-Z0-9_.-]+)/i,
    /\bmodule[=: ]+([a-zA-Z0-9_.-]+)/i,
    /\[([a-zA-Z0-9_.-]+)\]/
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) return match[1];
  }

  const common = line.match(/\b(api|auth|database|db|server|payment|frontend|backend|worker|gateway|cache|nginx|mysql|mongodb|redis)\b/i);
  return common ? common[1] : "Application";
}

function parseLogs(content, fileName) {
  const lines = content.split(/\r?\n/).filter(line => line.trim());
  const parsed = [];

  lines.forEach((line,index) => {
    const timestamp = extractTimestamp(line);
    const levelMatch = line.match(/\b(critical|fatal|emergency|panic|error|err|warning|warn|info|debug|trace)\b/i);
    const severity = classify(line);

    parsed.push({
      id: `${fileName}-${Date.now()}-${index}`,
      timestamp,
      timeLabel: timestamp ? timestamp.toLocaleString() : `Line ${index+1}`,
      service: extractService(line),
      severity,
      message: line.trim(),
      file: fileName,
      lineNumber: index+1
    });
  });

  return parsed;
}

async function handleFiles(files) {
  const selected = Array.from(files).filter(file =>
    /\.(log|txt)$/i.test(file.name) || file.type === "text/plain"
  );

  if (!selected.length) {
    notify("Please select a .log or .txt file.");
    return;
  }

  for (const file of selected) {
    try {
      const content = await file.text();
      const parsed = parseLogs(content,file.name);
      logs.push(...parsed);
      notify(`${file.name}: ${parsed.length} entries analyzed.`);
    } catch {
      notify(`Could not read ${file.name}.`);
    }
  }

  currentPage = 1;
  refreshDashboard();
  renderExplorer();
  renderIncidents();
  renderFindings();
  renderReport();
  updateFileFilter();
}

function getMaskedMessage(message) {
  if (!$("maskToggle").checked) return message;

  return message
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,"[EMAIL REDACTED]")
    .replace(/\b(?:Bearer\s+)?(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g,"[TOKEN REDACTED]")
    .replace(/((?:api[_-]?key|token|password|secret)\s*[=:]\s*)["']?[^ "';,]+/gi,"$1[REDACTED]");
}

function getStats() {
  const stats = {CRITICAL:0,ERROR:0,WARNING:0,INFO:0};
  logs.forEach(log => stats[log.severity]++);
  return stats;
}

function getHealth(stats) {
  if (!logs.length) return null;
  const score = 100 - (stats.CRITICAL * 15 + stats.ERROR * 8 + stats.WARNING * 2) / logs.length * 10;
  return Math.max(0,Math.min(100,Math.round(score)));
}

function refreshDashboard() {
  const stats = getStats();
  const health = getHealth(stats);

  $("totalLogs").textContent = logs.length.toLocaleString();
  $("criticalLogs").textContent = stats.CRITICAL.toLocaleString();
  $("errorLogs").textContent = stats.ERROR.toLocaleString();
  $("warningLogs").textContent = stats.WARNING.toLocaleString();
  $("chartTotal").textContent = logs.length.toLocaleString();
  $("failureCount").textContent = stats.CRITICAL + stats.ERROR;
  $("healthWarnings").textContent = stats.WARNING;
  $("sessionLabel").textContent = logs.length ? `${logs.length} entries analyzed` : "Waiting for log files";
  $("healthScore").textContent = health === null ? "—" : health;
  $("healthBar").style.width = `${health || 0}%`;

  $("healthMessage").textContent = health === null
    ? "Upload logs to calculate application health."
    : health >= 90 ? "Healthy — few issues detected."
    : health >= 70 ? "Fair — some issues need attention."
    : health >= 40 ? "Unstable — investigate detected errors."
    : "Critical — immediate investigation recommended.";

  $("healthMessage").style.color = health === null ? "var(--muted)" : health >= 70 ? "var(--green)" : "var(--red)";

  $("chartLegend").innerHTML = Object.entries(stats).map(([level,count]) =>
    `<span><i class="legend-dot ${level.toLowerCase()}"></i>${level.charAt(0)+level.slice(1).toLowerCase()} <b>${count}</b></span>`
  ).join("");

  drawChart(stats);
  renderRecent();
  $("incidentCount").textContent = stats.CRITICAL + stats.ERROR;
  $("patternCount").textContent = getPatterns().length;
  $("serviceCount").textContent = new Set(logs.map(log => log.service)).size;
}

function drawChart(stats) {
  const canvas = $("distributionChart");
  const ctx = canvas.getContext("2d");
  const ratio = window.devicePixelRatio || 1;
  const size = 190;

  canvas.width = size * ratio;
  canvas.height = size * ratio;
  ctx.scale(ratio,ratio);
  ctx.clearRect(0,0,size,size);

  const total = Object.values(stats).reduce((a,b)=>a+b,0);
  const entries = Object.entries(stats);
  let angle = -Math.PI/2;

  if (!total) {
    ctx.beginPath();
    ctx.arc(95,95,69,0,Math.PI*2);
    ctx.strokeStyle = "#26334a";
    ctx.lineWidth = 17;
    ctx.stroke();
    return;
  }

  entries.forEach(([level,count]) => {
    if (!count) return;
    const next = angle + count / total * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(95,95,69,angle,next);
    ctx.strokeStyle = colors[level];
    ctx.lineWidth = 17;
    ctx.lineCap = "butt";
    ctx.stroke();
    angle = next;
  });
}

function renderRecent() {
  const recent = [...logs].reverse().slice(0,5);
  $("recentLogs").innerHTML = recent.length ? recent.map(log => `
    <div class="recent-item">
      <span class="badge badge-${log.severity}">${log.severity}</span>
      <div><p title="${escapeHTML(log.message)}">${escapeHTML(getMaskedMessage(log.message))}</p>
      <small>${escapeHTML(log.service)} · ${escapeHTML(log.timeLabel)}</small></div>
    </div>
  `).join("") : `<div class="empty-state compact">No log activity yet. Upload a file to get started.</div>`;
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g,char => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[char]);
}

function updateFileFilter() {
  const select = $("fileFilter");
  const current = select.value;
  const files = [...new Set(logs.map(log => log.file))];

  select.innerHTML = `<option value="ALL">All files</option>` +
    files.map(file => `<option value="${escapeHTML(file)}">${escapeHTML(file)}</option>`).join("");

  if (files.includes(current)) select.value = current;
}

function getFilteredLogs() {
  const query = $("searchInput").value.toLowerCase().trim();
  const level = $("levelFilter").value;
  const file = $("fileFilter").value;

  return logs.filter(log =>
    (level === "ALL" || log.severity === level) &&
    (file === "ALL" || log.file === file) &&
    (!query || `${log.message} ${log.service} ${log.file} ${log.severity}`.toLowerCase().includes(query))
  );
}

function renderExplorer() {
  const filtered = getFilteredLogs();
  const totalPages = Math.max(1,Math.ceil(filtered.length/pageSize));
  currentPage = Math.min(currentPage,totalPages);

  const start = (currentPage-1)*pageSize;
  const pageLogs = filtered.slice(start,start+pageSize);

  $("resultCount").textContent = `${filtered.length} matching entries`;
  $("pageInfo").textContent = filtered.length
    ? `Showing ${start+1}–${Math.min(start+pageSize,filtered.length)} of ${filtered.length}`
    : "Showing 0 entries";

  $("prevPage").disabled = currentPage <= 1;
  $("nextPage").disabled = currentPage >= totalPages;

  $("logTable").innerHTML = pageLogs.length ? pageLogs.map(log => `
    <tr>
      <td><span class="badge badge-${log.severity}">${log.severity}</span></td>
      <td>${escapeHTML(log.timeLabel)}</td>
      <td>${escapeHTML(log.service)}</td>
      <td class="message-cell" title="${escapeHTML(getMaskedMessage(log.message))}">${escapeHTML(getMaskedMessage(log.message))}</td>
      <td>${escapeHTML(log.file)}</td>
    </tr>
  `).join("") : `<tr><td colspan="5"><div class="empty-state">No matching logs found.</div></td></tr>`;
}

function getPatterns() {
  const groups = new Map();

  logs.filter(log => ["CRITICAL","ERROR"].includes(log.severity)).forEach(log => {
    const key = log.message
      .replace(/\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}/g,"[TIME]")
      .replace(/\b\d+\b/g,"[N]")
      .trim()
      .slice(0,160);

    if (!groups.has(key)) groups.set(key,[]);
    groups.get(key).push(log);
  });

  return [...groups.entries()]
    .map(([message,items]) => ({message,items}))
    .sort((a,b)=>b.items.length-a.items.length);
}

function renderIncidents() {
  const incidents = logs.filter(log => ["CRITICAL","ERROR"].includes(log.severity))
    .sort((a,b) => (b.timestamp?.getTime() || 0)-(a.timestamp?.getTime() || 0));

  $("timelineList").innerHTML = incidents.length ? incidents.slice(0,40).map(log => `
    <div class="timeline-item">
      <span class="timeline-marker" style="background:${colors[log.severity]}"></span>
      <h4>${log.severity} · ${escapeHTML(log.service)}</h4>
      <p>${escapeHTML(getMaskedMessage(log.message))}</p>
      <small>${escapeHTML(log.timeLabel)} · ${escapeHTML(log.file)} · Line ${log.lineNumber}</small>
    </div>
  `).join("") : `<div class="empty-state">No critical or error events detected.</div>`;

  const patterns = getPatterns();
  $("patternsList").innerHTML = patterns.length ? patterns.slice(0,10).map(pattern => `
    <div class="pattern-row">
      <span class="badge badge-ERROR">${pattern.items[0].severity}</span>
      <div><strong>${pattern.items.length} occurrences</strong>
      <p>${escapeHTML(getMaskedMessage(pattern.message))}</p>
      <p>Services: ${escapeHTML([...new Set(pattern.items.map(item=>item.service))].join(", "))}</p></div>
    </div>
  `).join("") : `<div class="empty-state compact">No repeated error patterns detected.</div>`;
}

function investigate(message) {
  const text = message.toLowerCase();

  const rules = [
    {
      match:/timeout|timed out/,
      title:"Possible request or service timeout",
      cause:"A service may be taking longer than the configured request timeout. Network delays, slow database queries or an overloaded service could be responsible.",
      steps:["Check response times and service latency.","Inspect database query performance.","Review timeout settings and upstream service health."]
    },
    {
      match:/connection refused|econnrefused|connection reset/,
      title:"Possible connection or service availability issue",
      cause:"The application could not establish or maintain a connection. The destination service may be down, unreachable or listening on a different port.",
      steps:["Verify that the destination service is running.","Check hostnames, ports and network connectivity.","Inspect firewall and service configuration."]
    },
    {
      match:/out of memory|heap|memory/,
      title:"Possible memory exhaustion",
      cause:"The process may have exhausted available memory. Large objects, memory leaks or unusually high traffic could contribute.",
      steps:["Inspect memory usage and application metrics.","Review recent changes that allocate large objects.","Check process limits and memory leak reports."]
    },
    {
      match:/permission denied|unauthorized|forbidden|access denied|401|403/,
      title:"Possible authentication or permission issue",
      cause:"A request or process may not have the required credentials or access permissions.",
      steps:["Verify credentials and token expiry.","Check user roles and resource permissions.","Inspect authentication and authorization configuration."]
    },
    {
      match:/database|sql|mongodb|mysql|postgres|query failed/,
      title:"Possible database issue",
      cause:"The database operation may have failed due to connectivity, query errors, resource limits or unavailable database services.",
      steps:["Check database availability and connection pools.","Inspect the query and database error details.","Review database capacity, locks and recent schema changes."]
    },
    {
      match:/rate limit|too many requests|429/,
      title:"Possible rate limiting",
      cause:"The application or an external service may be receiving more requests than its configured limit allows.",
      steps:["Inspect request volume and rate-limit responses.","Review retry and backoff behavior.","Check API quotas and client request patterns."]
    },
    {
      match:/dns|enotfound|name resolution/,
      title:"Possible DNS or hostname resolution issue",
      cause:"The application may be unable to resolve a service hostname.",
      steps:["Verify the hostname and DNS configuration.","Check network connectivity.","Inspect DNS records and service discovery."]
    },
    {
      match:/disk full|no space left/,
      title:"Possible disk capacity issue",
      cause:"The system may have run out of available storage.",
      steps:["Check free disk space.","Inspect large log files and temporary files.","Review storage limits and cleanup policies."]
    },
    {
      match:/ssl|certificate|tls|handshake/,
      title:"Possible TLS or certificate issue",
      cause:"A secure connection may be failing because of certificate validity, trust or protocol configuration.",
      steps:["Check certificate expiry and certificate chain.","Verify TLS configuration on both endpoints.","Inspect hostname and trust-store settings."]
    }
  ];

  const matched = rules.find(rule => rule.match.test(text));

  return matched || {
    title:"Unclassified application error",
    cause:"The log contains an error, but its message does not match a known diagnostic pattern. More application context or a stack trace may be needed to identify the cause.",
    steps:["Inspect the complete stack trace and surrounding log entries.","Check recent code and configuration changes.","Reproduce the issue and review related service logs."]
  };
}

function renderFindings() {
  const patterns = getPatterns();
  const findings = patterns.map(pattern => ({
    ...pattern,
    analysis:investigate(pattern.message),
    severity:pattern.items.some(item=>item.severity==="CRITICAL") ? "CRITICAL" : "ERROR"
  }));

  $("findingCount").textContent = `${findings.length} findings`;

  $("findingsList").innerHTML = findings.length ? findings.slice(0,15).map((finding,index) => `
    <div class="finding-row">
      <div class="finding-severity">✧</div>
      <div class="finding-content">
        <h4>${index+1}. ${escapeHTML(finding.analysis.title)}</h4>
        <p><strong>Observed pattern:</strong> ${escapeHTML(getMaskedMessage(finding.message))}</p>
        <p><strong>Occurrences:</strong> ${finding.items.length} · <strong>Severity:</strong> ${finding.severity}</p>
        <p style="margin-top:8px"><strong>Likely cause:</strong> ${escapeHTML(finding.analysis.cause)}</p>
        <p class="suggestion"><strong>Suggested debugging steps:</strong> ${finding.analysis.steps.map(escapeHTML).join(" · ")}</p>
      </div>
    </div>
  `).join("") : `<div class="empty-state">No errors to investigate. Upload logs containing errors or critical events.</div>`;
}

function renderReport() {
  const stats = getStats();
  const health = getHealth(stats);
  const patterns = getPatterns();

  $("reportMeta").textContent = logs.length
    ? `${logs.length} log entries · ${new Date().toLocaleString()}`
    : "No analysis session available";

  $("reportStats").innerHTML = [
    ["Total logs",logs.length],
    ["Critical",stats.CRITICAL],
    ["Errors",stats.ERROR],
    ["Warnings",stats.WARNING]
  ].map(([label,value]) => `
    <div class="report-stat"><span>${label}</span><strong>${value}</strong></div>
  `).join("") + `
    <div class="report-stat"><span>Health score</span><strong>${health ?? "—"}${health === null ? "" : "/100"}</strong></div>
    <div class="report-stat"><span>Error patterns</span><strong>${patterns.length}</strong></div>
  `;
}

function downloadReport() {
  if (!logs.length) {
    notify("Upload logs before generating a report.");
    return;
  }

  const stats = getStats();
  const health = getHealth(stats);
  const patterns = getPatterns();
  const findings = patterns.map(item => investigate(item.message));

  const report = [
    "LOGLENS — LOG ANALYSIS REPORT",
    "====================================",
    `Generated: ${new Date().toLocaleString()}`,
    `Total log entries: ${logs.length}`,
    `Application health score: ${health}/100`,
    "",
    "SEVERITY DISTRIBUTION",
    ...Object.entries(stats).map(([level,count])=>`${level}: ${count}`),
    "",
    "FILES ANALYZED",
    ...[...new Set(logs.map(log=>log.file))].map(file=>`- ${file}`),
    "",
    "REPEATED ERROR PATTERNS",
    ...patterns.map(pattern=>`- ${pattern.items.length} occurrences: ${getMaskedMessage(pattern.message)}`),
    "",
    "ROOT CAUSE INVESTIGATION",
    ...findings.map((finding,index)=>[
      `${index+1}. ${finding.title}`,
      `Likely cause: ${finding.cause}`,
      ...finding.steps.map(step=>`- ${step}`),
      ""
    ].join("\n")),
    "",
    "Note: Root cause suggestions are rule-based diagnostic hints, not confirmed causes.",
    "Sensitive values may be masked depending on your current masking setting."
  ].join("\n");

  downloadText(report,"loglens-analysis-report.txt");
}

function downloadText(content,fileName) {
  const blob = new Blob([content],{type:"text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(url);
}

function compareFiles() {
  if (!compareA || !compareB) {
    notify("Please select both files before comparing.");
    return;
  }

  const a = parseLogs(compareA.content,compareA.name);
  const b = parseLogs(compareB.content,compareB.name);

  const countErrors = items => items.filter(item=>["CRITICAL","ERROR"].includes(item.severity)).length;
  const countWarnings = items => items.filter(item=>item.severity==="WARNING").length;

  const errorsA = countErrors(a);
  const errorsB = countErrors(b);
  const warningsA = countWarnings(a);
  const warningsB = countWarnings(b);

  const signatures = items => {
    const map = new Map();
    items.filter(item=>["CRITICAL","ERROR"].includes(item.severity)).forEach(item => {
      const key = item.message.replace(/\b\d+\b/g,"[N]").slice(0,150);
      map.set(key,(map.get(key)||0)+1);
    });
    return map;
  };

  const mapA = signatures(a);
  const mapB = signatures(b);

  const newIssues = [...mapB.keys()].filter(key=>!mapA.has(key));
  const resolvedIssues = [...mapA.keys()].filter(key=>!mapB.has(key));
  const recurring = [...mapB.entries()].filter(([key,count])=>mapA.has(key)&&count>mapA.get(key));

  $("compareResults").innerHTML = `
    <div class="panel compare-results">
      <div class="panel-heading"><div><h3>Comparison results</h3><p>${escapeHTML(compareA.name)} vs ${escapeHTML(compareB.name)}</p></div><span class="local-badge">COMPLETED</span></div>
      <div class="compare-metrics">
        <div><span>New error patterns</span><strong style="color:var(--red)">${newIssues.length}</strong></div>
        <div><span>Resolved patterns</span><strong style="color:var(--green)">${resolvedIssues.length}</strong></div>
        <div><span>Increased patterns</span><strong style="color:var(--orange)">${recurring.length}</strong></div>
      </div>
      <div class="compare-metrics">
        <div><span>File A errors</span><strong>${errorsA}</strong></div>
        <div><span>File B errors</span><strong>${errorsB}</strong></div>
        <div><span>Error difference</span><strong>${errorsB-errorsA>0?"+":""}${errorsB-errorsA}</strong></div>
      </div>
      <div class="pattern-row"><div><strong>New error patterns</strong><p>${newIssues.length?newIssues.map(escapeHTML).join("<br>"):"No new error patterns detected."}</p></div></div>
      <div class="pattern-row"><div><strong>Resolved error patterns</strong><p>${resolvedIssues.length?resolvedIssues.map(escapeHTML).join("<br>"):"No resolved patterns detected."}</p></div></div>
      <div class="pattern-row"><div><strong>Increased occurrences</strong><p>${recurring.length?recurring.map(([key,count])=>`${escapeHTML(key)} (${mapA.get(key)} → ${count})`).join("<br>"):"No increased recurring patterns."}</p></div></div>
      <p class="subtitle">Warning counts: ${warningsA} in File A and ${warningsB} in File B. Comparison uses normalized error-message patterns.</p>
    </div>
  `;
}

function switchSection(section) {
  document.querySelectorAll(".page-section").forEach(item => item.classList.toggle("active",item.id===section));
  document.querySelectorAll(".nav-link").forEach(item => item.classList.toggle("active",item.dataset.section===section));

  const active = document.querySelector(`.nav-link[data-section="${section}"]`);
  $("breadcrumbTitle").textContent = active ? active.textContent.trim() : "Overview";
  $("sidebar").classList.remove("open");

  if (section==="explorer") renderExplorer();
  if (section==="incidents") renderIncidents();
  if (section==="investigator") renderFindings();
  if (section==="reports") renderReport();
}

function readCompareFile(file,side) {
  if (!file) return;
  file.text().then(content => {
    const result = {name:file.name,content};
    if (side==="A") compareA=result;
    else compareB=result;

    $(`file${side}Name`).textContent = `${file.name} · ${(file.size/1024).toFixed(1)} KB`;
    notify(`File ${side} ready for comparison.`);
  }).catch(()=>notify("Unable to read the selected file."));
}

// Navigation
document.querySelectorAll(".nav-link").forEach(button => {
  button.addEventListener("click",()=>switchSection(button.dataset.section));
});

document.querySelectorAll("[data-go]").forEach(button => {
  button.addEventListener("click",()=>switchSection(button.dataset.go));
});

// File upload
$("uploadTopButton").addEventListener("click",()=>switchSection("explorer"));
$("bannerUpload").addEventListener("click",()=>switchSection("explorer"));
$("explorerUpload").addEventListener("click",()=>$("logFiles").click());
$("chooseFiles").addEventListener("click",()=>$("logFiles").click());

$("logFiles").addEventListener("change",event=>{
  handleFiles(event.target.files);
  event.target.value="";
});

// Drag and drop
const dropZone = $("dropZone");

dropZone.addEventListener("dragover",event=>{
  event.preventDefault();
  dropZone.style.borderColor="var(--purple)";
});

dropZone.addEventListener("dragleave",()=>{
  dropZone.style.borderColor="";
});

dropZone.addEventListener("drop",event=>{
  event.preventDefault();
  dropZone.style.borderColor="";
  handleFiles(event.dataTransfer.files);
});

// Search and filters
["searchInput","levelFilter","fileFilter"].forEach(id=>{
  $(id).addEventListener(id==="searchInput"?"input":"change",()=>{
    currentPage=1;
    renderExplorer();
  });
});

$("maskToggle").addEventListener("change",()=>{
  renderExplorer();
  renderRecent();
  renderIncidents();
  renderFindings();
});

$("prevPage").addEventListener("click",()=>{
  currentPage--;
  renderExplorer();
});

$("nextPage").addEventListener("click",()=>{
  currentPage++;
  renderExplorer();
});

// Clear session
$("clearLogs").addEventListener("click",()=>{
  if (!logs.length) return notify("There are no logs to clear.");

  if (!confirm("Clear all uploaded logs from this session?")) return;

  logs=[];
  currentPage=1;
  refreshDashboard();
  renderExplorer();
  renderIncidents();
  renderFindings();
  renderReport();
  updateFileFilter();
  notify("Analysis session cleared.");
});

// Compare files
$("compareFileA").addEventListener("change",event=>readCompareFile(event.target.files[0],"A"));
$("compareFileB").addEventListener("change",event=>readCompareFile(event.target.files[0],"B"));
$("runCompare").addEventListener("click",compareFiles);

// Reports
$("downloadReport").addEventListener("click",downloadReport);

// Theme
$("themeToggle").addEventListener("click",()=>{
  document.body.classList.toggle("light");
  localStorage.setItem("loglens-theme",document.body.classList.contains("light")?"light":"dark");
});

if (localStorage.getItem("loglens-theme")==="light") {
  document.body.classList.add("light");
}

// Mobile navigation
$("menuToggle").addEventListener("click",()=>{
  $("sidebar").classList.toggle("open");
});

// Initialize
refreshDashboard();
renderExplorer();
renderIncidents();
renderFindings();
renderReport();
