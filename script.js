
"use strict";

/* =========================================
   LOGLENS — APPLICATION LOGIC
========================================= */

const $ = (id) => document.getElementById(id);

const state = {
  logs: [],
  currentPage: 1,
  pageSize: 12,
  compareA: [],
  compareB: [],
  toastTimer: null,
  compareRequest: 0
};

const severityOrder = {
  CRITICAL: 0,
  ERROR: 1,
  WARNING: 2,
  INFO: 3
};

const severityColors = {
  CRITICAL: "#ff526f",
  ERROR: "#ff806d",
  WARNING: "#f4bd62",
  INFO: "#65a9ff"
};

const sectionTitles = {
  overview: "Overview",
  explorer: "Log Explorer",
  incidents: "Incident Center",
  investigator: "Root Cause Investigator",
  compare: "Log Comparison",
  reports: "Reports"
};

/* =========================================
   GENERAL HELPERS
========================================= */

function notify(message, type = "success") {
  const toast = $("toast");
  if (!toast) return;

  toast.textContent = message;
  toast.className = `toast show ${type}`;

  clearTimeout(state.toastTimer);

  state.toastTimer = setTimeout(() => {
    toast.className = "toast";
  }, 3200);
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatTime(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return "Unknown time";
  }

  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function getFileName(file) {
  return file?.name || "unknown.log";
}

/* =========================================
   LOG CLASSIFICATION
========================================= */

function classify(message) {
  const text = String(message || "");

  const explicit = text.match(
    /\b(CRITICAL|FATAL|SEVERE|ERROR|ERR|WARNING|WARN|INFO|INFORMATIONAL|DEBUG|TRACE)\b/i
  );

  if (explicit) {
    const level = explicit[1].toUpperCase();

    if (["CRITICAL", "FATAL", "SEVERE"].includes(level)) {
      return "CRITICAL";
    }

    if (["ERROR", "ERR"].includes(level)) {
      return "ERROR";
    }

    if (["WARNING", "WARN"].includes(level)) {
      return "WARNING";
    }

    return "INFO";
  }

  if (
    /\b(out of memory|outofmemory|fatal|panic|unrecoverable|segmentation fault)\b/i.test(text)
  ) {
    return "CRITICAL";
  }

  if (
    /\b(exception|failed|failure|error|timeout|timed out|refused|denied)\b/i.test(text)
  ) {
    return "ERROR";
  }

  if (
    /\b(retry|slow|deprecated|warning|threshold exceeded|high latency)\b/i.test(text)
  ) {
    return "WARNING";
  }

  return "INFO";
}

/* =========================================
   TIMESTAMP AND SERVICE EXTRACTION
========================================= */

function extractTimestamp(line) {
  const patterns = [
    /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/,
    /\d{4}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}:\d{2}/,
    /\d{2}-\d{2}-\d{4}[ T]\d{2}:\d{2}:\d{2}/
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);

    if (match) {
      const parsed = new Date(match[0]);

      if (!Number.isNaN(parsed.getTime())) {
        return parsed;
      }
    }
  }

  return new Date();
}

function extractService(line) {
  const patterns = [
    /\bservice[=: ]+["']?([a-zA-Z0-9_.-]+)/i,
    /\bmodule[=: ]+["']?([a-zA-Z0-9_.-]+)/i,
    /\bcomponent[=: ]+["']?([a-zA-Z0-9_.-]+)/i,
    /\[([a-zA-Z0-9_.-]+)\]/
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);

    if (match) {
      return match[1];
    }
  }

  return "Application";
}

/* =========================================
   LOG PARSING
========================================= */

function parseLogs(text, fileName) {
  return String(text)
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line, index) => {
      const level = classify(line);

      return {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}-${index}`,
        timestamp: extractTimestamp(line),
        level,
        service: extractService(line),
        message: line.trim(),
        file: fileName,
        lineNumber: index + 1
      };
    });
}

async function handleFiles(fileList) {
  const files = Array.from(fileList || []);

  if (!files.length) return;

  const supported = files.filter((file) =>
    /\.(log|txt)$/i.test(file.name)
  );

  if (!supported.length) {
    notify("Please select .log or .txt files.", "error");
    return;
  }

  let added = 0;

  for (const file of supported) {
    try {
      const text = await file.text();
      const parsed = parseLogs(text, file.name);

      state.logs.push(...parsed);
      added += parsed.length;
    } catch (error) {
      console.error("File reading error:", error);
      notify(`Could not read ${file.name}.`, "error");
    }
  }

  state.currentPage = 1;
  refreshAll();

  if (added) {
    notify(`${formatNumber(added)} log entries imported successfully.`);
  } else {
    notify("No readable log entries were found.", "error");
  }
}

/* =========================================
   SENSITIVE DATA MASKING
========================================= */

function maskSensitiveData(message) {
  let text = String(message || "");

  text = text.replace(
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    "[REDACTED_EMAIL]"
  );

  text = text.replace(
    /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi,
    "$1[REDACTED]"
  );

  text = text.replace(
    /\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)\s*[:=]\s*["']?[^"',\s;]+/gi,
    "$1=[REDACTED]"
  );

  text = text.replace(
    /\b(sk-[A-Za-z0-9_-]{12,})\b/g,
    "[REDACTED_KEY]"
  );

  return text;
}

function getDisplayedMessage(message) {
  return $("maskToggle")?.checked
    ? maskSensitiveData(message)
    : message;
}

/* =========================================
   STATISTICS AND HEALTH SCORE
========================================= */

function getStats(logs = state.logs) {
  const stats = {
    total: logs.length,
    CRITICAL: 0,
    ERROR: 0,
    WARNING: 0,
    INFO: 0
  };

  logs.forEach((log) => {
    stats[log.level] = (stats[log.level] || 0) + 1;
  });

  return stats;
}

function getHealth(stats) {
  if (!stats.total) return 100;

  const weightedIssues =
    stats.CRITICAL * 4 +
    stats.ERROR * 2 +
    stats.WARNING;

  const maximumWeight = stats.total * 4;
  const issueRatio = weightedIssues / maximumWeight;

  return Math.max(0, Math.round(100 - issueRatio * 100));
}

function updateStats() {
  const stats = getStats();

  if ($("totalLogs")) {
    $("totalLogs").textContent = formatNumber(stats.total);
  }

  if ($("criticalLogs")) {
    $("criticalLogs").textContent = formatNumber(stats.CRITICAL);
  }

  if ($("errorLogs")) {
    $("errorLogs").textContent = formatNumber(stats.ERROR);
  }

  if ($("warningLogs")) {
    $("warningLogs").textContent = formatNumber(stats.WARNING);
  }

  const score = getHealth(stats);

  if ($("healthScore")) {
    $("healthScore").textContent = `${score}%`;
  }

  if ($("healthBar")) {
    $("healthBar").style.width = `${score}%`;
  }

  if ($("healthMessage")) {
    $("healthMessage").textContent =
      stats.total === 0
        ? "Upload logs to calculate system health."
        : score >= 85
          ? "Your logs indicate a healthy application."
          : score >= 60
            ? "Some issues need your attention."
            : "Significant errors detected. Investigate immediately.";
  }

  if ($("failureCount")) {
    $("failureCount").textContent =
      formatNumber(stats.CRITICAL + stats.ERROR);
  }

  if ($("healthWarnings")) {
    $("healthWarnings").textContent =
      formatNumber(stats.WARNING);
  }

  if ($("chartTotal")) {
    $("chartTotal").textContent = formatNumber(stats.total);
  }

  renderChart(stats);
}

/* =========================================
   DISTRIBUTION CHART
========================================= */

function renderChart(stats) {
  const canvas = $("distributionChart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const size = 190;
  const dpr = window.devicePixelRatio || 1;

  canvas.width = size * dpr;
  canvas.height = size * dpr;
  canvas.style.width = `${size}px`;
  canvas.style.height = `${size}px`;

  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, size, size);

  const values = [
    { name: "Critical", value: stats.CRITICAL, color: severityColors.CRITICAL },
    { name: "Error", value: stats.ERROR, color: severityColors.ERROR },
    { name: "Warning", value: stats.WARNING, color: severityColors.WARNING },
    { name: "Info", value: stats.INFO, color: severityColors.INFO }
  ];

  const total = values.reduce((sum, item) => sum + item.value, 0);

  if (!total) {
    ctx.beginPath();
    ctx.arc(95, 95, 68, 0, Math.PI * 2);
    ctx.strokeStyle = "#29364d";
    ctx.lineWidth = 17;
    ctx.stroke();
  } else {
    let start = -Math.PI / 2;

    values.forEach((item) => {
      if (!item.value) return;

      const angle = (item.value / total) * Math.PI * 2;

      ctx.beginPath();
      ctx.arc(95, 95, 68, start, start + angle);
      ctx.strokeStyle = item.color;
      ctx.lineWidth = 17;
      ctx.lineCap = "round";
      ctx.stroke();

      start += angle;
    });
  }

  const legend = $("chartLegend");

  if (legend) {
    legend.innerHTML = values.map((item) => `
      <div class="legend-item">
        <span class="legend-dot" style="background:${item.color}"></span>
        <span>${item.name}</span>
        <strong>${formatNumber(item.value)}</strong>
      </div>
    `).join("");
  }
}

/* =========================================
   RECENT LOGS
========================================= */

function renderRecent() {
  const container = $("recentLogs");
  if (!container) return;

  const recent = [...state.logs]
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, 6);

  if (!recent.length) {
    container.innerHTML = `
      <div class="empty-state">
        <span>No logs available yet.</span>
        <p>Upload a log file to see recent activity.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = recent.map((log) => `
    <div class="recent-log-item">
      <span class="severity-dot ${log.level.toLowerCase()}"></span>
      <div class="recent-log-content">
        <strong>${escapeHTML(log.service)}</strong>
        <p>${escapeHTML(getDisplayedMessage(log.message))}</p>
      </div>
      <span class="recent-log-time">${escapeHTML(formatTime(log.timestamp))}</span>
    </div>
  `).join("");
}

/* =========================================
   LOG EXPLORER
========================================= */

function getFilteredLogs() {
  const search = ($("searchInput")?.value || "").toLowerCase().trim();
  const level = $("levelFilter")?.value || "ALL";
  const file = $("fileFilter")?.value || "ALL";

  return state.logs.filter((log) => {
    const matchesSearch =
      !search ||
      log.message.toLowerCase().includes(search) ||
      log.service.toLowerCase().includes(search) ||
      log.file.toLowerCase().includes(search);

    const matchesLevel = level === "ALL" || log.level === level;
    const matchesFile = file === "ALL" || log.file === file;

    return matchesSearch && matchesLevel && matchesFile;
  }).sort((a, b) => b.timestamp - a.timestamp);
}

function updateFileFilter() {
  const select = $("fileFilter");
  if (!select) return;

  const previous = select.value;
  const files = [...new Set(state.logs.map((log) => log.file))];

  select.innerHTML = `
    <option value="ALL">All files</option>
    ${files.map((file) => `
      <option value="${escapeHTML(file)}">${escapeHTML(file)}</option>
    `).join("")}
  `;

  if (files.includes(previous)) {
    select.value = previous;
  }
}

function renderExplorer() {
  const table = $("logTable");
  if (!table) return;

  const logs = getFilteredLogs();
  const totalPages = Math.max(1, Math.ceil(logs.length / state.pageSize));

  state.currentPage = Math.min(state.currentPage, totalPages);

  const start = (state.currentPage - 1) * state.pageSize;
  const visible = logs.slice(start, start + state.pageSize);

  if ($("resultCount")) {
    $("resultCount").textContent = `${formatNumber(logs.length)} results`;
  }

  if ($("pageInfo")) {
    $("pageInfo").textContent = `Page ${state.currentPage} of ${totalPages}`;
  }

  if ($("prevPage")) {
    $("prevPage").disabled = state.currentPage <= 1;
  }

  if ($("nextPage")) {
    $("nextPage").disabled = state.currentPage >= totalPages;
  }

  if (!visible.length) {
    table.innerHTML = `
      <tr>
        <td colspan="5" class="empty-state">No matching logs found.</td>
      </tr>
    `;
    return;
  }

  table.innerHTML = visible.map((log) => `
    <tr>
      <td>${escapeHTML(formatTime(log.timestamp))}</td>
      <td>
        <span class="severity-badge ${log.level.toLowerCase()}">
          ${log.level}
        </span>
      </td>
      <td>${escapeHTML(log.service)}</td>
      <td class="log-message-cell">${escapeHTML(getDisplayedMessage(log.message))}</td>
      <td>${escapeHTML(log.file)}</td>
    </tr>
  `).join("");
}

/* =========================================
   INCIDENT DETECTION
========================================= */

function normalizeMessage(message) {
  return String(message)
    .toLowerCase()
    .replace(/\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z)?\b/g, "[time]")
    .replace(/\b\d+\b/g, "[number]")
    .replace(/\b[0-9a-f]{8,}\b/g, "[id]")
    .replace(/\s+/g, " ")
    .trim();
}

function getPatterns() {
  const groups = new Map();

  state.logs
    .filter((log) => ["CRITICAL", "ERROR"].includes(log.level))
    .forEach((log) => {
      const key = normalizeMessage(log.message);

      if (!groups.has(key)) {
        groups.set(key, {
          message: log.message,
          count: 0,
          level: log.level,
          service: log.service,
          latest: log.timestamp
        });
      }

      const group = groups.get(key);
      group.count++;

      if (severityOrder[log.level] < severityOrder[group.level]) {
        group.level = log.level;
      }

      if (log.timestamp > group.latest) {
        group.latest = log.timestamp;
      }
    });

  return [...groups.values()].sort((a, b) => b.count - a.count);
}

function renderIncidents() {
  const critical = state.logs.filter((log) => log.level === "CRITICAL");
  const errors = state.logs.filter((log) => log.level === "ERROR");
  const patterns = getPatterns();

  const services = new Set(
    state.logs
      .filter((log) => ["CRITICAL", "ERROR"].includes(log.level))
      .map((log) => log.service)
  );

  if ($("incidentCount")) {
    $("incidentCount").textContent = formatNumber(critical.length + errors.length);
  }

  if ($("patternCount")) {
    $("patternCount").textContent = formatNumber(patterns.length);
  }

  if ($("serviceCount")) {
    $("serviceCount").textContent = formatNumber(services.size);
  }

  const timeline = $("timelineList");

  if (timeline) {
    const incidents = [...critical, ...errors]
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 20);

    timeline.innerHTML = incidents.length
      ? incidents.map((log) => `
        <div class="timeline-item">
          <span class="severity-dot ${log.level.toLowerCase()}"></span>
          <div>
            <strong>${log.level} · ${escapeHTML(log.service)}</strong>
            <p>${escapeHTML(getDisplayedMessage(log.message))}</p>
            <small>${escapeHTML(formatTime(log.timestamp))}</small>
          </div>
        </div>
      `).join("")
      : `<div class="empty-state">No incidents detected in this session.</div>`;
  }

  const patternList = $("patternsList");

  if (patternList) {
    patternList.innerHTML = patterns.length
      ? patterns.slice(0, 10).map((pattern) => `
        <div class="pattern-item">
          <div>
            <strong>${escapeHTML(pattern.service)}</strong>
            <p>${escapeHTML(getDisplayedMessage(pattern.message))}</p>
            <small>Latest: ${escapeHTML(formatTime(pattern.latest))}</small>
          </div>
          <span class="pattern-count">${pattern.count}×</span>
        </div>
      `).join("")
      : `<div class="empty-state">Repeated error patterns will appear here.</div>`;
  }
}

/* =========================================
   ROOT CAUSE INVESTIGATOR
========================================= */

function getFindings() {
  const findings = [];
  const stats = getStats();
  const patterns = getPatterns();

  patterns
    .filter((pattern) => pattern.count >= 2)
    .slice(0, 4)
    .forEach((pattern) => {
      findings.push({
        title: "Repeated error pattern",
        description:
          `${pattern.service} contains a recurring error pattern detected ${pattern.count} times.`,
        level: pattern.level,
        evidence: pattern.message
      });
    });

  const timeoutLogs = state.logs.filter((log) =>
    /\b(timeout|timed out|connection refused|connection reset)\b/i.test(log.message)
  );

  if (timeoutLogs.length) {
    findings.push({
      title: "Possible connectivity or latency issue",
      description:
        `${timeoutLogs.length} log entries mention timeouts or connection failures. Check service availability, network latency, and dependency health.`,
      level: "WARNING",
      evidence: timeoutLogs[0].message
    });
  }

  const memoryLogs = state.logs.filter((log) =>
    /\b(out of memory|heap|memory limit|memory exhausted)\b/i.test(log.message)
  );

  if (memoryLogs.length) {
    findings.push({
      title: "Possible memory pressure",
      description:
        `${memoryLogs.length} entries suggest memory-related problems. Review memory usage, heap limits, and recent workload changes.`,
      level: "CRITICAL",
      evidence: memoryLogs[0].message
    });
  }

  const authLogs = state.logs.filter((log) =>
    /\b(unauthorized|authentication failed|invalid credentials|forbidden|access denied)\b/i.test(log.message)
  );

  if (authLogs.length) {
    findings.push({
      title: "Authentication or permission failures",
      description:
        `${authLogs.length} entries indicate authentication or authorization problems. Review credentials, permissions, and token expiry.`,
      level: "WARNING",
      evidence: authLogs[0].message
    });
  }

  if (stats.CRITICAL > 0) {
    findings.push({
      title: "Critical events detected",
      description:
        `${stats.CRITICAL} critical entries were found. Prioritize these events and inspect surrounding log activity.`,
      level: "CRITICAL",
      evidence: state.logs.find((log) => log.level === "CRITICAL")?.message || ""
    });
  }

  return findings;
}

function renderFindings() {
  const container = $("findingsList");
  if (!container) return;

  const findings = getFindings();

  if ($("findingCount")) {
    $("findingCount").textContent = formatNumber(findings.length);
  }

  container.innerHTML = findings.length
    ? findings.map((finding) => `
      <div class="finding-card">
        <div class="finding-heading">
          <strong>${escapeHTML(finding.title)}</strong>
          <span class="severity-badge ${finding.level.toLowerCase()}">
            ${finding.level}
          </span>
        </div>
        <p>${escapeHTML(finding.description)}</p>
        <div class="finding-evidence">
          <small>Supporting log evidence</small>
          <code>${escapeHTML(getDisplayedMessage(finding.evidence))}</code>
        </div>
      </div>
    `).join("")
    : `
      <div class="empty-state">
        <strong>No investigation findings yet.</strong>
        <p>Upload logs to generate rule-based investigation suggestions.</p>
      </div>
    `;
}

/* =========================================
   REPORTS
========================================= */

function renderReport() {
  const stats = getStats();

  if ($("reportMeta")) {
    $("reportMeta").textContent =
      `${formatNumber(stats.total)} log entries · Generated ${new Date().toLocaleString()}`;
  }

  if ($("reportStats")) {
    $("reportStats").innerHTML = `
      <div class="report-stat"><span>Total logs</span><strong>${formatNumber(stats.total)}</strong></div>
      <div class="report-stat"><span>Critical</span><strong>${formatNumber(stats.CRITICAL)}</strong></div>
      <div class="report-stat"><span>Errors</span><strong>${formatNumber(stats.ERROR)}</strong></div>
      <div class="report-stat"><span>Warnings</span><strong>${formatNumber(stats.WARNING)}</strong></div>
      <div class="report-stat"><span>Health score</span><strong>${getHealth(stats)}%</strong></div>
      <div class="report-stat"><span>Error patterns</span><strong>${formatNumber(getPatterns().length)}</strong></div>
    `;
  }
}

function createReportText() {
  const stats = getStats();
  const findings = getFindings();
  const patterns = getPatterns();

  const lines = [
    "LOGLENS — LOG ANALYSIS REPORT",
    "====================================",
    `Generated: ${new Date().toLocaleString()}`,
    "",
    "SUMMARY",
    `Total logs: ${stats.total}`,
    `Critical: ${stats.CRITICAL}`,
    `Errors: ${stats.ERROR}`,
    `Warnings: ${stats.WARNING}`,
    `Info: ${stats.INFO}`,
    `Health score: ${getHealth(stats)}%`,
    "",
    "REPEATED ERROR PATTERNS",
    "===================================="
  ];

  if (!patterns.length) {
    lines.push("No error patterns detected.");
  } else {
    patterns.slice(0, 20).forEach((pattern, index) => {
      lines.push(
        `${index + 1}. [${pattern.level}] ${pattern.service} — ${maskSensitiveData(pattern.message)} (${pattern.count} occurrences)`
      );
    });
  }

  lines.push("", "INVESTIGATION FINDINGS", "====================================");

  if (!findings.length) {
    lines.push("No findings generated.");
  } else {
    findings.forEach((finding, index) => {
      lines.push(
        `${index + 1}. ${finding.title} [${finding.level}]`,
        finding.description,
        `Evidence: ${maskSensitiveData(finding.evidence)}`,
        ""
      );
    });
  }

  lines.push("", "LOG ENTRIES", "====================================");

  state.logs.forEach((log) => {
    lines.push(
      `[${formatTime(log.timestamp)}] [${log.level}] [${log.service}] ${maskSensitiveData(log.message)}`
    );
  });

  lines.push(
    "",
    "Note: Investigation findings are rule-based suggestions, not confirmed root causes."
  );

  return lines.join("\n");
}

function downloadText(content, fileName) {
  const blob = new Blob([content], {
    type: "text/plain;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* =========================================
   LOG COMPARISON
========================================= */

// Show a clean state whenever the selected files change.
function resetCompareResults(message = "Select two log files and run a comparison to see the results.") {
  state.compareA = [];
  state.compareB = [];

  const container = $("compareResults");

  if (container) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>No comparison results yet.</strong>
        <p>${escapeHTML(message)}</p>
      </div>
    `;
  }
}

// This function receives only the two selected files' parsed logs.
// It never reads state.logs.
function compareFiles(logsA, logsB, nameA, nameB) {
  const statsA = getStats(logsA);
  const statsB = getStats(logsB);

  const difference = (a, b) => {
    if (a === b) return "No change";

    return b > a
      ? `Increased by ${formatNumber(b - a)}`
      : `Decreased by ${formatNumber(a - b)}`;
  };

  const patternsA = new Set(
    logsA
      .filter((log) => ["CRITICAL", "ERROR"].includes(log.level))
      .map((log) => normalizeMessage(log.message))
  );

  const patternsB = new Set(
    logsB
      .filter((log) => ["CRITICAL", "ERROR"].includes(log.level))
      .map((log) => normalizeMessage(log.message))
  );

  const newPatterns = [...patternsB].filter((item) => !patternsA.has(item));
  const resolvedPatterns = [...patternsA].filter((item) => !patternsB.has(item));

  const container = $("compareResults");
  if (!container) return;

  container.innerHTML = `
    <div class="compare-summary">
      <div class="compare-file">
        <small>Baseline</small>
        <strong>${escapeHTML(nameA)}</strong>
        <span>${formatNumber(statsA.total)} log entries</span>
      </div>
      <div class="compare-file">
        <small>Comparison</small>
        <strong>${escapeHTML(nameB)}</strong>
        <span>${formatNumber(statsB.total)} log entries</span>
      </div>
    </div>

    <div class="compare-grid">
      ${["CRITICAL", "ERROR", "WARNING", "INFO"].map((level) => `
        <div class="compare-metric">
          <span>${level}</span>
          <strong>${formatNumber(statsA[level])} → ${formatNumber(statsB[level])}</strong>
          <small>${difference(statsA[level], statsB[level])}</small>
        </div>
      `).join("")}
    </div>

    <div class="compare-insights">
      <div>
        <strong>New error patterns</strong>
        <span>${formatNumber(newPatterns.length)}</span>
      </div>
      <div>
        <strong>Patterns no longer present</strong>
        <span>${formatNumber(resolvedPatterns.length)}</span>
      </div>
    </div>

    <p class="compare-note">
      Pattern comparison uses normalized error messages. A pattern disappearing
      from the second file does not by itself confirm that an incident is resolved.
    </p>
  `;
}

async function readCompareFile(file) {
  if (!file) {
    throw new Error("Please select a file.");
  }

  if (!/\.(log|txt)$/i.test(file.name)) {
    throw new Error("Please choose a .log or .txt file.");
  }

  const text = await file.text();
  return parseLogs(text, file.name);
}

/* =========================================
   NAVIGATION
========================================= */

function switchSection(section) {
  if (!sectionTitles[section]) return;

  document.querySelectorAll(".app-section").forEach((element) => {
    element.classList.toggle("active", element.id === section);
  });

  document.querySelectorAll("[data-section]").forEach((button) => {
    button.classList.toggle(
      "active",
      button.dataset.section === section
    );
  });

  if ($("breadcrumbTitle")) {
    $("breadcrumbTitle").textContent = sectionTitles[section];
  }

  $("sidebar")?.classList.remove("open");

  if (section === "explorer") renderExplorer();
  if (section === "incidents") renderIncidents();
  if (section === "investigator") renderFindings();
  if (section === "reports") renderReport();
}

/* =========================================
   REFRESH ALL VIEWS
========================================= */

function refreshDashboard() {
  updateStats();
  renderRecent();
}

function refreshAll() {
  updateFileFilter();
  refreshDashboard();
  renderExplorer();
  renderIncidents();
  renderFindings();
  renderReport();
  updateSessionLabel();
}

function updateSessionLabel() {
  const label = $("sessionLabel");
  if (!label) return;

  const files = [...new Set(state.logs.map((log) => log.file))];

  label.textContent = state.logs.length
    ? `${files.length} file${files.length === 1 ? "" : "s"} analyzed`
    : "No files analyzed yet";
}

/* =========================================
   FILE UPLOAD EVENTS
========================================= */

$("chooseFiles")?.addEventListener("click", () => {
  $("logFiles")?.click();
});

$("uploadTopButton")?.addEventListener("click", () => {
  $("logFiles")?.click();
});

$("bannerUpload")?.addEventListener("click", () => {
  $("logFiles")?.click();
});

$("explorerUpload")?.addEventListener("click", () => {
  $("logFiles")?.click();
});

$("logFiles")?.addEventListener("change", async (event) => {
  await handleFiles(event.target.files);
  event.target.value = "";
});

/* =========================================
   DRAG AND DROP
========================================= */

const dropZone = $("dropZone");

if (dropZone) {
  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("drag-over");
    });
  });

  dropZone.addEventListener("drop", async (event) => {
    await handleFiles(event.dataTransfer?.files);
  });
}

/* =========================================
   SEARCH AND FILTER EVENTS
========================================= */

$("searchInput")?.addEventListener("input", () => {
  state.currentPage = 1;
  renderExplorer();
});

$("levelFilter")?.addEventListener("change", () => {
  state.currentPage = 1;
  renderExplorer();
});

$("fileFilter")?.addEventListener("change", () => {
  state.currentPage = 1;
  renderExplorer();
});

$("maskToggle")?.addEventListener("change", () => {
  renderExplorer();
  renderRecent();
  renderIncidents();
  renderFindings();
});

/* =========================================
   PAGINATION
========================================= */

$("prevPage")?.addEventListener("click", () => {
  if (state.currentPage > 1) {
    state.currentPage--;
    renderExplorer();
  }
});

$("nextPage")?.addEventListener("click", () => {
  const totalPages = Math.max(
    1,
    Math.ceil(getFilteredLogs().length / state.pageSize)
  );

  if (state.currentPage < totalPages) {
    state.currentPage++;
    renderExplorer();
  }
});

/* =========================================
   CLEAR SESSION — RESET ALL DATA
========================================= */

$("clearSession")?.addEventListener("click", () => {
  const hasMainLogs = state.logs.length > 0;

  const hasComparisonData =
    state.compareA.length > 0 ||
    state.compareB.length > 0 ||
    $("compareFileA")?.files?.length > 0 ||
    $("compareFileB")?.files?.length > 0;

  if (!hasMainLogs && !hasComparisonData) {
    notify("There is no session data to clear.", "error");
    return;
  }

  const confirmed = window.confirm(
    "Clear all imported logs, comparison files, and results from this session?"
  );

  if (!confirmed) return;

  state.logs = [];
  state.currentPage = 1;
  state.compareRequest++;

  state.compareA = [];
  state.compareB = [];

  if ($("logFiles")) $("logFiles").value = "";
  if ($("compareFileA")) $("compareFileA").value = "";
  if ($("compareFileB")) $("compareFileB").value = "";

  if ($("compareNameA")) {
    $("compareNameA").textContent = "No file selected";
  }

  if ($("compareNameB")) {
    $("compareNameB").textContent = "No file selected";
  }

  resetCompareResults();

  if ($("searchInput")) $("searchInput").value = "";
  if ($("levelFilter")) $("levelFilter").value = "ALL";
  if ($("fileFilter")) $("fileFilter").value = "ALL";
  if ($("maskToggle")) $("maskToggle").checked = false;

  refreshAll();

  notify("All session data and comparison results cleared.");
});

/* =========================================
   NAVIGATION BUTTONS
========================================= */

document.querySelectorAll("[data-section]").forEach((button) => {
  button.addEventListener("click", () => {
    switchSection(button.dataset.section);
  });
});

document.querySelectorAll("[data-go]").forEach((button) => {
  button.addEventListener("click", () => {
    switchSection(button.dataset.go);
  });
});

/* =========================================
   LOG COMPARISON EVENTS
========================================= */

// Invalidate previous comparison whenever File A changes.
$("compareFileA")?.addEventListener("change", (event) => {
  const file = event.target.files?.[0];

  state.compareRequest++;
  resetCompareResults("File selection changed. Run a new comparison to view updated results.");

  if ($("compareNameA")) {
    $("compareNameA").textContent = file?.name || "No file selected";
  }
});

// Invalidate previous comparison whenever File B changes.
$("compareFileB")?.addEventListener("change", (event) => {
  const file = event.target.files?.[0];

  state.compareRequest++;
  resetCompareResults("File selection changed. Run a new comparison to view updated results.");

  if ($("compareNameB")) {
    $("compareNameB").textContent = file?.name || "No file selected";
  }
});

$("runCompare")?.addEventListener("click", async () => {
  const fileA = $("compareFileA")?.files?.[0];
  const fileB = $("compareFileB")?.files?.[0];

  if (!fileA || !fileB) {
    resetCompareResults("Please select both files before comparing.");
    notify("Choose both files before comparing.", "error");
    return;
  }

  if (fileA === fileB) {
    resetCompareResults("Please select two different files.");
    notify("Choose two different files to compare.", "error");
    return;
  }

  // Each comparison receives a unique request number.
  // This prevents an older asynchronous comparison from overwriting newer results.
  const requestId = ++state.compareRequest;

  resetCompareResults("Reading the two selected files...");

  try {
    // Read only the two files selected in the comparison inputs.
    const [logsA, logsB] = await Promise.all([
      readCompareFile(fileA),
      readCompareFile(fileB)
    ]);

    // Ignore outdated comparison requests.
    if (requestId !== state.compareRequest) return;

    state.compareA = logsA;
    state.compareB = logsB;

    compareFiles(
      logsA,
      logsB,
      fileA.name,
      fileB.name
    );

    notify("Comparison completed using the two selected files.");
  } catch (error) {
    if (requestId !== state.compareRequest) return;

    resetCompareResults("The selected files could not be compared. Please try again.");
    notify(error.message || "Could not compare these files.", "error");
  }
});

/* =========================================
   REPORT DOWNLOAD
========================================= */

$("downloadReport")?.addEventListener("click", () => {
  if (!state.logs.length) {
    notify("Upload logs before generating a report.", "error");
    return;
  }

  downloadText(
    createReportText(),
    `LogLens-Report-${new Date().toISOString().slice(0, 10)}.txt`
  );

  notify("Your report has been downloaded.");
});

/* =========================================
   THEME TOGGLE
========================================= */

function applyTheme(theme) {
  document.body.classList.toggle("light-theme", theme === "light");

  const button = $("themeToggle");

  if (button) {
    button.textContent = theme === "light" ? "☾" : "☀";
    button.setAttribute(
      "aria-label",
      theme === "light" ? "Switch to dark theme" : "Switch to light theme"
    );
  }
}

let savedTheme = "dark";

try {
  savedTheme = localStorage.getItem("loglens-theme") || "dark";
} catch (error) {
  console.warn("Theme preference could not be loaded.");
}

applyTheme(savedTheme);

$("themeToggle")?.addEventListener("click", () => {
  const nextTheme = document.body.classList.contains("light-theme")
    ? "dark"
    : "light";

  applyTheme(nextTheme);

  try {
    localStorage.setItem("loglens-theme", nextTheme);
  } catch (error) {
    console.warn("Theme preference could not be saved.");
  }
});

/* =========================================
   MOBILE SIDEBAR
========================================= */

$("menuToggle")?.addEventListener("click", () => {
  $("sidebar")?.classList.toggle("open");
});

/* =========================================
   INITIALIZATION
========================================= */

function initializeLogLens() {
  refreshAll();
  resetCompareResults();

  window.addEventListener("resize", () => {
    updateStats();
  });

  console.log("LogLens initialized successfully.");
}

initializeLogLens();