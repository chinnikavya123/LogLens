
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
  compareRequest: 0,
  anomalies: [],
  anomalyAnalyzed: false
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
  anomalies: "Anomaly Detection",
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

function isValidDate(date) {
  return date instanceof Date && !Number.isNaN(date.getTime());
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

    if (["CRITICAL", "FATAL", "SEVERE"].includes(level)) return "CRITICAL";
    if (["ERROR", "ERR"].includes(level)) return "ERROR";
    if (["WARNING", "WARN"].includes(level)) return "WARNING";

    return "INFO";
  }

  if (/\b(out of memory|outofmemory|fatal|panic|unrecoverable|segmentation fault)\b/i.test(text)) {
    return "CRITICAL";
  }

  if (/\b(exception|failed|failure|error|timeout|timed out|refused|denied)\b/i.test(text)) {
    return "ERROR";
  }

  if (/\b(retry|slow|deprecated|warning|threshold exceeded|high latency)\b/i.test(text)) {
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

      if (isValidDate(parsed)) {
        return parsed;
      }
    }
  }

  return null;
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

    if (match) return match[1];
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
      const timestamp = extractTimestamp(line);

      return {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}-${index}`,
        timestamp,
        hasTimestamp: isValidDate(timestamp),
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

  const supported = files.filter((file) => /\.(log|txt)$/i.test(file.name));

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

  return Math.max(
    0,
    Math.round(100 - (weightedIssues / maximumWeight) * 100)
  );
}

function updateStats() {
  const stats = getStats();

  if ($("totalLogs")) $("totalLogs").textContent = formatNumber(stats.total);
  if ($("criticalLogs")) $("criticalLogs").textContent = formatNumber(stats.CRITICAL);
  if ($("errorLogs")) $("errorLogs").textContent = formatNumber(stats.ERROR);
  if ($("warningLogs")) $("warningLogs").textContent = formatNumber(stats.WARNING);

  const score = getHealth(stats);

  if ($("healthScore")) $("healthScore").textContent = `${score}%`;
  if ($("healthBar")) $("healthBar").style.width = `${score}%`;

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
    $("failureCount").textContent = formatNumber(stats.CRITICAL + stats.ERROR);
  }

  if ($("healthWarnings")) {
    $("healthWarnings").textContent = formatNumber(stats.WARNING);
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

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
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
    .sort((a, b) => {
      if (!a.hasTimestamp) return 1;
      if (!b.hasTimestamp) return -1;
      return b.timestamp - a.timestamp;
    })
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
  }).sort((a, b) => {
    if (!a.hasTimestamp) return 1;
    if (!b.hasTimestamp) return -1;
    return b.timestamp - a.timestamp;
  });
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

  if (files.includes(previous)) select.value = previous;
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

  if ($("prevPage")) $("prevPage").disabled = state.currentPage <= 1;
  if ($("nextPage")) $("nextPage").disabled = state.currentPage >= totalPages;

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
        <span class="severity-badge ${log.level.toLowerCase()}">${log.level}</span>
      </td>
      <td>${escapeHTML(log.service)}</td>
      <td class="log-message-cell">${escapeHTML(getDisplayedMessage(log.message))}</td>
      <td>${escapeHTML(log.file)}</td>
    </tr>
  `).join("");
}

/* =========================================
   INCIDENT PATTERN NORMALIZATION
========================================= */

function normalizeMessage(message) {
  return String(message)
    .toLowerCase()
    .replace(/\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z)?\b/g, "[time]")
    .replace(/\b\d+\b/g, "[number]")
    .replace(/\b[0-9a-f]{8,}\b/gi, "[id]")
    .replace(/\s+/g, " ")
    .trim();
}

/* =========================================
   INCIDENT PATTERN GROUPING
========================================= */

function getPatterns() {
  const groups = new Map();

  state.logs
    .filter((log) => ["CRITICAL", "ERROR"].includes(log.level))
    .forEach((log) => {
      const key = `${log.service}::${normalizeMessage(log.message)}`;

      if (!groups.has(key)) {
        groups.set(key, {
          key,
          message: log.message,
          normalizedMessage: normalizeMessage(log.message),
          count: 0,
          level: log.level,
          service: log.service,
          logs: [],
          first: log,
          latest: log
        });
      }

      const group = groups.get(key);

      group.count++;
      group.logs.push(log);

      if (severityOrder[log.level] < severityOrder[group.level]) {
        group.level = log.level;
      }

      if (
        log.hasTimestamp &&
        (!group.first.hasTimestamp || log.timestamp < group.first.timestamp)
      ) {
        group.first = log;
      }

      if (
        log.hasTimestamp &&
        (!group.latest.hasTimestamp || log.timestamp > group.latest.timestamp)
      ) {
        group.latest = log;
      }
    });

  return [...groups.values()].sort((a, b) => b.count - a.count);
}

/* =========================================
   INCIDENT CORRELATION ENGINE
========================================= */

function getIncidentEvents() {
  return state.logs.filter((log) =>
    ["CRITICAL", "ERROR"].includes(log.level)
  );
}

function getCorrelatedIncidents() {
  const patterns = getPatterns();

  return patterns.map((pattern) => {
    const sortedLogs = [...pattern.logs].sort((a, b) => {
      if (!a.hasTimestamp) return 1;
      if (!b.hasTimestamp) return -1;
      return a.timestamp - b.timestamp;
    });

    const datedLogs = sortedLogs.filter((log) => log.hasTimestamp);

    const firstOccurrence = datedLogs[0] || sortedLogs[0];
    const latestOccurrence = datedLogs[datedLogs.length - 1] || sortedLogs[sortedLogs.length - 1];

    const durationMinutes =
      datedLogs.length > 1
        ? Math.max(
            0,
            Math.round(
              (latestOccurrence.timestamp - firstOccurrence.timestamp) / 60000
            )
          )
        : null;

    const files = [...new Set(sortedLogs.map((log) => log.file))];

    return {
      ...pattern,
      logs: sortedLogs,
      firstOccurrence,
      latestOccurrence,
      durationMinutes,
      files,
      repeated: sortedLogs.length > 1
    };
  });
}

/* =========================================
   INCIDENT TIMELINE
========================================= */

function renderIncidentTimeline() {
  const container = $("timelineList");
  if (!container) return;

  const search = ($("incidentSearch")?.value || "").toLowerCase().trim();
  const severity = $("incidentSeverityFilter")?.value || "ALL";
  const sort = $("incidentSort")?.value || "newest";

  let incidents = getIncidentEvents().filter((log) => {
    const matchesSeverity = severity === "ALL" || log.level === severity;

    const matchesSearch =
      !search ||
      log.message.toLowerCase().includes(search) ||
      log.service.toLowerCase().includes(search) ||
      log.file.toLowerCase().includes(search);

    return matchesSeverity && matchesSearch;
  });

  incidents.sort((a, b) => {
    if (!a.hasTimestamp) return 1;
    if (!b.hasTimestamp) return -1;

    return sort === "oldest"
      ? a.timestamp - b.timestamp
      : b.timestamp - a.timestamp;
  });

  const allGroups = getCorrelatedIncidents();

  const firstIds = new Set(
    allGroups.map((group) => group.firstOccurrence.id)
  );

  if (!incidents.length) {
    container.innerHTML = `
      <div class="empty-state">
        ${state.logs.length
          ? "No incidents match your selected filters."
          : "Upload logs to build your incident timeline."}
      </div>
    `;
    return;
  }

  container.innerHTML = incidents.slice(0, 100).map((log) => {
    const group = allGroups.find((item) =>
      item.logs.some((entry) => entry.id === log.id)
    );

    const isFirst = firstIds.has(log.id);

    const occurrenceLabel = group
      ? `${group.count} matching event${group.count === 1 ? "" : "s"}`
      : "Single event";

    return `
      <div class="timeline-item">
        <span class="severity-dot ${log.level.toLowerCase()}"></span>

        <div>
          <strong>
            ${escapeHTML(log.level)} · ${escapeHTML(log.service)}
          </strong>

          <p>${escapeHTML(getDisplayedMessage(log.message))}</p>

          <small>${escapeHTML(formatTime(log.timestamp))}</small>

          <div class="timeline-event-details">
            <span>${escapeHTML(log.file)}</span>
            <span>Line ${log.lineNumber}</span>
            <span>${escapeHTML(occurrenceLabel)}</span>
            ${isFirst ? `<span class="timeline-first-label">FIRST OCCURRENCE</span>` : ""}
          </div>
        </div>
      </div>
    `;
  }).join("") + (
    incidents.length > 100
      ? `<div class="empty-state compact">Showing the first 100 matching events.</div>`
      : ""
  );
}

/* =========================================
   CORRELATED INCIDENT GROUPS
========================================= */

function renderCorrelatedGroups() {
  const container = $("correlatedGroupsList");
  if (!container) return;

  const groups = getCorrelatedIncidents();

  if ($("correlationResultCount")) {
    $("correlationResultCount").textContent = `${groups.length} groups`;
  }

  if ($("correlatedGroupCount")) {
    $("correlatedGroupCount").textContent = formatNumber(groups.length);
  }

  const repeatedEvents = groups.reduce(
    (total, group) => total + Math.max(0, group.count - 1),
    0
  );

  if ($("repeatedEventCount")) {
    $("repeatedEventCount").textContent = formatNumber(repeatedEvents);
  }

  if ($("firstOccurrenceCount")) {
    $("firstOccurrenceCount").textContent = formatNumber(groups.length);
  }

  if (!groups.length) {
    container.innerHTML = `
      <div class="empty-state compact">
        No critical or error patterns are available for correlation.
      </div>
    `;
    return;
  }

  container.innerHTML = groups.slice(0, 20).map((group, index) => {
    const duration = group.durationMinutes === null
      ? "Time range unavailable"
      : group.durationMinutes === 0
        ? "Occurred within the same minute"
        : `Spanned ${group.durationMinutes} minute${group.durationMinutes === 1 ? "" : "s"}`;

    return `
      <article class="correlated-incident-card">
        <div class="correlated-incident-header">
          <div>
            <span class="correlation-id">INCIDENT GROUP ${String(index + 1).padStart(2, "0")}</span>
            <h4>${escapeHTML(group.service)}</h4>
          </div>

          <span class="severity-badge ${group.level.toLowerCase()}">
            ${escapeHTML(group.level)}
          </span>
        </div>

        <p class="correlated-incident-message">
          ${escapeHTML(getDisplayedMessage(group.message))}
        </p>

        <div class="correlated-incident-metrics">
          <div>
            <small>Occurrences</small>
            <strong>${formatNumber(group.count)}</strong>
          </div>

          <div>
            <small>First seen</small>
            <strong>${escapeHTML(formatTime(group.firstOccurrence.timestamp))}</strong>
          </div>

          <div>
            <small>Last seen</small>
            <strong>${escapeHTML(formatTime(group.latestOccurrence.timestamp))}</strong>
          </div>
        </div>

        <div class="correlated-incident-footer">
          <span>${escapeHTML(duration)}</span>
          <span>${group.files.length} source file${group.files.length === 1 ? "" : "s"}</span>
          <span>${group.repeated ? "Repeated pattern" : "Single occurrence"}</span>
        </div>
      </article>
    `;
  }).join("");
}

/* =========================================
   INCIDENT CENTER RENDERING
========================================= */

function renderIncidents() {
  const events = getIncidentEvents();
  const patterns = getPatterns();

  const services = new Set(events.map((log) => log.service));

  if ($("incidentCount")) {
    $("incidentCount").textContent = formatNumber(events.length);
  }

  if ($("patternCount")) {
    $("patternCount").textContent = formatNumber(patterns.length);
  }

  if ($("serviceCount")) {
    $("serviceCount").textContent = formatNumber(services.size);
  }

  renderIncidentTimeline();
  renderCorrelatedGroups();
  renderPatternsList();
}

function renderPatternsList() {
  const container = $("patternsList");
  if (!container) return;

  const patterns = getPatterns().filter((pattern) => pattern.count > 1);

  if (!patterns.length) {
    container.innerHTML = `
      <div class="empty-state">
        No repeated error patterns detected yet.
      </div>
    `;
    return;
  }

  container.innerHTML = patterns.slice(0, 10).map((pattern) => `
    <div class="pattern-item">
      <div>
        <strong>${escapeHTML(pattern.service)}</strong>
        <p>${escapeHTML(getDisplayedMessage(pattern.message))}</p>
        <small>Latest: ${escapeHTML(formatTime(pattern.latest.timestamp))}</small>
      </div>
      <span class="pattern-count">${formatNumber(pattern.count)}×</span>
    </div>
  `).join("");
}

/* =========================================
   ANOMALY DETECTION
========================================= */

function detectAnomalies() {
  const anomalies = [];
  const logs = state.logs;

  if (!logs.length) return anomalies;

  const errorLogs = logs.filter((log) =>
    ["CRITICAL", "ERROR"].includes(log.level)
  );

  const stats = getStats();

  /* Repeated failure patterns */
  const patterns = getPatterns();

  patterns
    .filter((pattern) => pattern.count >= 3)
    .forEach((pattern) => {
      anomalies.push({
        type: "Repeated failure pattern",
        severity: pattern.level === "CRITICAL" ? "HIGH" : "MEDIUM",
        service: pattern.service,
        description: `The same normalized error pattern occurred ${pattern.count} times.`,
        evidence: pattern.message,
        recommendation: "Inspect the recurring error and check whether a common dependency or operation is failing."
      });
    });

  /* Unusual error concentration */
  const errorRatio = errorLogs.length / logs.length;

  if (logs.length >= 10 && errorRatio >= 0.4) {
    anomalies.push({
      type: "High error concentration",
      severity: errorRatio >= 0.7 ? "HIGH" : "MEDIUM",
      service: "Multiple services",
      description: `${Math.round(errorRatio * 100)}% of all log entries are critical or error events.`,
      evidence: `${errorLogs.length} error-level entries out of ${logs.length} total entries.`,
      recommendation: "Review the affected operations and investigate whether a recent change caused the increase."
    });
  }

  /* Service-specific concentration */
  const serviceGroups = new Map();

  logs.forEach((log) => {
    if (!serviceGroups.has(log.service)) {
      serviceGroups.set(log.service, {
        total: 0,
        errors: 0
      });
    }

    const group = serviceGroups.get(log.service);
    group.total++;

    if (["CRITICAL", "ERROR"].includes(log.level)) {
      group.errors++;
    }
  });

  serviceGroups.forEach((group, service) => {
    if (group.total < 5) return;

    const ratio = group.errors / group.total;

    if (ratio >= 0.5 && group.errors >= 3) {
      anomalies.push({
        type: "Service-specific error concentration",
        severity: ratio >= 0.75 ? "HIGH" : "MEDIUM",
        service,
        description: `${service} has ${group.errors} error-level entries out of ${group.total} logs.`,
        evidence: `${Math.round(ratio * 100)}% of this service's log entries are critical or errors.`,
        recommendation: `Investigate ${service} independently and inspect its dependencies, recent deployments and resource usage.`
      });
    }
  });

  /* Error spikes in timestamped five-minute windows */
  const datedErrors = errorLogs.filter((log) => log.hasTimestamp);

  if (datedErrors.length >= 5) {
    const buckets = new Map();

    datedErrors.forEach((log) => {
      const bucket = Math.floor(log.timestamp.getTime() / 300000);

      if (!buckets.has(bucket)) buckets.set(bucket, []);
      buckets.get(bucket).push(log);
    });

    const counts = [...buckets.values()].map((group) => group.length);
    const average = counts.reduce((sum, value) => sum + value, 0) / counts.length;

    const spike = [...buckets.entries()]
      .sort((a, b) => b[1].length - a[1].length)[0];

    if (spike && spike[1].length >= Math.max(5, average * 2)) {
      anomalies.push({
        type: "Sudden error spike",
        severity: "HIGH",
        service: "Multiple services",
        description: `${spike[1].length} critical or error entries occurred within one five-minute window.`,
        evidence: `Average errors per occupied five-minute window: ${average.toFixed(1)}.`,
        recommendation: "Inspect the events in this time window and check for deployment changes, traffic increases or dependency failures."
      });
    }
  }

  return anomalies;
}

function renderAnomalies() {
  const container = $("anomalyList");
  if (!container) return;

  if (!state.logs.length) {
    if ($("anomalyStatus")) $("anomalyStatus").textContent = "Waiting for logs";

    container.innerHTML = `
      <div class="empty-state">
        Upload log files before running anomaly detection.
      </div>
    `;

    return;
  }

  if (!state.anomalyAnalyzed) {
    if ($("anomalyStatus")) $("anomalyStatus").textContent = "Analysis not run";

    container.innerHTML = `
      <div class="empty-state">
        <strong>Ready to analyze your logs.</strong>
        <p>Select Analyze logs to identify unusual activity.</p>
      </div>
    `;

    return;
  }

  const anomalies = state.anomalies;

  const highCount = anomalies.filter((item) => item.severity === "HIGH").length;
  const affected = new Set(anomalies.map((item) => item.service));

  if ($("anomalyCount")) $("anomalyCount").textContent = formatNumber(anomalies.length);
  if ($("highAnomalyCount")) $("highAnomalyCount").textContent = formatNumber(highCount);
  if ($("affectedServiceCount")) $("affectedServiceCount").textContent = formatNumber(affected.size);
  if ($("analyzedEntryCount")) $("analyzedEntryCount").textContent = formatNumber(state.logs.length);

  if ($("anomalyStatus")) {
    $("anomalyStatus").textContent = anomalies.length
      ? "Analysis completed"
      : "No unusual patterns found";
  }

  if ($("anomalyResultCount")) {
    $("anomalyResultCount").textContent = `${anomalies.length} findings`;
  }

  if (!anomalies.length) {
    container.innerHTML = `
      <div class="empty-state">
        <strong>No unusual patterns detected.</strong>
        <p>The current rule-based checks did not identify any anomalies.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = anomalies.map((item) => `
    <article class="anomaly-card">
      <div class="finding-heading">
        <strong>${escapeHTML(item.type)}</strong>
        <span class="severity-badge ${item.severity === "HIGH" ? "critical" : "warning"}">
          ${escapeHTML(item.severity)}
        </span>
      </div>

      <p>${escapeHTML(item.description)}</p>

      <div class="finding-evidence">
        <small>Evidence</small>
        <code>${escapeHTML(getDisplayedMessage(item.evidence))}</code>
      </div>

      <div class="anomaly-recommendation">
        <strong>Recommended action</strong>
        <p>${escapeHTML(item.recommendation)}</p>
      </div>

      <small class="anomaly-service">Service: ${escapeHTML(item.service)}</small>
    </article>
  `).join("");
}

function runAnomalyDetection() {
  if (!state.logs.length) {
    notify("Upload logs before running anomaly detection.", "error");
    return;
  }

  state.anomalies = detectAnomalies();
  state.anomalyAnalyzed = true;

  renderAnomalies();

  notify(
    `${state.anomalies.length} anomaly findings identified.`
  );
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
  const correlated = getCorrelatedIncidents();

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
    "CORRELATED INCIDENT GROUPS",
    "===================================="
  ];

  if (!correlated.length) {
    lines.push("No critical or error groups detected.");
  } else {
    correlated.forEach((group, index) => {
      lines.push(
        `${index + 1}. [${group.level}] ${group.service}`,
        `Occurrences: ${group.count}`,
        `First occurrence: ${formatTime(group.firstOccurrence.timestamp)}`,
        `Latest occurrence: ${formatTime(group.latestOccurrence.timestamp)}`,
        `Message: ${maskSensitiveData(group.message)}`,
        ""
      );
    });
  }

  lines.push("", "REPEATED ERROR PATTERNS", "====================================");

  if (!patterns.length) {
    lines.push("No error patterns detected.");
  } else {
    patterns.slice(0, 20).forEach((pattern, index) => {
      lines.push(
        `${index + 1}. [${pattern.level}] ${pattern.service} — ${maskSensitiveData(pattern.message)} (${pattern.count} occurrences)`
      );
    });
  }

  lines.push("", "ANOMALY DETECTION", "====================================");

  if (!state.anomalyAnalyzed) {
    lines.push("Anomaly detection was not run for this session.");
  } else if (!state.anomalies.length) {
    lines.push("No unusual patterns detected.");
  } else {
    state.anomalies.forEach((anomaly, index) => {
      lines.push(
        `${index + 1}. ${anomaly.type} [${anomaly.severity}]`,
        anomaly.description,
        `Evidence: ${maskSensitiveData(anomaly.evidence)}`,
        `Recommendation: ${anomaly.recommendation}`,
        ""
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
    "Note: Correlation and investigation findings are rule-based suggestions, not confirmed root causes."
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
  if (!file) throw new Error("Please select a file.");

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
    button.classList.toggle("active", button.dataset.section === section);
  });

  if ($("breadcrumbTitle")) {
    $("breadcrumbTitle").textContent = sectionTitles[section];
  }

  $("sidebar")?.classList.remove("open");

  if (section === "explorer") renderExplorer();
  if (section === "incidents") renderIncidents();
  if (section === "anomalies") renderAnomalies();
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
  renderAnomalies();
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

$("chooseFiles")?.addEventListener("click", () => $("logFiles")?.click());
$("uploadTopButton")?.addEventListener("click", () => $("logFiles")?.click());
$("bannerUpload")?.addEventListener("click", () => $("logFiles")?.click());
$("explorerUpload")?.addEventListener("click", () => $("logFiles")?.click());

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
  renderAnomalies();
});

/* =========================================
   INCIDENT FILTER EVENTS
========================================= */

$("incidentSearch")?.addEventListener("input", renderIncidentTimeline);

$("incidentSeverityFilter")?.addEventListener("change", renderIncidentTimeline);

$("incidentSort")?.addEventListener("change", renderIncidentTimeline);

/* =========================================
   ANOMALY EVENTS
========================================= */

$("runAnomalyDetection")?.addEventListener("click", runAnomalyDetection);

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
   CLEAR SESSION
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
  state.anomalies = [];
  state.anomalyAnalyzed = false;

  if ($("logFiles")) $("logFiles").value = "";
  if ($("compareFileA")) $("compareFileA").value = "";
  if ($("compareFileB")) $("compareFileB").value = "";

  if ($("compareNameA")) $("compareNameA").textContent = "No file selected";
  if ($("compareNameB")) $("compareNameB").textContent = "No file selected";

  resetCompareResults();

  if ($("searchInput")) $("searchInput").value = "";
  if ($("levelFilter")) $("levelFilter").value = "ALL";
  if ($("fileFilter")) $("fileFilter").value = "ALL";
  if ($("maskToggle")) $("maskToggle").checked = false;

  if ($("incidentSearch")) $("incidentSearch").value = "";
  if ($("incidentSeverityFilter")) $("incidentSeverityFilter").value = "ALL";
  if ($("incidentSort")) $("incidentSort").value = "newest";

  if ($("anomalyCount")) $("anomalyCount").textContent = "0";
  if ($("highAnomalyCount")) $("highAnomalyCount").textContent = "0";
  if ($("affectedServiceCount")) $("affectedServiceCount").textContent = "0";
  if ($("analyzedEntryCount")) $("analyzedEntryCount").textContent = "0";
  if ($("anomalyResultCount")) $("anomalyResultCount").textContent = "0 findings";
  if ($("anomalyStatus")) $("anomalyStatus").textContent = "Waiting for analysis";

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

$("compareFileA")?.addEventListener("change", (event) => {
  const file = event.target.files?.[0];

  state.compareRequest++;
  resetCompareResults("File selection changed. Run a new comparison to view updated results.");

  if ($("compareNameA")) {
    $("compareNameA").textContent = file?.name || "No file selected";
  }
});

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

  const requestId = ++state.compareRequest;

  resetCompareResults("Reading the two selected files...");

  try {
    const [logsA, logsB] = await Promise.all([
      readCompareFile(fileA),
      readCompareFile(fileB)
    ]);

    if (requestId !== state.compareRequest) return;

    state.compareA = logsA;
    state.compareB = logsB;

    compareFiles(logsA, logsB, fileA.name, fileB.name);

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