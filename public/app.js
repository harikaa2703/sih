(() => {
  "use strict";

  const findings = [
    {
      id: "NCM-MGMT-001", title: "Telnet enabled on management interface", severity: "high",
      device: "core-rtr-01", vendor: "Cisco IOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 SC-8, AC-17 · CIS secure remote-management guidance", line: 18,
      nistControls: [["SC-8", "Transmission Confidentiality and Integrity"], ["AC-17", "Remote Access"]],
      cisGuidance: "Secure remote management; edition-specific control ID not asserted",
      source: "transport input telnet ssh", description: "Telnet sends session credentials and data without encryption. A network observer on the management path could capture administrator access.",
      remediation: "line vty 0 4\n transport input ssh",
      check: (line) => /transport input.*\btelnet\b/i.test(line)
    },
    {
      id: "NCM-SNMP-002", title: "Default SNMP community string detected", severity: "critical",
      device: "edge-fw-02", vendor: "Fortinet FortiOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 CM-6, SC-8 · CIS SNMP hardening guidance", line: 36,
      nistControls: [["CM-6", "Configuration Settings"], ["SC-8", "Transmission Confidentiality and Integrity"]],
      cisGuidance: "SNMP community hardening; edition-specific control ID not asserted",
      source: 'set community "public"', description: "The well-known SNMP community string can permit unauthorized monitoring or configuration access when exposed to a reachable management network.",
      remediation: "config system snmp community\n  edit 1\n    set name <unique-secret>\n    set query-v2c-status disable\n  next\nend",
      check: (line) => /(?:community\s+["']?(?:public|private)\b|set\s+name\s+["']?(?:public|private)\b)/i.test(line)
    },
    {
      id: "NCM-MGMT-003", title: "Unencrypted HTTP management enabled", severity: "high",
      device: "edge-fw-02", vendor: "Fortinet FortiOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 SC-8 · CIS secure management guidance", line: 54,
      nistControls: [["SC-8", "Transmission Confidentiality and Integrity"]],
      cisGuidance: "Secure management access; edition-specific control ID not asserted",
      source: "set admin-http enable", description: "The administrative web interface accepts unencrypted HTTP, exposing management sessions to interception.",
      remediation: "config system global\n  set admin-http disable\n  set admin-https enable\nend",
      check: (line) => /(?:ip http server|set admin-http enable|set http enable)/i.test(line)
    },
    {
      id: "NCM-CRYPTO-004", title: "Weak SSH cipher suite permitted", severity: "medium",
      device: "dist-sw-04", vendor: "Cisco IOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 SC-13 · CIS cryptographic-settings guidance", line: 72,
      nistControls: [["SC-13", "Cryptographic Protection"]],
      cisGuidance: "SSH cryptographic settings; edition-specific control ID not asserted",
      source: "ip ssh server algorithm encryption aes128-cbc 3des-cbc",
      description: "Legacy CBC or 3DES cipher suites are weaker than current authenticated encryption options and should be removed where the platform supports stronger alternatives.",
      remediation: "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr",
      check: (line) => /(?:ssh.*(?:3des|des-cbc|aes\d+-cbc|rc4)|(?:3des|des-cbc|aes\d+-cbc|rc4).*ssh)/i.test(line)
    },
    {
      id: "NCM-MGMT-005", title: "Legal login banner is not configured", severity: "medium",
      device: "core-rtr-01", vendor: "Cisco IOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 AC-8 · CIS login-banner guidance", line: null,
      nistControls: [["AC-8", "System Use Notification"]],
      cisGuidance: "Pre-authentication banner; edition-specific control ID not asserted",
      source: "No banner motd or banner login directive found in the configuration.", description: "A pre-authentication notice can communicate authorized-use terms. No login banner directive was present in the reviewed snapshot.",
      remediation: "banner motd ^CAuthorized access only. Activity may be monitored.^C",
      check: (lines) => !lines.some((line) => /^\s*banner\s+(?:motd|login)\b/i.test(line))
    },
    {
      id: "NCM-MGMT-006", title: "Management idle timeout exceeds policy", severity: "medium",
      device: "dist-sw-04", vendor: "Cisco IOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 AC-12 · CIS session-timeout guidance", line: 91,
      nistControls: [["AC-12", "Session Termination"]],
      cisGuidance: "Management session timeout; edition-specific control ID not asserted",
      source: "exec-timeout 30 0",
      description: "An inactive management session remains available for 30 minutes. Shorter idle timeouts reduce the window for reuse of unattended sessions.",
      remediation: "line vty 0 4\n exec-timeout 10 0",
      check: (line) => /^\s*exec-timeout\s+(?:1[1-9]|[2-9]\d|\d{3,})\s/i.test(line)
    },
    {
      id: "NCM-LOG-007", title: "Centralized syslog destination is missing", severity: "low",
      device: "campus-sw-07", vendor: "Arista EOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 AU-2, AU-12 · CIS logging guidance", line: null,
      nistControls: [["AU-2", "Event Logging"], ["AU-12", "Audit Record Generation"]],
      cisGuidance: "Centralized logging; edition-specific control ID not asserted",
      source: "No logging host directive found in the configuration.", description: "Without a configured central log destination, device events may not be retained in the organization's monitoring and investigation workflow.",
      remediation: "logging host 192.0.2.40",
      check: (lines) => !lines.some((line) => /^\s*logging\s+host\b/i.test(line))
    },
    {
      id: "NCM-ACL-008", title: "Overly permissive any-to-any access rule", severity: "high",
      device: "edge-fw-02", vendor: "Fortinet FortiOS", framework: ["CIS", "NIST"],
      control: "NIST SP 800-53 Rev. 5 SC-7, CM-6 · CIS firewall-policy guidance", line: 88,
      nistControls: [["SC-7", "Boundary Protection"], ["CM-6", "Configuration Settings"]],
      cisGuidance: "Least-privilege firewall policy; edition-specific control ID not asserted",
      source: "set srcaddr all / set dstaddr all / set action accept",
      description: "A firewall policy permits traffic from every source to every destination. Review the intended service scope and replace broad selectors with least-privilege address objects.",
      remediation: "config firewall policy\n  edit 12\n    set srcaddr <approved-source>\n    set dstaddr <approved-destination>\n  next\nend",
      check: (line) => /(?:permit\s+(?:ip|any)\s+any\s+any|set\s+srcaddr\s+all.*set\s+dstaddr\s+all)/i.test(line)
    }
  ];

  const devices = [
    { name: "core-rtr-01", vendor: "Cisco IOS", type: "Router", posture: 82, scanned: "09:42 IST", icon: "⌘" },
    { name: "edge-fw-02", vendor: "Fortinet FortiOS", type: "Firewall", posture: 68, scanned: "09:40 IST", icon: "◈" },
    { name: "dist-sw-04", vendor: "Cisco IOS", type: "Switch", posture: 91, scanned: "09:36 IST", icon: "▦" },
    { name: "campus-sw-07", vendor: "Arista EOS", type: "Switch", posture: 96, scanned: "09:30 IST", icon: "▦" }
  ];
  let allFindings = findings.slice();
  let toastTimer;
  let uploadedDeviceCount = 0;

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[character]);
  }

  function severityMarkup(severity) {
    return `<span class="severity-pill ${severity}"><span class="sev-dot sev-${severity}"></span>${escapeHtml(severity)}</span>`;
  }

  function vendorMarkup(vendor) {
    const kind = vendor.toLowerCase().includes("fortinet") ? "vendor-fortinet"
      : vendor.toLowerCase().includes("juniper") ? "vendor-juniper"
        : vendor.toLowerCase().includes("arista") ? "vendor-arista" : "";
    return `<span class="vendor-chip"><i class="vendor-mark ${kind}"></i>${escapeHtml(vendor)}</span>`;
  }

  function showToast(message, isError = false) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add("hidden"), 3400);
  }

  function renderDeviceRows(target, compact) {
    const counts = new Map();
    allFindings.forEach((finding) => counts.set(finding.device, (counts.get(finding.device) || 0) + 1));
    target.innerHTML = devices.map((device) => {
      const count = counts.get(device.name) || 0;
      const postureClass = device.posture < 80 ? "warning" : "";
      if (compact) {
        return `<tr><td><span class="device-name-cell"><span class="device-icon">${device.icon}</span>${escapeHtml(device.name)}</span></td><td>${vendorMarkup(device.vendor)}</td><td><span class="posture-pill ${postureClass}">${device.posture}%</span></td><td><span class="table-findings">${String(count).padStart(2, "0")}</span></td><td><span class="table-date">${escapeHtml(device.scanned)}</span></td><td><span class="row-arrow">›</span></td></tr>`;
      }
      return `<tr><td><span class="device-name-cell"><span class="device-icon">${device.icon}</span>${escapeHtml(device.name)}</span></td><td>${vendorMarkup(device.vendor)}</td><td>${escapeHtml(device.type)}</td><td><span class="posture-pill ${postureClass}">${device.posture < 80 ? "Needs review" : "Monitored"}</span></td><td><span class="table-findings">${String(count).padStart(2, "0")}</span></td><td><span class="table-date">${escapeHtml(device.scanned)}</span></td></tr>`;
    }).join("");
  }

  function renderDevices() {
    renderDeviceRows($("#device-preview"), true);
    renderDeviceRows($("#device-table-body"), false);
    $("#inventory-count").textContent = String(24 + uploadedDeviceCount).padStart(2, "0");
    $("#device-count-label").textContent = `${String(devices.length).padStart(2, "0")} ASSETS`;
  }

  function renderFindings() {
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    allFindings.forEach((finding) => { severityCounts[finding.severity] += 1; });
    Object.keys(severityCounts).forEach((severity) => {
      const target = $(`#summary-${severity}`);
      if (target) target.textContent = String(severityCounts[severity]).padStart(2, "0");
    });
    $("#nav-finding-count").textContent = String(allFindings.length).padStart(2, "0");
    $("#metric-findings").innerHTML = `${String(allFindings.length).padStart(2, "0")}<span class="metric-unit"> issues</span>`;
    const query = $("#finding-search").value.trim().toLowerCase();
    const severity = $("#severity-filter").value;
    const framework = $("#framework-filter").value;
    const visible = allFindings.filter((finding) => {
      const searchable = `${finding.title} ${finding.device} ${finding.vendor} ${finding.control} ${finding.id}`.toLowerCase();
      return (!query || searchable.includes(query))
        && (severity === "all" || finding.severity === severity)
        && (framework === "all" || finding.framework.includes(framework));
    });
    $("#finding-result-count").textContent = `${visible.length} ${visible.length === 1 ? "finding" : "findings"}`;
    $("#empty-findings").classList.toggle("hidden", visible.length !== 0);
    $("#findings-table-body").innerHTML = visible.map((finding) => `
      <tr class="finding-row" data-finding-id="${escapeHtml(finding.id)}" tabindex="0" role="button" aria-label="Open ${escapeHtml(finding.title)}">
        <td><div class="finding-title-cell"><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.id)}</small></div></td>
        <td><span class="device-name-cell">${escapeHtml(finding.device)}</span><small class="table-date">${escapeHtml(finding.vendor)}</small></td>
        <td>${severityMarkup(finding.severity)}</td>
        <td><span class="framework-tags">${finding.framework.map((tag) => `<span class="framework-tag">${escapeHtml(tag)}</span>`).join("")}</span></td>
        <td><span class="table-date">Today, ${escapeHtml(devices.find((device) => device.name === finding.device)?.scanned || "09:42 IST")}</span></td>
        <td><span class="row-arrow">›</span></td>
      </tr>`).join("");
    $$(".finding-row", $("#findings-table-body")).forEach((row) => {
      const open = () => openFinding(row.dataset.findingId);
      row.addEventListener("click", open);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
    });
    renderDevices();
  }

  function openFinding(id) {
    const finding = allFindings.find((item) => item.id === id);
    if (!finding) return;
    $("#detail-content").innerHTML = `
      <div class="detail-header">${severityMarkup(finding.severity)}<h2 id="detail-title">${escapeHtml(finding.title)}</h2><span class="detail-rule">${escapeHtml(finding.id)} &nbsp;·&nbsp; ${escapeHtml(finding.device)} &nbsp;·&nbsp; ${escapeHtml(finding.vendor)}</span></div>
      <div class="detail-section"><span class="detail-section-label">WHAT WE OBSERVED</span><p>${escapeHtml(finding.description)}</p></div>
      <div class="detail-section"><span class="detail-section-label">${finding.line ? `SOURCE EVIDENCE · LINE ${finding.line}` : "CONFIGURATION EVIDENCE · DIRECTIVE NOT FOUND"}</span><div class="source-snippet"><span class="line-no">${finding.line ? String(finding.line).padStart(3, "0") : "CHK"}</span><span class="source-highlight">${escapeHtml(finding.source)}</span></div></div>
      <div class="detail-section"><span class="detail-section-label">ILLUSTRATIVE FRAMEWORK REFERENCES</span><div class="detail-frameworks">${finding.control.split(" · ").map((control) => `<span>${escapeHtml(control)}</span>`).join("")}</div></div>
      <div class="detail-section"><span class="detail-section-label">SUGGESTED REMEDIATION · REVIEW BEFORE APPLYING</span><pre class="remediation-block">${escapeHtml(finding.remediation)}</pre></div>
      <p class="disclaimer-note">Reference mappings are illustrative demo values. Validate against the applicable, current benchmark.</p>`;
    $("#detail-modal").classList.remove("hidden");
  }

  function setPage(page) {
    const known = ["dashboard", "findings", "devices", "ai-review", "reports"];
    if (!known.includes(page)) return;
    $$(".page-view").forEach((view) => view.classList.toggle("visible", view.id === `page-${page}`));
    $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.page === page));
    $("#breadcrumb-page").textContent = ({
      dashboard: "Dashboard", findings: "Findings", devices: "Devices",
      "ai-review": "AI review", reports: "Reports"
    })[page];
    if (page === "findings") renderFindings();
    if (page === "devices") renderDevices();
  }

  function renderUploadedFinding(rule, device, lineNumber, source) {
    return {
      ...rule,
      device,
      vendor: devices.find((item) => item.name === device)?.vendor || "Uploaded configuration",
      line: lineNumber,
      source: source || rule.source,
      control: `${rule.framework.join(" · ")} · illustrative controls`,
      framework: rule.framework.slice(),
      id: `DEMO-${rule.id}`,
      description: `${rule.description} This observation was detected in the uploaded snapshot by a limited browser-based demo check.`
    };
  }

  function detectVendor(fileName, text) {
    if (/forti|fortigate|fgt/i.test(fileName) || /config\s+system\s+global|config\s+firewall\s+policy/i.test(text)) {
      return { vendor: "Fortinet FortiOS", type: "Firewall" };
    }
    if (/juniper|junos/i.test(fileName) || /^\s*set\s+system\s+services/m.test(text)) {
      return { vendor: "Juniper Junos", type: "Router" };
    }
    if (/arista|eos/i.test(fileName) || /^\s*management\s+api\s+http-commands/m.test(text)) {
      return { vendor: "Arista EOS", type: "Switch" };
    }
    if (/cisco|ios|router|switch/i.test(fileName) || /^\s*(?:version\s+\d|hostname\s+|interface\s+|line\s+vty)/mi.test(text)) {
      return { vendor: "Cisco IOS", type: "Router" };
    }
    return null;
  }

  function scanConfig(file) {
    const output = $("#scan-result");
    output.classList.add("hidden");
    output.classList.remove("warning");
    if (file.size > 2 * 1024 * 1024) {
      output.innerHTML = "<strong>Configuration is too large.</strong>Choose a snapshot under 2 MB for this browser demo.";
      output.classList.remove("hidden");
      output.classList.add("warning");
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => {
      output.innerHTML = "<strong>Could not read this file.</strong>Your browser could not open the selected configuration. Try a plain-text .cfg or .conf file.";
      output.classList.remove("hidden");
      output.classList.add("warning");
    };
    reader.onload = () => {
      const text = String(reader.result || "");
      const detected = detectVendor(file.name, text);
      if (!detected) {
        output.innerHTML = "<strong>Vendor not recognized.</strong>This demo identifies Cisco IOS and FortiOS signatures. No compliance verdict was produced.";
        output.classList.remove("hidden");
        output.classList.add("warning");
        return;
      }
      const lines = text.split(/\r?\n/);
      const deviceNameLine = lines.find((line) => /^\s*(?:hostname|set\s+hostname|set\s+system\s+host-name)\s+/i.test(line));
      let deviceName = deviceNameLine
        ? deviceNameLine.replace(/^\s*(?:hostname|set\s+hostname|set\s+system\s+host-name)\s+/i, "").replace(/["']/g, "").trim()
        : file.name.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9_-]/g, "-");
      deviceName = deviceName.slice(0, 40) || `uploaded-${Date.now()}`;
      const currentDevice = devices.find((device) => device.name === deviceName);
      if (currentDevice) {
        currentDevice.vendor = detected.vendor;
        currentDevice.type = detected.type;
        currentDevice.scanned = "Just now";
      } else {
        devices.unshift({ name: deviceName, vendor: detected.vendor, type: detected.type, posture: 100, scanned: "Just now", icon: "⌘" });
        uploadedDeviceCount += 1;
      }
      const ruleChecks = [
        { id: "NCM-MGMT-001", regex: /transport input.*\btelnet\b|set admin-telnet enable|set telnet enable/i },
        { id: "NCM-SNMP-002", regex: /(?:community\s+["']?(?:public|private)\b|set\s+name\s+["']?(?:public|private)\b)/i },
        { id: "NCM-MGMT-003", regex: /(?:ip http server|set admin-http enable|set http enable)/i },
        { id: "NCM-CRYPTO-004", regex: /(?:ssh.*(?:3des|des-cbc|aes\d+-cbc|rc4)|(?:3des|des-cbc|aes\d+-cbc|rc4).*ssh)/i },
        { id: "NCM-ACL-008", regex: /(?:permit\s+(?:ip|any)\s+any\s+any|set\s+srcaddr\s+all.*set\s+dstaddr\s+all)/i }
      ];
      const scanned = new Set();
      const detectedFindings = [];
      lines.forEach((line, index) => {
        ruleChecks.forEach((check) => {
          if (!scanned.has(check.id) && check.regex.test(line)) {
            const rule = findings.find((item) => item.id === check.id);
            if (rule) detectedFindings.push(renderUploadedFinding(rule, deviceName, index + 1, line.trim()));
            scanned.add(check.id);
          }
        });
      });
      allFindings = allFindings.filter((item) => !item.id.startsWith("DEMO-") || item.device !== deviceName).concat(detectedFindings);
      renderFindings();
      const findingLabel = detectedFindings.length === 1 ? "finding" : "findings";
      const resultMessage = detectedFindings.length
        ? `<strong>Snapshot analyzed · ${escapeHtml(detected.vendor)} · ${escapeHtml(deviceName)}</strong>${detectedFindings.length} demo ${findingLabel} detected with exact source lines. Only explicit signatures were checked; absence of findings does not mean the device is compliant.`
        : `<strong>Snapshot analyzed · ${escapeHtml(detected.vendor)} · ${escapeHtml(deviceName)}</strong>No supported issue signatures were detected by the limited demo checks. This is not a complete configuration assessment or a compliance verdict.`;
      output.innerHTML = resultMessage;
      output.classList.remove("hidden");
      output.classList.add("warning");
      showToast(`Local scan complete: ${detectedFindings.length} ${findingLabel}.`);
    };
    reader.readAsText(file);
  }

  const ascii = (text) => String(text).replace(/[^\x20-\x7E]/g, "-");
  const pdfEscape = (text) => ascii(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const pdfColor = {
    ink: [0.11, 0.17, 0.24], muted: [0.43, 0.49, 0.56], green: [0.19, 0.62, 0.45],
    navy: [0.08, 0.14, 0.22], pale: [0.94, 0.97, 0.95], red: [0.71, 0.28, 0.27],
    orange: [0.73, 0.42, 0.25], yellow: [0.63, 0.54, 0.23], grey: [0.48, 0.53, 0.58]
  };

  function createPdf() {
    const pages = [];
    const pageCount = 2 + Math.ceil(findings.length / 2);
    const makePage = () => {
      const commands = [];
      const fill = (color) => `${color[0]} ${color[1]} ${color[2]} rg`;
      const stroke = (color) => `${color[0]} ${color[1]} ${color[2]} RG`;
      const baseline = (top) => 792 - top;
      const text = (value, x, top, size = 9, color = pdfColor.ink, bold = false) => {
        commands.push(`BT /${bold ? "F2" : "F1"} ${size} Tf ${fill(color)} 1 0 0 1 ${x} ${baseline(top)} Tm (${pdfEscape(value)}) Tj ET`);
      };
      const rect = (x, top, width, height, color) => commands.push(`${fill(color)} ${x} ${792 - top - height} ${width} ${height} re f`);
      const line = (x1, top1, x2, top2, color = pdfColor.pale, width = 1) => commands.push(`${stroke(color)} ${width} w ${x1} ${baseline(top1)} m ${x2} ${baseline(top2)} l S`);
      const wrapText = (value, maxChars) => {
        const words = ascii(value).split(/\s+/);
        const rows = [];
        let row = "";
        words.forEach((word) => {
          const next = row ? `${row} ${word}` : word;
          if (next.length > maxChars && row) { rows.push(row); row = word; }
          else row = next;
        });
        if (row) rows.push(row);
        return rows;
      };
      const paragraph = (value, x, top, maxChars = 95, leading = 12, size = 8, color = pdfColor.muted, bold = false) => {
        const rows = wrapText(value, maxChars);
        rows.forEach((row, index) => text(row, x, top + index * leading, size, color, bold));
        return top + rows.length * leading;
      };
      const header = (pageNumber, section) => {
        rect(0, 0, 612, 58, pdfColor.navy);
        text("AEGIS  /  NETWORK ASSURANCE", 42, 26, 9, [0.65, 0.86, 0.76], true);
        text(section.toUpperCase(), 42, 43, 7, [0.7, 0.76, 0.81]);
        text(`DEMO-NTRO-001     PAGE ${String(pageNumber).padStart(2, "0")} / ${String(pageCount).padStart(2, "0")}`, 406, 34, 7, [0.75, 0.8, 0.84]);
        line(42, 758, 570, 758, [0.88, 0.9, 0.91], 0.7);
        text("SYNTHETIC SAMPLE DATA - NOT AN OFFICIAL COMPLIANCE ASSESSMENT", 42, 775, 6, pdfColor.grey);
      };
      return { commands, text, rect, line, paragraph, header };
    };
    const findingRef = (index) => `F-${String(index + 1).padStart(3, "0")}`;
    const counts = findings.reduce((total, finding) => {
      total[finding.severity] += 1;
      return total;
    }, { critical: 0, high: 0, medium: 0, low: 0 });

    const summary = makePage();
    summary.header(1, "Executive summary");
    summary.text("NETWORK CONFIGURATION SECURITY REVIEW", 42, 94, 8, pdfColor.green, true);
    summary.text("Sample audit report", 42, 126, 25, pdfColor.ink, true);
    summary.text("NTRO - Production network estate (fictional demonstration data)", 42, 148, 9, pdfColor.muted);

    summary.rect(42, 169, 528, 67, pdfColor.pale);
    summary.text("REPORT REFERENCE", 56, 187, 6.5, pdfColor.muted, true);
    summary.text("DEMO-NTRO-001", 56, 204, 9, pdfColor.ink, true);
    summary.text("ASSESSMENT DATE", 214, 187, 6.5, pdfColor.muted, true);
    summary.text("30 September 2026", 214, 204, 9, pdfColor.ink, true);
    summary.text("SCOPE", 391, 187, 6.5, pdfColor.muted, true);
    summary.text("4 sample configs / 3 vendors", 391, 204, 8, pdfColor.ink, true);
    summary.text("EXECUTIVE SUMMARY", 42, 270, 8, pdfColor.green, true);
    summary.paragraph("This report demonstrates the output structure for an offline, read-only network-configuration review. The fixed sample contains four fictional configuration snapshots: two Cisco IOS devices, one Fortinet FortiOS firewall, and one Arista EOS switch.", 42, 290, 104, 12, 8);
    summary.paragraph(`The sample rule set records ${findings.length} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, and ${counts.low} low. This PDF always uses the same built-in sample records and does not include files uploaded during a demo session.`, 42, 338, 104, 12, 8);
    summary.text("FINDINGS SUMMARY", 42, 399, 8, pdfColor.green, true);
    summary.rect(42, 414, 528, 24, [0.96, 0.97, 0.97]);
    summary.text("SEVERITY", 54, 430, 6.5, pdfColor.muted, true);
    summary.text("COUNT", 199, 430, 6.5, pdfColor.muted, true);
    summary.text("SAMPLE OBSERVATIONS", 281, 430, 6.5, pdfColor.muted, true);
    const severitySummary = [
      ["Critical", counts.critical, "Default SNMP community"],
      ["High", counts.high, "Telnet, cleartext HTTP, broad firewall policy"],
      ["Medium", counts.medium, "Weak cipher, banner, idle timeout"],
      ["Low", counts.low, "Centralized logging destination"]
    ];
    severitySummary.forEach((row, index) => {
      const top = 459 + index * 28;
      summary.text(row[0], 54, top, 8, pdfColor.ink, true);
      summary.text(String(row[1]).padStart(2, "0"), 199, top, 8, pdfColor.ink, true);
      summary.text(row[2], 281, top, 7.5, pdfColor.muted);
      summary.line(42, top + 10, 570, top + 10, [0.91, 0.93, 0.94], 0.6);
    });
    summary.text("METHOD AND LIMITATIONS", 42, 594, 8, pdfColor.green, true);
    summary.paragraph("The prototype analyzes uploaded snapshots locally using a limited set of deterministic checks. It does not connect to devices, run a complete benchmark, verify remediation, or issue a production compliance verdict. Sample line numbers refer only to the fictional fixtures represented in this report.", 42, 614, 104, 12, 7.5);
    summary.paragraph("Severity is the sample rule-pack priority label, not a CVSS score. Findings are not ranked using an exploitability calculation.", 42, 663, 104, 12, 7.5);
    pages.push(summary.commands.join("\n"));

    const crosswalk = makePage();
    crosswalk.header(2, "Framework crosswalk");
    crosswalk.text("FRAMEWORK REFERENCES", 42, 91, 8, pdfColor.green, true);
    crosswalk.text("Mapped evidence and validation status", 42, 115, 17, pdfColor.ink, true);
    crosswalk.paragraph("NIST control identifiers below use the NIST SP 800-53 Revision 5 catalog. They are candidate relationships for review, not a determination that a control is satisfied or applicable.", 42, 136, 104, 12, 8);
    crosswalk.rect(42, 169, 528, 24, [0.96, 0.97, 0.97]);
    crosswalk.text("NIST CONTROL", 52, 185, 6.5, pdfColor.muted, true);
    crosswalk.text("CONTROL NAME", 151, 185, 6.5, pdfColor.muted, true);
    crosswalk.text("SAMPLE FINDINGS", 421, 185, 6.5, pdfColor.muted, true);
    const controlMap = new Map();
    findings.forEach((finding, index) => finding.nistControls.forEach(([id, name]) => {
      if (!controlMap.has(id)) controlMap.set(id, { name, references: [] });
      controlMap.get(id).references.push(findingRef(index));
    }));
    Array.from(controlMap.entries()).sort((a, b) => a[0].localeCompare(b[0])).forEach(([id, control], index) => {
      const top = 211 + index * 25;
      crosswalk.text(id, 52, top, 8, pdfColor.ink, true);
      crosswalk.text(control.name, 151, top, 7.5, pdfColor.muted);
      crosswalk.text(control.references.join(", "), 421, top, 7, pdfColor.green);
      crosswalk.line(42, top + 8, 570, top + 8, [0.91, 0.93, 0.94], 0.5);
    });
    crosswalk.text("CIS BENCHMARK GUIDANCE", 42, 475, 8, pdfColor.green, true);
    crosswalk.paragraph("The sample identifies applicable CIS benchmark guidance areas by vendor (Cisco IOS, Fortinet FortiOS, and Arista EOS). Version-specific CIS control identifiers are intentionally omitted because the exact benchmark editions and validated crosswalk are not part of this demo dataset.", 42, 495, 104, 12, 7.5);
    crosswalk.text("NOT MAPPED IN THIS SAMPLE", 42, 546, 8, pdfColor.green, true);
    crosswalk.paragraph("No DISA STIG finding IDs or ISO/IEC 27001 control IDs are asserted in this report. Add these citations only after validating the target benchmark edition and the rule-to-control mapping.", 42, 566, 104, 12, 7.5);
    crosswalk.text("SOURCE", 42, 618, 8, pdfColor.green, true);
    crosswalk.paragraph("NIST Special Publication 800-53, Revision 5: Security and Privacy Controls for Information Systems and Organizations. The controls shown are references for assessor review; they are not audit conclusions.", 42, 638, 104, 12, 7.5);
    pages.push(crosswalk.commands.join("\n"));

    const detailPages = [];
    for (let start = 0; start < findings.length; start += 2) detailPages.push(findings.slice(start, start + 2));
    detailPages.forEach((pageFindings, pageIndex) => {
      const page = makePage();
      page.header(pageIndex + 3, "Finding details");
      page.text(`FINDINGS REGISTER  /  ${String(pageIndex + 1).padStart(2, "0")}`, 42, 89, 8, pdfColor.green, true);
      page.text("Evidence and remediation", 42, 112, 17, pdfColor.ink, true);
      page.text(`${pageFindings.length} sample observations  -  fixed demonstration dataset`, 42, 130, 8, pdfColor.muted);
      pageFindings.forEach((finding, index) => {
        const number = pageIndex * 2 + index;
        const top = index === 0 ? 153 : 451;
        const severityColor = finding.severity === "critical" ? pdfColor.red
          : finding.severity === "high" ? pdfColor.orange
            : finding.severity === "medium" ? pdfColor.yellow : pdfColor.green;
        page.line(42, top, 570, top, [0.87, 0.9, 0.91], 0.8);
        page.text(`${findingRef(number)}  /  ${finding.severity.toUpperCase()}`, 42, top + 17, 7, severityColor, true);
        page.text(`${finding.title}`, 42, top + 36, 11, pdfColor.ink, true);
        page.text(`ASSET  ${finding.device}     VENDOR  ${finding.vendor}     STATUS  Open`, 42, top + 52, 7, pdfColor.muted);
        page.text("OBSERVATION", 42, top + 73, 6.5, pdfColor.green, true);
        const observationEnd = page.paragraph(finding.description, 42, top + 88, 105, 10, 7.2, pdfColor.muted);
        const evidenceTop = observationEnd + 9;
        page.text(finding.line ? `CONFIGURATION EVIDENCE  /  SOURCE LINE ${finding.line}` : "CONFIGURATION EVIDENCE  /  REQUIRED DIRECTIVE NOT FOUND", 42, evidenceTop, 6.5, pdfColor.green, true);
        page.rect(42, evidenceTop + 5, 528, 39, pdfColor.navy);
        page.text(finding.line ? `LINE ${finding.line}` : "CHECK", 49, evidenceTop + 17, 6, [0.65, 0.76, 0.8]);
        page.paragraph(finding.source, 92, evidenceTop + 18, 91, 9, 7, [0.8, 0.88, 0.84]);
        const evidenceBottom = evidenceTop + 47;
        const contentTop = evidenceBottom + 21;
        const nistRefs = finding.nistControls.map(([id]) => id).join(", ");
        page.text(`NIST SP 800-53 REV. 5  ${nistRefs}`, 42, contentTop, 7, pdfColor.ink, true);
        page.paragraph(`CIS guidance: ${finding.cisGuidance}. No DISA STIG or ISO/IEC 27001 citation is asserted for this sample finding.`, 42, contentTop + 13, 104, 10, 6.8, pdfColor.muted);
        const remediationTop = contentTop + 43;
        page.text("RECOMMENDED REMEDIATION  /  REVIEW BEFORE APPLYING", 42, remediationTop, 6.5, pdfColor.green, true);
        const remediationLines = finding.remediation.split(/\r?\n/);
        remediationLines.forEach((line, lineIndex) => page.text(line, 42, remediationTop + 15 + lineIndex * 9, 6.7, pdfColor.ink));
      });
      pages.push(page.commands.join("\n"));
    });

    const objects = [];
    const pageRefs = pages.map((_, index) => `${6 + index * 2} 0 R`).join(" ");
    objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
    objects[2] = `<< /Type /Pages /Kids [${pageRefs}] /Count ${pages.length} >>`;
    objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
    objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>";
    pages.forEach((content, index) => {
      const contentId = 5 + index * 2;
      const pageId = contentId + 1;
      objects[contentId] = `<< /Length ${content.length} >>\nstream\n${content}\nendstream`;
      objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`;
    });
    const infoId = 5 + pages.length * 2;
    objects[infoId] = `<< /Title (${pdfEscape("Aegis Sample Network Configuration Security Review")}) /Author (${pdfEscape("Aegis Network Assurance")}) /Subject (${pdfEscape("Fixed synthetic audit report demonstration")}) /Producer (${pdfEscape("Aegis browser report generator")}) >>`;
    let pdf = "%PDF-1.4\n";
    const offsets = [0];
    for (let id = 1; id < objects.length; id += 1) {
      offsets[id] = pdf.length;
      pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`;
    }
    const xrefOffset = pdf.length;
    pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
    for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
    pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R /Info ${infoId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
    return new Blob([pdf], { type: "application/pdf" });
  }

  function downloadReport() {
    const pdf = createPdf();
    const url = URL.createObjectURL(pdf);
    const link = document.createElement("a");
    link.href = url;
    link.download = "aegis-sample-security-audit.pdf";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast("Fixed sample PDF downloaded; uploaded configurations are not included.");
  }

  function openScan() {
    $("#scan-modal").classList.remove("hidden");
    $("#scan-result").classList.add("hidden");
    $("#config-file").value = "";
  }

  function closeModal(modal) {
    modal.classList.add("hidden");
  }

  $$(".nav-item").forEach((button) => button.addEventListener("click", () => setPage(button.dataset.page)));
  $$("[data-go]").forEach((button) => button.addEventListener("click", () => setPage(button.dataset.go)));
  $$("[data-open-scan]").forEach((button) => button.addEventListener("click", openScan));
  $$("[data-download-report]").forEach((button) => button.addEventListener("click", downloadReport));
  $$("[data-close-scan]").forEach((button) => button.addEventListener("click", () => closeModal($("#scan-modal"))));
  $("#close-detail").addEventListener("click", () => closeModal($("#detail-modal")));
  $("#dismiss-notice").addEventListener("click", () => $(".demo-notice").remove());
  $("#help-button").addEventListener("click", () => showToast("Aegis demo: local-first, read-only network configuration auditing."));
  $("#finding-search").addEventListener("input", renderFindings);
  $("#severity-filter").addEventListener("change", renderFindings);
  $("#framework-filter").addEventListener("change", renderFindings);
  $("#config-file").addEventListener("change", (event) => {
    if (event.target.files && event.target.files[0]) scanConfig(event.target.files[0]);
  });
  const uploadZone = $("#upload-zone");
  uploadZone.addEventListener("dragover", (event) => { event.preventDefault(); uploadZone.classList.add("dragging"); });
  uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("dragging"));
  uploadZone.addEventListener("drop", (event) => {
    event.preventDefault();
    uploadZone.classList.remove("dragging");
    if (event.dataTransfer.files && event.dataTransfer.files[0]) scanConfig(event.dataTransfer.files[0]);
  });
  $("#confirm-mapping").addEventListener("click", () => {
    $("#mapping-card").innerHTML = `<div class="mapping-head"><div><span class="section-kicker">MAPPING STATUS</span><h3>Juniper Junos · management access</h3></div><span class="posture-pill reviewed">✓ Human confirmed</span></div><div class="mapping-context"><span>✓</span><span><strong>Confirmed for this demo session.</strong> The proposed mapping is now marked as reviewed. Compliance decisions still come from deterministic rules, not an AI model.</span></div><div class="mapping-flow"><div class="mapping-code"><span class="mapping-label">OBSERVED CONFIG LINE</span><code>set system services telnet</code><small>junos-edge-03.conf · line 18</small></div><span class="mapping-arrow">→</span><div class="mapping-model"><span class="mapping-label">CONFIRMED NCM FIELD</span><code>management_plane.<b>telnet_enabled</b></code><small>Human-confirmed mapping</small></div></div>`;
    $(".review-count").innerHTML = '<span class="sev-dot sev-low"></span> 0 mappings to review';
    $(".nav-dot")?.remove();
    showToast("Mapping confirmed for this demo session.");
  });
  $("#reject-mapping").addEventListener("click", () => {
    $("#mapping-card").innerHTML = `<div class="mapping-head"><div><span class="section-kicker">SUGGESTION REJECTED</span><h3>Juniper Junos · management access</h3></div><span class="posture-pill warning">Not trusted</span></div><p class="page-subtitle">This mapping will not be used in analysis. Unconfirmed or rejected suggestions never produce compliance findings.</p>`;
    $(".review-count").innerHTML = '<span class="sev-dot sev-low"></span> 0 mappings to review';
    $(".nav-dot")?.remove();
    showToast("Suggestion rejected. It will not be used for analysis.");
  });
  [$("#scan-modal"), $("#detail-modal")].forEach((modal) => modal.addEventListener("click", (event) => {
    if (event.target === modal) closeModal(modal);
  }));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") $$(".modal-backdrop").forEach((modal) => closeModal(modal));
  });

  renderFindings();
  renderDevices();
})();
