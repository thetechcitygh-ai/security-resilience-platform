import React, { forwardRef, useMemo, useRef, useState } from "react";

const frameworks = [
  { key: "owasp", name: "OWASP Top 10", category: "Application Security", type: "technical" },
  { key: "nist", name: "NIST SP 800-115", category: "Technical Security Testing", type: "technical" },
  { key: "ceh", name: "CEH Methodology", category: "Ethical Hacking Lifecycle", type: "technical" },
  { key: "ptes", name: "PTES", category: "Penetration Testing Execution Standard", type: "technical" },
  { key: "dora", name: "DORA", category: "Digital Operational Resilience", type: "regulatory" },
  { key: "eba", name: "EBA ICT Risk", category: "ICT and Security Risk Management", type: "regulatory" },
  { key: "tiber", name: "TIBER-EU", category: "Threat-led Resilience Testing", type: "regulatory" }
];

const testingLevels = [
  {
    key: "penetration",
    title: "Penetration Testing",
    subtitle: "Authorised technical validation",
    description: "Controlled validation of weaknesses using signed rules of engagement, agreed windows and non-destructive checks.",
    controls: ["Signed scope", "Rules of engagement", "Manual validation", "Retest workflow"],
    phases: ["Authorisation gate", "Passive recon", "Safe service review", "Control validation", "Evidence capture", "Report drafting"]
  },
  {
    key: "red-team",
    title: "Red Teaming",
    subtitle: "Threat-led resilience exercise",
    description: "Governed simulation of realistic adversary objectives without unsafe exploitation inside this frontend prototype.",
    controls: ["Executive mandate", "Kill switch", "Scenario brief", "Purple-team debrief"],
    phases: ["Mandate check", "Scenario loading", "Objective mapping", "Control observation", "Detection review", "Executive debrief"]
  },
  {
    key: "scenario",
    title: "Scenario-Based Testing",
    subtitle: "Operational resilience validation",
    description: "Business, technology and response-team exercises mapped to DORA, EBA and TIBER-EU governance expectations.",
    controls: ["Business scenario", "Response roles", "Escalation path", "Lessons learned"],
    phases: ["Scenario selection", "Stakeholder mapping", "Response simulation", "Continuity review", "Gap analysis", "Roadmap update"]
  }
];

const reportSections = [
  "Executive Summary",
  "Scope and Authorisation",
  "Testing Level and Methodology",
  "CVSS Breakdown",
  "Findings and Evidence Notes",
  "Remediation Roadmap",
  "DORA Compliance Matrix",
  "EBA ICT Risk Mapping",
  "TIBER-EU Resilience Notes",
  "Audit Trail"
];

const doraMatrix = [
  { area: "ICT risk management", platformControl: "Scope approval, assessment logs and remediation tracking" },
  { area: "Incident readiness", platformControl: "Scenario-based testing and escalation-path review" },
  { area: "Digital operational resilience testing", platformControl: "Penetration, red-team and scenario-based testing workflows" },
  { area: "Third-party ICT risk awareness", platformControl: "Client/owner attribution and authorisation evidence" },
  { area: "Information sharing and reporting", platformControl: "Executive, technical and remediation report packs" }
];

function getNow() {
  return new Date().toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function makeId(prefix, number) {
  return `${prefix}-${String(number).padStart(3, "0")}`;
}

function normaliseUrl(value) {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/$/, "");
}

function getUrlScheme(value) {
  const raw = value.trim().toLowerCase();
  if (raw.startsWith("https://")) return "https";
  if (raw.startsWith("http://")) return "http";
  return "unspecified";
}

function classifyExposure(target) {
  const lower = target.toLowerCase();
  if (lower.includes("localhost") || lower.includes(".local") || lower.includes("10.") || lower.includes("192.168.")) {
    return "Private";
  }
  return "Public";
}

function getSeverityClass(severity) {
  if (severity === "Critical") return "bg-red-50 text-red-700 border-red-200";
  if (severity === "High") return "bg-orange-50 text-orange-700 border-orange-200";
  if (severity === "Medium") return "bg-amber-50 text-amber-700 border-amber-200";
  if (severity === "Low") return "bg-blue-50 text-blue-700 border-blue-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}

function getRiskClass(risk) {
  if (risk === "Critical") return "bg-red-50 text-red-700 border-red-200";
  if (risk === "High") return "bg-orange-50 text-orange-700 border-orange-200";
  if (risk === "Medium") return "bg-amber-50 text-amber-700 border-amber-200";
  if (risk === "Low") return "bg-blue-50 text-blue-700 border-blue-200";
  if (risk === "Clean") return "bg-emerald-50 text-emerald-700 border-emerald-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}

function highestRisk(findings) {
  if (findings.some((item) => item.severity === "Critical")) return "Critical";
  if (findings.some((item) => item.severity === "High")) return "High";
  if (findings.some((item) => item.severity === "Medium")) return "Medium";
  if (findings.some((item) => item.severity === "Low")) return "Low";
  return "Clean";
}

const Card = forwardRef(function Card({ children, className = "" }, ref) {
  return (
    <div ref={ref} className={`rounded-3xl border border-slate-200 bg-white shadow-sm ${className}`}>
      {children}
    </div>
  );
});

function Pill({ children, className = "" }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${className}`}>
      {children}
    </span>
  );
}

function Button({ children, className = "", variant = "primary", disabled = false, ...props }) {
  const variants = {
    primary: "bg-slate-950 text-white hover:bg-slate-800 focus:ring-slate-950/10",
    secondary: "border border-slate-200 bg-white text-slate-800 hover:bg-slate-50 focus:ring-slate-950/10",
    success: "bg-emerald-500 text-white hover:bg-emerald-600 focus:ring-emerald-500/20",
    info: "bg-blue-500 text-white hover:bg-blue-600 focus:ring-blue-500/20",
    warning: "bg-amber-500 text-white hover:bg-amber-600 focus:ring-amber-500/20",
    danger: "bg-red-500 text-white hover:bg-red-600 focus:ring-red-500/20"
  };

  return (
    <button
      disabled={disabled}
      className={`rounded-2xl px-5 py-3 text-sm font-semibold shadow-sm transition focus:outline-none focus:ring-4 ${variants[variant] || variants.primary} ${disabled ? "cursor-not-allowed opacity-50" : ""} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

function StatCard({ label, value, helper }) {
  return (
    <Card className="p-5">
      <p className="text-sm text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-bold text-slate-950">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{helper}</p>
    </Card>
  );
}

function EmptyState({ title, message, action }) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-center">
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-500">{message}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

function buildAssessmentResults({ asset, testingLevel, selectedFrameworks, currentCount }) {
  const target = asset.target.toLowerCase();
  const hasHttps = asset.urlScheme === "https";
  const isPublic = asset.exposure === "Public";
  const looksLikeLogin = target.includes("portal") || target.includes("login") || target.includes("app") || target.includes("auth");
  const generated = [];

  if (!hasHttps && isPublic) {
    generated.push({
      title: "HTTPS posture requires validation",
      severity: "High",
      cvss: 7.4,
      cwe: "CWE-319",
      framework: "OWASP A02 / NIST SP 800-115",
      remediation: "Confirm HTTPS enforcement, certificate validity, secure redirects and transport security policy for the public-facing asset.",
      evidence: "The submitted public target did not explicitly include an https:// URL scheme."
    });
  }

  if (isPublic) {
    generated.push({
      title: "Public exposure requires security hardening baseline",
      severity: "Medium",
      cvss: 5.6,
      cwe: "CWE-693",
      framework: "OWASP A05 / PTES Vulnerability Analysis",
      remediation: "Validate security headers, exposed metadata, content security policy, cookie flags and platform hardening controls.",
      evidence: "The target is classified as public-facing and should be validated against a web hardening baseline."
    });
  }

  if (looksLikeLogin) {
    generated.push({
      title: "Authentication resilience review required",
      severity: "High",
      cvss: 8.0,
      cwe: "CWE-307",
      framework: "OWASP A07 / CEH Enumeration Control",
      remediation: "Validate MFA, rate limiting, account lockout, secure session management, privileged access controls and alerting.",
      evidence: "The target name or URL suggests a login portal or authenticated application."
    });
  }

  if (testingLevel === "red-team") {
    generated.push({
      title: "Threat-led detection and response coverage should be evidenced",
      severity: "Medium",
      cvss: 5.4,
      cwe: "N/A",
      framework: "TIBER-EU / DORA Resilience Testing",
      remediation: "Define red-team objectives, detection expectations, escalation channels, debrief approach and purple-team learning outcomes.",
      evidence: "Red teaming level selected. The platform requires a governed scenario, kill switch and executive mandate."
    });
  }

  if (testingLevel === "scenario") {
    generated.push({
      title: "Operational resilience scenario requires response validation",
      severity: "Medium",
      cvss: 5.2,
      cwe: "N/A",
      framework: "DORA / EBA ICT Risk / TIBER-EU",
      remediation: "Validate response roles, continuity objectives, decision escalation, communication paths and post-test lessons learned.",
      evidence: "Scenario-based testing selected. Resilience readiness should be validated beyond technical vulnerability checks."
    });
  }

  if (selectedFrameworks.includes("dora")) {
    generated.push({
      title: "DORA-aligned evidence retention should be maintained",
      severity: "Low",
      cvss: 3.1,
      cwe: "N/A",
      framework: "DORA / NIST SP 800-115 Reporting",
      remediation: "Retain scope approvals, testing records, findings, remediation notes, report versions and responsible owners in an evidence vault.",
      evidence: "DORA framework selected. The workflow should preserve audit-ready operational resilience evidence."
    });
  }

  if (generated.length === 0) {
    generated.push({
      title: "No immediate issue generated by safe baseline simulation",
      severity: "Informational",
      cvss: 0.0,
      cwe: "N/A",
      framework: "NIST SP 800-115 Reporting",
      remediation: "Proceed with approved backend technical validation and evidence capture where authorised.",
      evidence: "No rule-based concern was generated from the metadata supplied in this frontend prototype."
    });
  }

  return generated.map((finding, index) => ({
    id: `FND-${String(currentCount + index + 1).padStart(4, "0")}`,
    assetId: asset.id,
    asset: asset.name,
    target: asset.target,
    status: finding.severity === "Informational" ? "Observed" : "Open",
    owner: asset.owner,
    testingLevel,
    createdAt: getNow(),
    ...finding
  }));
}

export default function SecurityResiliencePlatform() {
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [reports, setReports] = useState([]);
  const [scanLogs, setScanLogs] = useState([]);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [activeSection, setActiveSection] = useState("dashboard");
  const [scanState, setScanState] = useState("Ready");
  const [notice, setNotice] = useState("Platform is ready. Add an authorised website or asset to begin.");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedTestingLevel, setSelectedTestingLevel] = useState("penetration");
  const [selectedFrameworks, setSelectedFrameworks] = useState(["owasp", "nist", "ptes", "dora"]);
  const [newTargetName, setNewTargetName] = useState("");
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [newTargetOwner, setNewTargetOwner] = useState("");
  const [authorisationRef, setAuthorisationRef] = useState("");
  const [rulesAccepted, setRulesAccepted] = useState(false);

  const dashboardRef = useRef(null);
  const scopeRef = useRef(null);
  const scannerRef = useRef(null);
  const testingRef = useRef(null);
  const findingsRef = useRef(null);
  const reportsRef = useRef(null);
  const auditRef = useRef(null);

  const sectionRefs = {
    dashboard: dashboardRef,
    scope: scopeRef,
    scanner: scannerRef,
    testing: testingRef,
    findings: findingsRef,
    reports: reportsRef,
    audit: auditRef
  };

  const selectedAsset = assets.find((asset) => asset.id === selectedAssetId) || null;
  const selectedLevel = testingLevels.find((level) => level.key === selectedTestingLevel) || testingLevels[0];

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      const term = query.toLowerCase().trim();
      const matchesSearch =
        !term ||
        finding.title.toLowerCase().includes(term) ||
        finding.asset.toLowerCase().includes(term) ||
        finding.framework.toLowerCase().includes(term) ||
        finding.id.toLowerCase().includes(term) ||
        finding.target.toLowerCase().includes(term) ||
        finding.cwe.toLowerCase().includes(term);
      const matchesSeverity = severityFilter === "All" || finding.severity === severityFilter;
      const matchesStatus = statusFilter === "All" || finding.status === statusFilter;
      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [findings, query, severityFilter, statusFilter]);

  const approvedAssets = assets.filter((asset) => asset.auth === "Approved").length;
  const pendingAssets = assets.filter((asset) => asset.auth !== "Approved").length;
  const openFindings = findings.filter((finding) => finding.status === "Open").length;
  const criticalFindings = findings.filter((finding) => finding.severity === "Critical").length;
  const highFindings = findings.filter((finding) => finding.severity === "High").length;
  const activeFrameworkCoverage = assets.length > 0 ? Math.round((selectedFrameworks.length / frameworks.length) * 100) : 0;

  function addAudit(action, actor = "Current User") {
    setAuditLog((current) => [{ actor, action, time: getNow(), integrity: "SHA-256 placeholder" }, ...current]);
  }

  function goToSection(section) {
    setActiveSection(section);
    sectionRefs[section]?.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    addAudit(`Viewed ${section.replace("-", " ")} section`);
  }

  function toggleFramework(key) {
    setSelectedFrameworks((current) => {
      if (current.includes(key)) {
        return current.length === 1 ? current : current.filter((item) => item !== key);
      }
      return [...current, key];
    });
  }

  function addWebsiteTarget() {
    const rawUrl = newTargetUrl.trim();
    const cleanUrl = normaliseUrl(rawUrl);
    const cleanName = newTargetName.trim();
    const cleanOwner = newTargetOwner.trim();

    if (!cleanName || !cleanUrl || !cleanOwner) {
      setNotice("Please provide the target name, website URL and owner or client name.");
      return;
    }

    if (!authorisationRef.trim() || !rulesAccepted) {
      setNotice("Please provide an authorisation reference and confirm the rules of engagement before adding the target.");
      return;
    }

    const alreadyExists = assets.some((asset) => asset.target.toLowerCase() === cleanUrl.toLowerCase());
    if (alreadyExists) {
      setNotice("This target already exists in scope. Select it from the target list instead.");
      return;
    }

    const newAsset = {
      id: makeId("AST", assets.length + 1),
      name: cleanName,
      target: cleanUrl,
      owner: cleanOwner,
      authorisationRef: authorisationRef.trim(),
      rulesAccepted,
      scope: "Pending",
      auth: "Awaiting Sign-off",
      exposure: classifyExposure(cleanUrl),
      risk: "Unknown",
      urlScheme: getUrlScheme(rawUrl),
      createdAt: getNow(),
      lastScan: "Not started",
      scanCount: 0
    };

    setAssets((current) => [...current, newAsset]);
    setSelectedAssetId(newAsset.id);
    setNewTargetName("");
    setNewTargetUrl("");
    setNewTargetOwner("");
    setAuthorisationRef("");
    setRulesAccepted(false);
    setNotice(`${cleanName} has been added as a pending target. Review and authorise the scope before assessment.`);
    addAudit(`Added target to scope: ${cleanName} (${cleanUrl})`);
  }

  function approveSelectedTarget() {
    if (!selectedAsset) {
      setNotice("Please select a target to authorise.");
      return;
    }

    setAssets((current) =>
      current.map((asset) =>
        asset.id === selectedAsset.id ? { ...asset, scope: "Locked", auth: "Approved" } : asset
      )
    );

    setNotice(`${selectedAsset.name} has been authorised and locked in scope.`);
    addAudit(`Authorised and locked scope for ${selectedAsset.name}`, "Security Lead");
  }

  function runAssessment() {
    if (!selectedAsset) {
      setNotice("Please select a target before starting an assessment.");
      addAudit("Attempted to start assessment without selecting a target", "System Guardrail");
      return;
    }

    if (selectedAsset.auth !== "Approved") {
      setNotice(`${selectedAsset.name} is not approved yet. Authorise the scope before starting an assessment.`);
      addAudit(`Blocked assessment for unapproved target: ${selectedAsset.name}`, "System Guardrail");
      return;
    }

    setScanState("Running");
    setScanLogs([]);
    setNotice(`${selectedLevel.title} started for ${selectedAsset.name}. Frontend mode runs a guarded baseline simulation only.`);
    addAudit(`Started ${selectedLevel.title} for ${selectedAsset.name}`, "Platform Scheduler");
    goToSection("scanner");

    const phases = selectedLevel.phases;
    phases.forEach((phase, index) => {
      window.setTimeout(() => {
        setScanLogs((current) => [
          ...current,
          {
            time: getNow(),
            phase,
            message: `${phase} completed for ${selectedAsset.name}`
          }
        ]);
      }, 350 * (index + 1));
    });

    window.setTimeout(() => {
      const newFindings = buildAssessmentResults({
        asset: selectedAsset,
        testingLevel: selectedTestingLevel,
        selectedFrameworks,
        currentCount: findings.length
      });
      const risk = highestRisk(newFindings);

      setFindings((current) => [...newFindings, ...current]);
      setAssets((current) =>
        current.map((asset) =>
          asset.id === selectedAsset.id
            ? { ...asset, lastScan: getNow(), risk, scanCount: asset.scanCount + 1 }
            : asset
        )
      );
      setScanState("Completed");
      setNotice(`${selectedLevel.title} completed for ${selectedAsset.name}. ${newFindings.length} result(s) generated.`);
      addAudit(`Completed ${selectedLevel.title} for ${selectedAsset.name}; ${newFindings.length} result(s) generated`, "Platform Scheduler");
    }, 350 * (phases.length + 2));
  }

  function updateFindingStatus(id, status) {
    setFindings((current) => current.map((finding) => (finding.id === id ? { ...finding, status } : finding)));
    addAudit(`Updated finding ${id} status to ${status}`, "Finding Owner");
  }

  function createReport() {
    if (assets.length === 0) {
      setNotice("There is no report to generate yet. Add and assess at least one target first.");
      return;
    }

    const report = {
      id: makeId("RPT", reports.length + 1),
      title: `Security Resilience Report ${reports.length + 1}`,
      createdAt: getNow(),
      testingLevel: selectedLevel.title,
      sections: reportSections,
      summary: {
        assetsInScope: assets.length,
        approvedAssets,
        pendingAssets,
        totalFindings: findings.length,
        openFindings,
        criticalFindings,
        highFindings,
        activeFrameworkCoverage: `${activeFrameworkCoverage}%`
      }
    };

    setReports((current) => [report, ...current]);
    setNotice(`${report.title} has been generated and added to the report register.`);
    addAudit(`Generated ${report.title}`, "Report Engine");
  }

  function exportReport() {
    if (assets.length === 0) {
      setNotice("There is no report to export yet. Add and assess at least one target first.");
      return;
    }

    const exportPack = {
      platform: "Security Resilience Platform",
      generatedAt: getNow(),
      mode: "Frontend governed assessment prototype",
      limitation: "This frontend produces governed baseline assessment outputs. Live vulnerability scanning requires an authorised backend scanner worker, evidence vault and secure job queue.",
      assets,
      findings,
      reports,
      selectedFrameworks: frameworks.filter((framework) => selectedFrameworks.includes(framework.key)),
      doraMatrix,
      auditLog
    };

    const blob = new Blob([JSON.stringify(exportPack, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `security-resilience-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);

    setNotice("Report exported as JSON.");
    addAudit("Exported security resilience report data", "Report Engine");
  }

  function printPdfPack() {
    if (assets.length === 0) {
      setNotice("There is no PDF pack to generate yet. Add and assess at least one target first.");
      return;
    }

    setNotice("Use the browser print dialog to save the current report view as PDF.");
    addAudit("Opened browser print workflow for PDF report pack", "Report Engine");
    window.print();
  }

  function configureRules() {
    setNotice("Rules active: written authority required, scope lock required, non-destructive frontend mode, audit logging enabled and unapproved assessments blocked.");
    addAudit("Viewed configured platform guardrails");
  }

  function viewRoadmap() {
    setNotice("Production roadmap: FastAPI backend, PostgreSQL, scanner job queue, OWASP ZAP/Nuclei integrations, evidence vault, PDF service, RBAC and client portal.");
    addAudit("Viewed implementation roadmap");
  }

  function clearWorkspace() {
    setAssets([]);
    setFindings([]);
    setAuditLog([]);
    setReports([]);
    setScanLogs([]);
    setSelectedAssetId("");
    setScanState("Ready");
    setNotice("Workspace cleared. Add an authorised website or asset to begin.");
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <div className="mx-auto grid max-w-7xl gap-6 p-4 lg:grid-cols-[260px_1fr] md:p-8">
        <aside className="hidden lg:block">
          <div className="sticky top-6 rounded-3xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="rounded-2xl bg-slate-950 p-4 text-white">
              <p className="text-sm uppercase tracking-wide text-slate-300">MITC Aligned</p>
              <h1 className="mt-1 text-xl font-bold">Security Resilience Platform</h1>
            </div>
            <nav className="mt-5 space-y-2">
              {[
                ["dashboard", "Dashboard"],
                ["scope", "Scope Manager"],
                ["scanner", "Scanner"],
                ["testing", "Testing Levels"],
                ["findings", "Findings"],
                ["reports", "Reports"],
                ["audit", "Audit Log"]
              ].map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => goToSection(key)}
                  className={`w-full rounded-2xl px-4 py-3 text-left text-sm font-medium transition ${
                    activeSection === key ? "bg-slate-950 text-white" : "text-slate-600 hover:bg-slate-100 hover:text-slate-950"
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>
            <div className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-emerald-800">
              <p className="text-sm font-semibold">Guardrails Active</p>
              <p className="mt-2 text-xs leading-5">No target can be assessed until scope is recorded, authorised and locked.</p>
            </div>
          </div>
        </aside>

        <main className="min-w-0">
          <header ref={dashboardRef} className="rounded-3xl bg-slate-950 p-6 text-white shadow-sm md:p-8">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <div className="flex flex-wrap gap-2">
                  <Pill className="border-slate-700 bg-slate-900 text-slate-200">Private Cloud Ready</Pill>
                  <Pill className="border-emerald-700 bg-emerald-900 text-emerald-100">White-hat Only</Pill>
                  <Pill className="border-blue-700 bg-blue-900 text-blue-100">DORA / EBA / TIBER-EU</Pill>
                  <Pill className="border-purple-700 bg-purple-900 text-purple-100">Status: {scanState}</Pill>
                </div>
                <h2 className="mt-5 text-3xl font-bold tracking-tight md:text-5xl">Cyber Security Resilience Platform</h2>
                <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300 md:text-base">
                  A governed one-stop assessment workspace covering scope, authorisation, scanning workflow, findings, CVSS-style scoring, regulatory mapping, reporting and audit evidence.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button onClick={runAssessment} variant="success" disabled={scanState === "Running"}>
                  {scanState === "Running" ? "Running..." : "Start Approved Assessment"}
                </Button>
                <Button onClick={exportReport} variant="info">Export Report</Button>
              </div>
            </div>
          </header>

          <div className="mt-4 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800">{notice}</div>

          <section className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Targets" value={assets.length} helper={`${approvedAssets} approved, ${pendingAssets} pending`} />
            <StatCard label="Open Findings" value={openFindings} helper={`${criticalFindings} critical, ${highFindings} high`} />
            <StatCard label="Framework Coverage" value={`${activeFrameworkCoverage}%`} helper={`${selectedFrameworks.length} of ${frameworks.length} active`} />
            <StatCard label="Reports" value={reports.length} helper="Generated report register" />
          </section>

          <section className="mt-6 grid gap-6 xl:grid-cols-3">
            <Card className="p-6 xl:col-span-2">
              <h2 className="text-xl font-semibold">Dashboard</h2>
              <p className="mt-1 text-sm text-slate-500">Real-time posture across scope, testing level, findings, reports and audit activity.</p>
              <div className="mt-6 grid gap-3 md:grid-cols-5">
                {[
                  ["Authorise", approvedAssets > 0],
                  ["Configure", selectedFrameworks.length > 0],
                  ["Assess", scanState === "Running" || scanState === "Completed"],
                  ["Validate", findings.length > 0],
                  ["Report", reports.length > 0]
                ].map(([stage, isDone]) => {
                  const isActive = scanState === "Running" && stage === "Assess";
                  return (
                    <div
                      key={stage}
                      className={`rounded-2xl border p-4 ${
                        isActive ? "border-purple-200 bg-purple-50" : isDone ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white"
                      }`}
                    >
                      <p className="text-sm font-semibold">{stage}</p>
                      <p className="mt-1 text-xs text-slate-500">{isActive ? "Running" : isDone ? "Ready" : "Awaiting gate"}</p>
                    </div>
                  );
                })}
              </div>
            </Card>
            <Card className="p-6">
              <h2 className="text-xl font-semibold">Active Testing Level</h2>
              <p className="mt-2 text-sm font-medium text-slate-900">{selectedLevel.title}</p>
              <p className="mt-1 text-sm text-slate-500">{selectedLevel.description}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {selectedLevel.controls.map((control) => (
                  <Pill key={control} className="border-slate-200 bg-slate-50 text-slate-700">{control}</Pill>
                ))}
              </div>
            </Card>
          </section>

          <section ref={scopeRef} className="mt-6 grid gap-6 xl:grid-cols-2">
            <Card className="p-6">
              <h2 className="text-xl font-semibold">Target Scope Manager</h2>
              <p className="mt-1 text-sm text-slate-500">Add only assets you own or have written permission to test.</p>
              <div className="mt-5 grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <input
                  value={newTargetName}
                  onChange={(event) => setNewTargetName(event.target.value)}
                  placeholder="Target name e.g. Client Portal"
                  className="h-10 rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                />
                <input
                  value={newTargetUrl}
                  onChange={(event) => setNewTargetUrl(event.target.value)}
                  placeholder="Website URL e.g. https://portal.example.com"
                  className="h-10 rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                />
                <input
                  value={newTargetOwner}
                  onChange={(event) => setNewTargetOwner(event.target.value)}
                  placeholder="Owner / client name"
                  className="h-10 rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                />
                <input
                  value={authorisationRef}
                  onChange={(event) => setAuthorisationRef(event.target.value)}
                  placeholder="Authorisation reference e.g. contract ID, email approval, signed scope"
                  className="h-10 rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                />
                <label className="flex gap-3 rounded-2xl border border-slate-200 bg-white p-3 text-sm text-slate-700">
                  <input
                    type="checkbox"
                    checked={rulesAccepted}
                    onChange={(event) => setRulesAccepted(event.target.checked)}
                    className="mt-1"
                  />
                  <span>I confirm written permission exists and testing will remain within authorised scope.</span>
                </label>
                <Button onClick={addWebsiteTarget}>Add Target to Scope</Button>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold">Authorisation Gate</h2>
              {assets.length === 0 ? (
                <EmptyState title="No targets added" message="Add a target first. The authorisation gate will appear here." />
              ) : (
                <div className="mt-4 space-y-3">
                  <select
                    value={selectedAssetId}
                    onChange={(event) => setSelectedAssetId(event.target.value)}
                    className="h-10 w-full rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  >
                    {assets.map((asset) => (
                      <option key={asset.id} value={asset.id}>{asset.name} — {asset.target} — {asset.auth}</option>
                    ))}
                  </select>
                  <Button onClick={approveSelectedTarget} variant="warning">Authorise Selected Target</Button>
                  <div className="space-y-3">
                    {assets.map((asset) => (
                      <div key={asset.id} className="rounded-2xl border border-slate-200 bg-white p-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div>
                            <p className="text-sm font-semibold">{asset.name}</p>
                            <p className="mt-1 text-xs text-slate-500">{asset.target}</p>
                            <p className="mt-1 text-xs text-slate-400">Owner: {asset.owner}</p>
                            <p className="mt-1 text-xs text-slate-400">Last assessment: {asset.lastScan}</p>
                          </div>
                          <Pill className={asset.auth === "Approved" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700"}>{asset.auth}</Pill>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <Pill className="border-slate-200 bg-slate-50 text-slate-700">{asset.scope}</Pill>
                          <Pill className="border-slate-200 bg-slate-50 text-slate-700">{asset.exposure}</Pill>
                          <Pill className={getRiskClass(asset.risk)}>Risk: {asset.risk}</Pill>
                          <Pill className="border-slate-200 bg-slate-50 text-slate-700">Runs: {asset.scanCount}</Pill>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          </section>

          <section ref={scannerRef} className="mt-6 grid gap-6 xl:grid-cols-3">
            <Card className="p-6 xl:col-span-2">
              <h2 className="text-xl font-semibold">Scanner</h2>
              <p className="mt-1 text-sm text-slate-500">Configure authorised assessment level and framework coverage before initiating.</p>
              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <div>
                  <label className="text-sm font-medium text-slate-700">Testing Level</label>
                  <select
                    value={selectedTestingLevel}
                    onChange={(event) => setSelectedTestingLevel(event.target.value)}
                    className="mt-2 h-10 w-full rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  >
                    {testingLevels.map((level) => (
                      <option key={level.key} value={level.key}>{level.title}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-700">Target</label>
                  <select
                    value={selectedAssetId}
                    onChange={(event) => setSelectedAssetId(event.target.value)}
                    className="mt-2 h-10 w-full rounded-2xl border border-slate-200 bg-white px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  >
                    <option value="">Select authorised target</option>
                    {assets.map((asset) => (
                      <option key={asset.id} value={asset.id}>{asset.name} — {asset.auth}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="mt-5">
                <p className="text-sm font-medium text-slate-700">Active Frameworks</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {frameworks.map((framework) => (
                    <label key={framework.key} className="flex gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={selectedFrameworks.includes(framework.key)}
                        onChange={() => toggleFramework(framework.key)}
                        className="mt-1"
                      />
                      <span>
                        <span className="font-semibold">{framework.name}</span>
                        <br />
                        <span className="text-xs text-slate-500">{framework.category}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
              <Button onClick={runAssessment} variant="success" disabled={scanState === "Running"} className="mt-5">
                Initiate Authorised Assessment
              </Button>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold">Live Console</h2>
              <div className="mt-4 max-h-80 space-y-3 overflow-auto rounded-2xl bg-slate-950 p-4 text-xs text-slate-100">
                {scanLogs.length === 0 ? (
                  <p className="text-slate-400">Console idle. Start an authorised assessment to stream phases.</p>
                ) : (
                  scanLogs.map((log, index) => (
                    <div key={`${log.phase}-${index}`}>
                      <p className="text-emerald-300">[{log.time}] {log.phase}</p>
                      <p className="text-slate-300">{log.message}</p>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </section>

          <section ref={testingRef} className="mt-6 grid gap-6 xl:grid-cols-3">
            {testingLevels.map((level) => (
              <Card key={level.key} className={`p-6 ${selectedTestingLevel === level.key ? "ring-4 ring-blue-500/10" : ""}`}>
                <p className="text-xs font-semibold uppercase tracking-wide text-blue-600">{level.subtitle}</p>
                <h2 className="mt-2 text-lg font-semibold">{level.title}</h2>
                <p className="mt-2 text-sm leading-6 text-slate-600">{level.description}</p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {level.controls.map((control) => (
                    <Pill key={control} className="border-slate-200 bg-slate-50 text-slate-700">{control}</Pill>
                  ))}
                </div>
              </Card>
            ))}
          </section>

          <section ref={findingsRef} className="mt-6 grid gap-6 xl:grid-cols-3">
            <Card className="p-6 xl:col-span-2">
              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-xl font-semibold">Findings</h2>
                  <p className="mt-1 text-sm text-slate-500">CVSS-style scoring, CWE references, framework mapping and remediation guidance.</p>
                </div>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search findings"
                    className="h-10 rounded-2xl border border-slate-200 px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  />
                  <select
                    value={severityFilter}
                    onChange={(event) => setSeverityFilter(event.target.value)}
                    className="h-10 rounded-2xl border border-slate-200 px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  >
                    {["All", "Critical", "High", "Medium", "Low", "Informational"].map((item) => (
                      <option key={item}>{item}</option>
                    ))}
                  </select>
                  <select
                    value={statusFilter}
                    onChange={(event) => setStatusFilter(event.target.value)}
                    className="h-10 rounded-2xl border border-slate-200 px-4 text-sm outline-none focus:ring-4 focus:ring-slate-950/10"
                  >
                    {["All", "Open", "In Review", "Remediated", "Observed"].map((item) => (
                      <option key={item}>{item}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="mt-5 divide-y divide-slate-200 overflow-hidden rounded-2xl border border-slate-200 bg-white">
                {filteredFindings.length === 0 ? (
                  <div className="p-5">
                    <EmptyState
                      title="No findings yet"
                      message="Run an authorised assessment. Results, remediation guidance, evidence notes and framework mapping will appear here."
                    />
                  </div>
                ) : (
                  filteredFindings.map((finding) => (
                    <div key={finding.id} className="p-4">
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                        <div>
                          <p className="text-sm font-semibold text-slate-900">{finding.title}</p>
                          <p className="mt-1 text-xs text-slate-500">{finding.id} · {finding.framework} · {finding.cwe}</p>
                          <p className="mt-2 text-xs leading-5 text-slate-500">{finding.remediation}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Pill className={getSeverityClass(finding.severity)}>{finding.severity} · CVSS {finding.cvss}</Pill>
                          <select
                            value={finding.status}
                            onChange={(event) => updateFindingStatus(finding.id, event.target.value)}
                            className="rounded-2xl border border-slate-200 px-3 py-1 text-xs"
                          >
                            {["Open", "In Review", "Remediated", "Observed"].map((item) => (
                              <option key={item}>{item}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold">DORA / EBA / TIBER-EU Matrix</h2>
              <div className="mt-4 space-y-3">
                {doraMatrix.map((item) => (
                  <div key={item.area} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-sm font-semibold">{item.area}</p>
                    <p className="mt-1 text-xs leading-5 text-slate-500">{item.platformControl}</p>
                  </div>
                ))}
              </div>
            </Card>
          </section>

          <section ref={reportsRef} className="mt-6 grid gap-6 xl:grid-cols-2">
            <Card className="p-6">
              <h2 className="text-xl font-semibold">Reports</h2>
              <p className="mt-1 text-sm text-slate-500">Generate report packs with executive, technical, remediation and regulatory sections.</p>
              <div className="mt-5 grid gap-2 sm:grid-cols-2">
                {reportSections.map((section) => (
                  <div key={section} className="rounded-2xl border border-slate-200 bg-slate-50 p-3 text-sm font-medium text-slate-700">
                    {section}
                  </div>
                ))}
              </div>
              <div className="mt-5 flex flex-wrap gap-3">
                <Button onClick={createReport}>Generate Report</Button>
                <Button onClick={exportReport} variant="info">Export JSON</Button>
                <Button onClick={printPdfPack} variant="secondary">Print / Save PDF</Button>
              </div>
            </Card>

            <Card className="p-6">
              <h2 className="text-xl font-semibold">Report Register</h2>
              <div className="mt-4 space-y-3">
                {reports.length === 0 ? (
                  <EmptyState title="No reports generated" message="Generate a report after adding a target and running an assessment." />
                ) : (
                  reports.map((report) => (
                    <div key={report.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <p className="text-sm font-semibold">{report.title}</p>
                      <p className="mt-1 text-xs text-slate-500">{report.id} · {report.createdAt} · {report.testingLevel}</p>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </section>

          <section ref={auditRef} className="mt-6 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-xl font-semibold">Audit Log</h2>
                <p className="mt-1 text-sm text-slate-500">
                  Every action is timestamped, attributed and retained for audit review. Integrity hash shown as a backend placeholder.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button onClick={configureRules} variant="secondary">Configure Rules</Button>
                <Button onClick={viewRoadmap} variant="info">View Roadmap</Button>
                <Button onClick={clearWorkspace} variant="danger">Clear Workspace</Button>
              </div>
            </div>
            <div className="mt-5 max-h-96 space-y-3 overflow-auto">
              {auditLog.length === 0 ? (
                <EmptyState
                  title="No audit events yet"
                  message="Actions such as adding targets, authorising scope, running assessments, changing findings and generating reports will appear here."
                />
              ) : (
                auditLog.map((item, index) => (
                  <div key={`${item.action}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-sm font-semibold">{item.action}</p>
                    <p className="mt-1 text-xs text-slate-500">{item.actor} · {item.time} · {item.integrity}</p>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="mt-6 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="text-xl font-semibold">Production Build Roadmap</h2>
            <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
              The frontend is now MITC-aligned and operational without sample data. To achieve live vulnerability assessment objectives, connect it to a backend API, scanner workers, secure storage and report generation services.
            </p>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[
                ["Backend API", "Python/FastAPI for assets, scans, findings, reports and users."],
                ["Scanner Workers", "Authorised integrations for ZAP, Nuclei, Nmap and Nikto in controlled jobs."],
                ["Evidence Vault", "Store screenshots, logs, approvals, exports and report versions."],
                ["PDF Engine", "Server-side branded reports with executive and technical sections."],
                ["RBAC & MFA", "Secure multi-user and multi-client access control."],
                ["Client Portal", "Client approvals, findings review and remediation tracking."],
                ["DORA Matrix", "Automated mapping to resilience and ICT-risk obligations."],
                ["Retesting", "Track remediation verification and closure evidence."]
              ].map(([module, desc]) => (
                <div key={module} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <p className="text-sm font-semibold">{module}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-500">{desc}</p>
                </div>
              ))}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}