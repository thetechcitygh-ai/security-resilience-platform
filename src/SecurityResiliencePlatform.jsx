import React, { useMemo, useState } from "react";

const assets = [
  {
    id: "AST-001",
    name: "Corporate Website",
    target: "www.example-client.com",
    owner: "Client A",
    scope: "Locked",
    auth: "Approved",
    exposure: "Public",
    risk: "Medium",
  },
  {
    id: "AST-002",
    name: "Customer Portal",
    target: "portal.example-client.com",
    owner: "Client A",
    scope: "Locked",
    auth: "Approved",
    exposure: "Authenticated",
    risk: "High",
  },
  {
    id: "AST-003",
    name: "Internal API Gateway",
    target: "api.private.local",
    owner: "Internal IT",
    scope: "Pending",
    auth: "Awaiting Sign-off",
    exposure: "Private",
    risk: "Unknown",
  },
];

const findings = [
  {
    id: "FND-1048",
    title: "Weak TLS configuration observed",
    severity: "High",
    cvss: 8.1,
    asset: "Customer Portal",
    framework: "OWASP A02 / NIST Technical Testing",
    status: "Open",
    owner: "Infrastructure Team",
  },
  {
    id: "FND-1049",
    title: "Security headers incomplete",
    severity: "Medium",
    cvss: 5.8,
    asset: "Corporate Website",
    framework: "OWASP A05 / PTES Vulnerability Analysis",
    status: "In remediation",
    owner: "Web Team",
  },
  {
    id: "FND-1050",
    title: "Exposed software version metadata",
    severity: "Low",
    cvss: 3.7,
    asset: "Corporate Website",
    framework: "CEH Reconnaissance / NIST Review",
    status: "Accepted Risk",
    owner: "Application Team",
  },
  {
    id: "FND-1051",
    title: "Authentication rate limiting not confirmed",
    severity: "Critical",
    cvss: 9.0,
    asset: "Customer Portal",
    framework: "OWASP A07 / PTES Exploitation Control",
    status: "Open",
    owner: "Security Engineering",
  },
];

const frameworks = [
  { name: "OWASP Top 10", coverage: 92 },
  { name: "NIST SP 800-115", coverage: 86 },
  { name: "CEH Methodology", coverage: 81 },
  { name: "PTES", coverage: 88 },
  { name: "DORA", coverage: 74 },
  { name: "EBA ICT Risk", coverage: 69 },
  { name: "TIBER-EU", coverage: 63 },
];

const auditLog = [
  {
    actor: "Security Lead",
    action: "Approved scan scope for Customer Portal",
    time: "28 Apr 2026, 08:05",
  },
  {
    actor: "Platform Scheduler",
    action: "Launched non-invasive scan profile",
    time: "28 Apr 2026, 08:15",
  },
  {
    actor: "Risk Officer",
    action: "Reviewed critical finding FND-1051",
    time: "28 Apr 2026, 09:10",
  },
  {
    actor: "Report Engine",
    action: "Generated executive summary draft",
    time: "28 Apr 2026, 09:34",
  },
];

function severityClass(severity) {
  if (severity === "Critical") return "bg-red-50 text-red-700 border-red-200";
  if (severity === "High") return "bg-orange-50 text-orange-700 border-orange-200";
  if (severity === "Medium") return "bg-amber-50 text-amber-700 border-amber-200";
  if (severity === "Low") return "bg-blue-50 text-blue-700 border-blue-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}

function riskClass(risk) {
  if (risk === "High") return "bg-orange-50 text-orange-700 border-orange-200";
  if (risk === "Medium") return "bg-amber-50 text-amber-700 border-amber-200";
  if (risk === "Low") return "bg-blue-50 text-blue-700 border-blue-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}

function Card({ children, className = "" }) {
  return (
    <div className={`rounded-3xl border border-slate-200 bg-white shadow-sm ${className}`}>
      {children}
    </div>
  );
}

function Pill({ children, className = "" }) {
  return (
    <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-medium ${className}`}>
      {children}
    </span>
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

export default function SecurityResiliencePlatform() {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      const term = query.toLowerCase().trim();

      const matchesSearch =
        !term ||
        finding.title.toLowerCase().includes(term) ||
        finding.asset.toLowerCase().includes(term) ||
        finding.framework.toLowerCase().includes(term) ||
        finding.id.toLowerCase().includes(term);

      const matchesSeverity =
        severityFilter === "All" || finding.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [query, severityFilter]);

  const approvedAssets = assets.filter((asset) => asset.auth === "Approved").length;
  const openFindings = findings.filter((finding) => finding.status === "Open").length;
  const criticalFindings = findings.filter((finding) => finding.severity === "Critical").length;

  const averageFrameworkCoverage = Math.round(
    frameworks.reduce((total, item) => total + item.coverage, 0) / frameworks.length
  );

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <div className="mx-auto max-w-7xl p-4 md:p-8">
        <header className="rounded-3xl bg-slate-950 p-6 text-white shadow-sm md:p-8">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="flex flex-wrap gap-2">
                <Pill className="border-slate-700 bg-slate-900 text-slate-200">
                  Private Cloud
                </Pill>
                <Pill className="border-emerald-700 bg-emerald-900 text-emerald-100">
                  White-hat Only
                </Pill>
                <Pill className="border-blue-700 bg-blue-900 text-blue-100">
                  Audit-ready
                </Pill>
              </div>

              <h1 className="mt-5 text-3xl font-bold tracking-tight md:text-5xl">
                Security Resilience Platform
              </h1>

              <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300 md:text-base">
                A governed vulnerability assessment platform for authorised websites and client assets,
                covering recon, scan, enumerate, document and report workflows.
              </p>
            </div>

            <div className="flex flex-wrap gap-3">
              <button className="rounded-2xl bg-white px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-slate-100">
                Start Approved Scan
              </button>
              <button className="rounded-2xl border border-slate-600 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-900">
                Export Report
              </button>
            </div>
          </div>
        </header>

        <section className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Authorised Assets"
            value={approvedAssets}
            helper="Out of 3 registered targets"
          />
          <StatCard
            label="Open Findings"
            value={openFindings}
            helper={`${criticalFindings} critical requiring attention`}
          />
          <StatCard
            label="Framework Coverage"
            value={`${averageFrameworkCoverage}%`}
            helper="Average mapped control coverage"
          />
          <StatCard
            label="Reports Drafted"
            value="12"
            helper="Executive and technical packs"
          />
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-3">
          <Card className="p-6 xl:col-span-2">
            <h2 className="text-xl font-semibold">Assessment Pipeline</h2>
            <p className="mt-1 text-sm text-slate-500">
              Controlled flow from authorisation to remediation tracking.
            </p>

            <div className="mt-6 grid gap-3 md:grid-cols-5">
              {[
                "Authorise",
                "Recon",
                "Scan",
                "Validate",
                "Report",
              ].map((stage, index) => (
                <div
                  key={stage}
                  className={`rounded-2xl border p-4 ${
                    index < 3
                      ? "border-emerald-200 bg-emerald-50"
                      : "border-slate-200 bg-white"
                  }`}
                >
                  <p className="text-sm font-semibold">{stage}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    {index < 3 ? "Completed" : "Awaiting gate"}
                  </p>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-6">
            <h2 className="text-xl font-semibold">Compliance Posture</h2>
            <p className="mt-1 text-sm text-slate-500">
              Framework mapping status.
            </p>

            <div className="mt-5 space-y-4">
              {frameworks.slice(0, 4).map((item) => (
                <div key={item.name}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="font-medium text-slate-700">{item.name}</span>
                    <span className="text-slate-500">{item.coverage}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100">
                    <div
                      className="h-2 rounded-full bg-slate-950"
                      style={{ width: `${item.coverage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-3">
          <Card className="p-6 xl:col-span-2">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 className="text-xl font-semibold">Findings Register</h2>
                <p className="mt-1 text-sm text-slate-500">
                  CVSS-style risk scoring, remediation ownership and evidence tracking.
                </p>
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
                  {["All", "Critical", "High", "Medium", "Low"].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="mt-5 overflow-hidden rounded-2xl border border-slate-200">
              <div className="hidden grid-cols-12 bg-slate-100 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate-500 md:grid">
                <div className="col-span-4">Finding</div>
                <div className="col-span-2">Asset</div>
                <div className="col-span-2">Severity</div>
                <div className="col-span-2">Status</div>
                <div className="col-span-2">Owner</div>
              </div>

              <div className="divide-y divide-slate-200 bg-white">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="grid gap-3 p-4 md:grid-cols-12 md:items-center"
                  >
                    <div className="md:col-span-4">
                      <p className="text-sm font-semibold text-slate-900">
                        {finding.title}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {finding.id} · {finding.framework}
                      </p>
                    </div>

                    <div className="text-sm text-slate-600 md:col-span-2">
                      {finding.asset}
                    </div>

                    <div className="md:col-span-2">
                      <Pill className={severityClass(finding.severity)}>
                        {finding.severity} · CVSS {finding.cvss}
                      </Pill>
                    </div>

                    <div className="text-sm text-slate-600 md:col-span-2">
                      {finding.status}
                    </div>

                    <div className="text-sm text-slate-600 md:col-span-2">
                      {finding.owner}
                    </div>
                  </div>
                ))}

                {filteredFindings.length === 0 && (
                  <div className="p-6 text-sm text-slate-500">
                    No findings match your selected filters.
                  </div>
                )}
              </div>
            </div>
          </Card>

          <Card className="p-6">
            <h2 className="text-xl font-semibold">Report Generator</h2>
            <p className="mt-1 text-sm text-slate-500">
              Professional packs for different audiences.
            </p>

            <div className="mt-5 space-y-3">
              {[
                "Executive Summary",
                "Technical Report",
                "Remediation Roadmap",
                "Compliance Annex",
              ].map((report) => (
                <div
                  key={report}
                  className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
                >
                  <p className="text-sm font-semibold">{report}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Prepared for audit, remediation and management review.
                  </p>
                </div>
              ))}
            </div>

            <button className="mt-5 w-full rounded-2xl bg-slate-950 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-800">
              Generate PDF Pack
            </button>
          </Card>
        </section>

        <section className="mt-6 grid gap-6 xl:grid-cols-2">
          <Card className="p-6">
            <h2 className="text-xl font-semibold">Scope Manager</h2>
            <p className="mt-1 text-sm text-slate-500">
              Targets cannot be tested without documented authority.
            </p>

            <div className="mt-5 space-y-3">
              {assets.map((asset) => (
                <div
                  key={asset.id}
                  className="rounded-2xl border border-slate-200 bg-white p-4"
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-sm font-semibold">{asset.name}</p>
                      <p className="mt-1 text-xs text-slate-500">{asset.target}</p>
                    </div>

                    <Pill
                      className={
                        asset.auth === "Approved"
                          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                          : "border-amber-200 bg-amber-50 text-amber-700"
                      }
                    >
                      {asset.auth}
                    </Pill>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <Pill className="border-slate-200 bg-slate-50 text-slate-700">
                      {asset.scope}
                    </Pill>
                    <Pill className="border-slate-200 bg-slate-50 text-slate-700">
                      {asset.exposure}
                    </Pill>
                    <Pill className={riskClass(asset.risk)}>
                      Risk: {asset.risk}
                    </Pill>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-6">
            <h2 className="text-xl font-semibold">Immutable Audit Log</h2>
            <p className="mt-1 text-sm text-slate-500">
              Every material action is recorded for accountability.
            </p>

            <div className="mt-5 space-y-4">
              {auditLog.map((item, index) => (
                <div
                  key={`${item.action}-${index}`}
                  className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
                >
                  <p className="text-sm font-semibold">{item.action}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    {item.actor} · {item.time}
                  </p>
                </div>
              ))}
            </div>
          </Card>
        </section>

        <section className="mt-6 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Recommended Platform Modules</h2>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
            This prototype can be expanded into production modules for role-based access,
            target authorisation, scanner orchestration, evidence storage, report generation,
            remediation tracking and board-level cyber risk dashboards.
          </p>

          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              "RBAC & MFA",
              "Evidence Vault",
              "Risk Analytics",
              "Kill Switch",
            ].map((module) => (
              <div
                key={module}
                className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
              >
                <p className="text-sm font-semibold">{module}</p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  Production-ready control module for secure platform operations.
                </p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}