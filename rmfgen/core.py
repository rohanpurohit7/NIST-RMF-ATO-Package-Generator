from __future__ import annotations

import csv
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import networkx as nx
import yaml

RMF_STAGES = [
    "01-prepare", "02-categorize", "03-select-tailor", "04-implement",
    "05-assess", "06-authorize", "07-monitor", "08-cross-framework", "09-visuals",
]

FAMILY_EVIDENCE = {
    "AC": ["access policy", "account inventory", "role matrix", "access reviews", "authentication logs"],
    "AU": ["logging policy", "log source inventory", "SIEM queries", "retention settings", "alert evidence"],
    "AT": ["training policy", "completion records", "role-based training evidence"],
    "CA": ["assessment plan", "assessment procedures", "SAR", "POA&M", "continuous monitoring evidence"],
    "CM": ["configuration baseline", "change tickets", "approved builds", "SCAP/XCCDF results", "drift reports"],
    "CP": ["contingency plan", "backup evidence", "restore tests", "exercise results"],
    "IA": ["identity architecture", "MFA evidence", "credential policy", "authentication configuration"],
    "IR": ["incident response plan", "exercise results", "incident tickets", "lessons learned"],
    "MA": ["maintenance procedures", "maintenance logs", "remote maintenance approvals"],
    "MP": ["media policy", "sanitization records", "media inventories"],
    "PE": ["facility access records", "visitor logs", "physical diagrams"],
    "PL": ["system security plan", "rules of behavior", "architecture diagrams"],
    "PM": ["program policies", "risk strategy", "governance minutes"],
    "PS": ["screening evidence", "termination records", "transfer checklists"],
    "PT": ["privacy plans", "PIA", "data processing records"],
    "RA": ["risk assessment", "vulnerability scans", "threat model", "risk register"],
    "SA": ["SDLC policy", "secure development evidence", "SAST/DAST results", "supplier evidence"],
    "SC": ["network diagrams", "encryption settings", "boundary protections", "TLS evidence"],
    "SI": ["patch records", "malware protection", "vulnerability remediation", "integrity monitoring"],
    "SR": ["supply chain plan", "supplier assessments", "SBOM", "contract clauses"],
}

DEFAULT_CONTROLS = [
    "AC-2", "AC-3", "AC-6", "AU-2", "AU-6", "CA-2", "CA-5", "CA-7", "CM-2", "CM-6",
    "CP-9", "IA-2", "IR-4", "PL-2", "RA-3", "RA-5", "SA-11", "SC-7", "SC-13", "SI-2", "SI-4",
]

@dataclass
class ReleaseContext:
    version: str
    root: Path
    config: dict[str, Any]


def load_config(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    required = ["system_name", "system_id", "authorization_boundary", "impact"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise ValueError(f"Missing required configuration fields: {', '.join(missing)}")
    return data


def next_release(output_root: str | Path) -> str:
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    nums = []
    for p in root.glob("V*"):
        if p.is_dir() and p.name[1:].isdigit():
            nums.append(int(p.name[1:]))
    return f"V{max(nums, default=0) + 1}"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def categorize(config: dict[str, Any]) -> str:
    imp = config.get("impact", {})
    levels = {str(imp.get(k, "Low")).title() for k in ("confidentiality", "integrity", "availability")}
    if "High" in levels:
        return "High"
    if "Moderate" in levels:
        return "Moderate"
    return "Low"


def selected_controls(config: dict[str, Any]) -> list[str]:
    controls = list(dict.fromkeys(config.get("controls", DEFAULT_CONTROLS)))
    return sorted(controls)


def build_release(config_path: str | Path, output_root: str | Path) -> ReleaseContext:
    config = load_config(config_path)
    version = next_release(output_root)
    root = Path(output_root) / version
    for stage in ["00-package-index", *RMF_STAGES]:
        (root / stage).mkdir(parents=True, exist_ok=True)

    impact = categorize(config)
    controls = selected_controls(config)
    overlays = config.get("overlays", ["Cloud", "Zero Trust", "Privacy", "Continuous Monitoring"])

    write(root / "01-prepare/system-context.md", f"""
# System Context

- System: {config['system_name']} ({config['system_id']})
- Mission/Business Purpose: {config.get('mission', 'TBD')}
- Authorization Boundary: {config['authorization_boundary']}
- Hosting: {config.get('hosting', 'TBD')}
- Data Types: {', '.join(config.get('data_types', ['TBD']))}
- System Owner: {config.get('system_owner', 'TBD')}
- ISSO/ISSM: {config.get('isso', 'TBD')}
- Authorizing Official: {config.get('authorizing_official', 'TBD')}
""")
    write(root / "01-prepare/stakeholder-matrix.md", "# Stakeholder Matrix\n\n| Role | Responsibility |\n|---|---|\n| System Owner | Mission ownership and resources |\n| ISSO/ISSM | RMF coordination and evidence |\n| Control Owners | Control implementation and evidence |\n| Assessor | Independent assessment activities |\n| AO | Risk-based authorization decision |")
    write(root / "01-prepare/authorization-boundary.md", f"# Authorization Boundary\n\n{config['authorization_boundary']}\n")

    imp = config["impact"]
    write(root / "02-categorize/security-categorization.md", f"""
# Security Categorization

- Confidentiality: {imp.get('confidentiality', 'Low')}
- Integrity: {imp.get('integrity', 'Low')}
- Availability: {imp.get('availability', 'Low')}
- Overall impact baseline driver: **{impact}**
""")
    write(root / "02-categorize/impact-rationale.md", "# Impact Rationale\n\nDocument mission, legal, financial, operational, privacy, and safety consequences supporting each impact value.\n")

    write(root / "03-select-tailor/control-baseline.md", "# Control Baseline\n\n" + "\n".join(f"- {c}" for c in controls))
    write(root / "03-select-tailor/tailoring-decisions.md", "# Tailoring Decisions\n\nRecord scoping decisions, applicability, compensating controls, parameter values, inherited controls, and rationale.\n")
    write(root / "03-select-tailor/control-overlays-summary.md", "# Control Overlays Summary\n\n" + "\n".join(f"- {x}: summarize added/modified evidence expectations and implementation context." for x in overlays))
    write(root / "03-select-tailor/inheritance-matrix.md", "# Inheritance Matrix\n\n| Control | Provider | Consumer Responsibility | Evidence |\n|---|---|---|---|\n")

    write(root / "04-implement/system-security-plan.md", f"# System Security Plan\n\nSystem: {config['system_name']}\n\nThis generated SSP scaffold should be completed with system-specific control implementation statements, responsible roles, inherited control details, architecture references, and evidence links.\n")
    impl_rows = []
    evidence_rows = []
    for c in controls:
        fam = c.split("-")[0]
        evidence = FAMILY_EVIDENCE.get(fam, ["implementation statement", "test evidence"])
        impl_rows.append({"control": c, "status": "Planned", "implementation_statement": "TBD", "owner": "TBD", "inheritance": "TBD"})
        evidence_rows.append({"control": c, "family": fam, "expected_evidence": "; ".join(evidence), "assessment_methods": "Examine; Interview; Test"})
    write_csv(root / "04-implement/control-implementation-matrix.csv", impl_rows, list(impl_rows[0]))
    write(root / "04-implement/evidence-requirements-overlay.md", "# Evidence Requirements Overlay\n\n" + "\n".join(f"## {fam}\n- " + "\n- ".join(items) for fam, items in FAMILY_EVIDENCE.items()))
    write_csv(root / "04-implement/scap-control-evidence-mapping.csv", evidence_rows, list(evidence_rows[0]))

    write(root / "05-assess/security-assessment-plan.md", "# Security Assessment Plan\n\nDefine scope, objectives, assessor independence, sampling, assessment methods, test procedures, evidence requests, schedule, and rules of engagement.\n")
    write_csv(root / "05-assess/assessment-evidence-matrix.csv", evidence_rows, list(evidence_rows[0]))
    write(root / "05-assess/security-assessment-report.md", "# Security Assessment Report\n\n## Executive Summary\nTBD\n\n## Findings\nTBD\n\n## Residual Risk\nTBD\n")
    (root / "05-assess/assessment-findings.json").write_text("[]\n", encoding="utf-8")

    poam = [{"poam_id": "POAM-001", "control": "TBD", "weakness": "TBD", "risk": "TBD", "owner": "TBD", "milestone": "TBD", "due_date": "TBD", "status": "Open", "evidence": "TBD"}]
    write_csv(root / "06-authorize/poam.csv", poam, list(poam[0]))
    write_csv(root / "06-authorize/risk-acceptance-log.csv", [{"risk_id": "RISK-001", "description": "TBD", "decision": "TBD", "approver": "TBD", "expiration": "TBD"}], ["risk_id", "description", "decision", "approver", "expiration"])
    write(root / "06-authorize/executive-risk-summary.md", "# Executive Risk Summary\n\nSummarize system mission, categorization, control implementation state, assessment results, open POA&Ms, residual risk, dependencies, and recommended authorization decision.\n")
    write(root / "06-authorize/authorization-decision-brief.md", "# Authorization Decision Brief\n\n- Recommended decision: TBD\n- Authorization period: TBD\n- Conditions: TBD\n- Residual risks requiring AO awareness: TBD\n")

    write(root / "07-monitor/continuous-monitoring-strategy.md", "# Continuous Monitoring Strategy\n\nDefine control monitoring frequencies, vulnerability/configuration scanning, log review, change monitoring, POA&M updates, annual/ongoing assessment activities, metrics, and reporting cadence.\n")
    conmon = [
        {"activity": "Vulnerability scanning", "frequency": "Monthly or risk-driven", "owner": "Security Operations", "artifact": "scan results / POA&M updates"},
        {"activity": "SCAP configuration assessment", "frequency": "Monthly/Quarterly", "owner": "Platform Security", "artifact": "XCCDF/ARF/HTML report"},
        {"activity": "POA&M review", "frequency": "Monthly", "owner": "ISSO", "artifact": "POA&M status report"},
        {"activity": "Control reassessment", "frequency": "Per ISCM strategy", "owner": "Assessor/Control Owner", "artifact": "assessment evidence"},
    ]
    write_csv(root / "07-monitor/conmon-calendar.csv", conmon, list(conmon[0]))
    write(root / "07-monitor/poam-governance.md", "# POA&M Governance\n\nTrack weakness source, control mapping, severity/risk, owner, milestones, resources, scheduled completion, deviations, evidence, validation, aging, and closure approval. Escalate overdue/high-risk items through governance.\n")

    write(root / "08-cross-framework/nist-800-171-readiness.md", "# NIST SP 800-171 Rev. 3 Readiness\n\nMap CUI scope, system boundary, 800-171 requirements, inherited controls, implementation statements, evidence, assessment objectives, deficiencies, and remediation actions. Use SP 800-171A Rev. 3 assessment procedures for readiness and assessment planning.\n")
    write(root / "08-cross-framework/nist-800-171-assessment-plan.md", "# NIST SP 800-171 Assessment Plan\n\nEstablish assessment scope, CUI assets, external service providers, requirement/objective mapping, evidence requests, sampling, assessor procedures, findings, and corrective-action tracking.\n")
    write(root / "08-cross-framework/soc2-type2-readiness.md", "# SOC 2 Type 2 Readiness Support\n\nDefine system description and boundaries; map controls to applicable Trust Services Criteria; establish control owners; preserve evidence over the examination period; test design and operating effectiveness; track exceptions; maintain vendor, change, access, incident, backup, logging, vulnerability, and monitoring evidence. Final examination conclusions are issued by an independent CPA firm.\n")

    generate_document_graph(root)
    generate_scap_artifacts(root, config)
    generate_checklist(root)
    manifest = {"version": version, "system": config["system_name"], "impact": impact, "controls": controls, "overlays": overlays, "scap_target": "SCAP 1.4-aware / OpenSCAP-compatible XCCDF-OVAL workflow"}
    (root / "00-package-index/release-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write(root / "00-package-index/authorization-package-index.md", "# Authorization Package Index\n\n" + "\n".join(f"- {p.relative_to(root)}" for p in sorted(root.rglob("*")) if p.is_file()))
    return ReleaseContext(version, root, config)


def generate_checklist(root: Path) -> None:
    write(root / "00-package-index/ato-ready-checklist.md", """
# ATO-Ready Checklist

- [ ] Authorization boundary approved and current
- [ ] Security categorization documented and approved
- [ ] Baseline selected and tailoring/overlays documented
- [ ] SSP implementation statements complete and evidence-linked
- [ ] Inherited controls and provider evidence identified
- [ ] SAP approved and assessment executed
- [ ] SAR findings dispositioned
- [ ] POA&M complete with owners, milestones, due dates, and validation evidence
- [ ] Risk acceptances/deviations time-bounded and approved
- [ ] Vulnerability and SCAP configuration results reviewed
- [ ] Continuous monitoring strategy and cadence approved
- [ ] Contingency/incident exercises current
- [ ] Privacy/supply-chain requirements addressed where applicable
- [ ] Executive risk summary prepared for AO
- [ ] Package manifest/version frozen for authorization decision
""")


def generate_document_graph(root: Path) -> None:
    graph = nx.DiGraph()
    edges = [
        ("System Context", "Categorization"), ("Categorization", "Baseline & Tailoring"),
        ("Baseline & Tailoring", "SSP & Evidence"), ("SSP & Evidence", "Assessment Plan"),
        ("Assessment Plan", "SAR & Findings"), ("SAR & Findings", "POA&M"),
        ("POA&M", "Executive Risk Summary"), ("Executive Risk Summary", "Authorization Decision"),
        ("Authorization Decision", "Continuous Monitoring"), ("Continuous Monitoring", "Next Release"),
        ("SCAP / OpenSCAP", "Assessment Evidence"), ("Assessment Evidence", "SAR & Findings"),
        ("800-171 Readiness", "Assessment Evidence"), ("SOC 2 Readiness", "Assessment Evidence"),
    ]
    graph.add_edges_from(edges)
    plt.figure(figsize=(16, 10))
    pos = nx.spring_layout(graph, seed=7, k=1.2)
    nx.draw_networkx(graph, pos=pos, with_labels=True, node_size=3000, font_size=8, arrows=True)
    plt.axis("off")
    plt.tight_layout()
    out = root / "09-visuals/document-library-graph.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out, dpi=180, bbox_inches="tight")
    plt.close()


def generate_scap_artifacts(root: Path, config: dict[str, Any]) -> None:
    scap = root / "05-assess/scap"
    scap.mkdir(parents=True, exist_ok=True)
    manifest = {
        "target_standard": "SCAP 1.4",
        "execution_engine": "OpenSCAP oscap",
        "content_path": config.get("scap", {}).get("content_path", "external/content-datastream.xml"),
        "profile": config.get("scap", {}).get("profile", "TBD"),
        "outputs": ["ARF results", "XCCDF results", "HTML report", "OVAL results when applicable"],
        "note": "Use OpenSCAP for supported SCAP/XCCDF/OVAL evaluation; preserve source content version, profile, command, target, timestamp, and hashes as assessment evidence.",
    }
    (scap / "scap-integration-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write(scap / "openscap-runbook.md", """
# OpenSCAP Assessment Runbook

1. Install `oscap` and approved SCAP content.
2. Record `oscap --version` and source content provenance.
3. Inspect content with `oscap info <datastream>`.
4. Validate content where supported using `oscap ds sds-validate <datastream>`.
5. Execute the approved profile:
   `oscap xccdf eval --profile <profile> --results-arf arf-results.xml --report report.html <datastream>`
6. Preserve ARF/XCCDF/OVAL outputs, HTML report, command line, content hash, scanner version, target identifier, and timestamp.
7. Map failed/notchecked/error rules to RMF controls and POA&M items.
8. Re-scan after remediation and retain closure evidence.
""")
    write_csv(scap / "scap-results-to-poam-mapping.csv", [{"scap_rule_id": "TBD", "result": "TBD", "xccdf_profile": "TBD", "rmf_control": "TBD", "poam_id": "TBD", "evidence": "TBD"}], ["scap_rule_id", "result", "xccdf_profile", "rmf_control", "poam_id", "evidence"])


def run_openscap(content: str, profile: str, output_dir: str | Path) -> dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if not shutil.which("oscap"):
        return {"status": "skipped", "reason": "oscap executable not installed"}
    content_path = Path(content)
    if not content_path.exists():
        return {"status": "skipped", "reason": f"SCAP content not found: {content}"}
    info = subprocess.run(["oscap", "info", str(content_path)], text=True, capture_output=True)
    (out / "oscap-info.txt").write_text(info.stdout + info.stderr, encoding="utf-8")
    cmd = ["oscap", "xccdf", "eval", "--profile", profile, "--results-arf", str(out / "arf-results.xml"), "--report", str(out / "report.html"), str(content_path)]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    (out / "oscap-command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
    (out / "oscap-stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (out / "oscap-stderr.txt").write_text(proc.stderr, encoding="utf-8")
    return {"status": "completed" if proc.returncode in (0, 2) else "failed", "returncode": proc.returncode}
