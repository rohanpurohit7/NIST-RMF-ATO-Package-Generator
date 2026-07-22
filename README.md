# NIST RMF ATO Package Generator

A versioned authorization-package automation toolkit that turns system metadata and control decisions into an RMF-oriented evidence library and release bundle.

## Scope

The generator models the NIST Risk Management Framework lifecycle as staged jobs:

1. **Prepare** — system context, stakeholders, authorization boundary, mission/business context.
2. **Categorize** — FIPS 199-style confidentiality/integrity/availability impact selection and rationale.
3. **Select** — baseline selection, tailoring, overlays, inheritance, organization-defined parameters, and privacy considerations.
4. **Implement** — control implementation statements and evidence expectations.
5. **Assess** — assessment plan, evidence matrix, assessment results, findings, SAR summary, and assessor traceability.
6. **Authorize** — executive risk summary, POA&M, risk acceptance/deviation log, ATO-ready checklist, authorization package index.
7. **Monitor** — continuous monitoring strategy, control frequencies, vulnerability/configuration monitoring, POA&M cadence, and ongoing authorization evidence.
8. **Cross-framework readiness** — NIST SP 800-171 Rev. 3 / 800-171A Rev. 3 readiness and SOC 2 Type 2 readiness support.
9. **Release bundle** — immutable `V1`, `V2`, `V3`, ... authorization package snapshots for each release.

> This project accelerates package preparation and readiness. It does not issue an ATO, replace an Authorizing Official, replace an independent assessor, or guarantee a SOC 2 examination result.

## Current reference model

The project is designed around:

- NIST SP 800-37 Rev. 2 RMF lifecycle.
- NIST SP 800-53 Rev. 5 controls and SP 800-53B baselines/tailoring/overlays.
- NIST SP 800-53A Rev. 5 assessment procedures.
- NIST SP 800-137 information security continuous monitoring.
- NIST SP 800-171 Rev. 3 and SP 800-171A Rev. 3 readiness.
- AICPA SOC 2 Trust Services Criteria readiness concepts for security and optional availability, processing integrity, confidentiality, and privacy scope.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

python -m rmfgen.cli build \
  --config sample_data/system.yaml \
  --output releases
```

The first run creates `releases/V1/`; the next run creates `releases/V2/`, and so on.

## Generated package structure

```text
releases/V1/
├── 00-package-index/
│   ├── authorization-package-index.md
│   ├── release-manifest.json
│   └── ato-ready-checklist.md
├── 01-prepare/
│   ├── system-context.md
│   ├── stakeholder-matrix.md
│   └── authorization-boundary.md
├── 02-categorize/
│   ├── security-categorization.md
│   └── impact-rationale.md
├── 03-select-tailor/
│   ├── control-baseline.md
│   ├── tailoring-decisions.md
│   ├── control-overlays-summary.md
│   └── inheritance-matrix.md
├── 04-implement/
│   ├── system-security-plan.md
│   ├── control-implementation-matrix.csv
│   └── evidence-requirements-overlay.md
├── 05-assess/
│   ├── security-assessment-plan.md
│   ├── assessment-evidence-matrix.csv
│   ├── security-assessment-report.md
│   └── assessment-findings.json
├── 06-authorize/
│   ├── executive-risk-summary.md
│   ├── poam.csv
│   ├── risk-acceptance-log.csv
│   └── authorization-decision-brief.md
├── 07-monitor/
│   ├── continuous-monitoring-strategy.md
│   ├── conmon-calendar.csv
│   └── poam-governance.md
├── 08-cross-framework/
│   ├── nist-800-171-readiness.md
│   ├── nist-800-171-assessment-plan.md
│   └── soc2-type2-readiness.md
└── 09-visuals/
    └── document-library-graph.png
```

## Evidence overlay concept

The evidence overlay summarizes, by control family and control, expected evidence classes such as:

- policy and procedures;
- architecture/configuration artifacts;
- access-control records;
- logs and monitoring outputs;
- scan and remediation evidence;
- tickets/change records;
- test results;
- training/personnel evidence;
- contingency/incident exercise evidence;
- third-party and supply-chain evidence.

It is an implementation aid, not a substitute for authoritative assessment procedures.

## CI/CD stages

The included GitHub Actions workflow runs staged jobs for configuration validation, categorization, control selection/tailoring, implementation package generation, assessment package generation, authorization readiness, continuous monitoring, cross-framework readiness, and release bundle validation.
