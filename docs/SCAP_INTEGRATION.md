# SCAP and OpenSCAP Integration

## Design objective

The RMF package generator treats automated configuration assessment as evidence that feeds control implementation, assessment, POA&M, authorization, and continuous monitoring artifacts.

## Standards posture

- Target metadata and package documentation are SCAP 1.4-aware.
- OpenSCAP is the default execution engine for supported XCCDF, OVAL, and SCAP source-data-stream workflows.
- Scanner/tool version, content version, profile, target, command line, timestamps, hashes, ARF/XCCDF/OVAL results, and human-readable reports should be preserved as assessment evidence.
- Tool output does not by itself determine control effectiveness; assessor judgment and control-specific evidence remain required.

## Workflow

1. Obtain approved SCAP content and record provenance.
2. Inspect content with `oscap info`.
3. Validate source data stream where supported with `oscap ds sds-validate`.
4. Execute an approved XCCDF profile with OpenSCAP.
5. Generate ARF/XCCDF results and an HTML report.
6. Map failed, error, unknown, and notchecked rules to relevant RMF controls.
7. Create or update POA&M items where deficiencies represent unresolved risk.
8. Link remediation evidence and re-scan results to closure validation.
9. Retain each run under the corresponding authorization release package (`V1`, `V2`, `V3`, ...).
10. Feed recurring SCAP results into the continuous-monitoring calendar and control reassessment cadence.

## Example

```bash
python -m rmfgen.cli scap \
  --content /path/to/content-datastream.xml \
  --profile xccdf_org.example_profile \
  --output releases/V1/05-assess/scap/live-scan
```

The wrapper records OpenSCAP command output and produces ARF/HTML artifacts when the supplied content and profile are supported by the installed OpenSCAP version.
