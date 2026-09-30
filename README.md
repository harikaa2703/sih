# Aegis Network Assurance demo

Aegis is a local-first, read-only prototype for multi-vendor network configuration compliance reviews. It demonstrates a normalized view across vendor configurations, deterministic rule findings, framework-oriented report structure, and a human review gate for suggested parser mappings.

## Run locally

```sh
npm start
```

Open `http://localhost:3000`. The dashboard and sample report work without a database. The existing student API routes remain available and still require MongoDB; if MongoDB is unavailable, the server reports the connection error while keeping the static demo accessible.

## Demo features

- A dashboard seeded with synthetic inventory, control coverage, risk trends, and findings.
- Search and filter controls for findings by severity and framework.
- Finding details with source-line evidence, illustrative framework references, and review-before-applying remediation suggestions.
- A local-only configuration upload flow for small Cisco IOS and FortiOS snapshots. The browser checks a limited set of explicit configuration signatures; it does not upload the file or make a complete compliance determination.
- An AI parser-extension review screen that demonstrates a human-confirmation workflow. The mapping is seeded sample data; no AI service is connected.
- A generated, fixed six-page PDF sample report with scope, severity totals, a NIST SP 800-53 Rev. 5 crosswalk, findings register, source evidence, and remediation guidance. The same synthetic dataset is used on every download; uploaded configurations are not included.

## Sample report structure

1. Executive summary, assessment metadata, severity totals, scope, and method.
2. NIST SP 800-53 Rev. 5 candidate-control crosswalk with finding references.
3. Per-finding severity, affected device, source evidence (or a clearly stated absent directive), impact, and remediation.
4. Framework mapping limitations and assessment disclaimer. CIS control numbers are omitted until edition-specific references are verified; DISA STIG and ISO/IEC 27001 mappings are not asserted in this sample.

All dashboard and downloadable report values are dummy data for product demonstration. NIST SP 800-53 Revision 5 control references are candidate relationships, not compliance determinations. CIS guidance is named without version-specific control IDs; no DISA STIG or ISO/IEC 27001 citations are claimed. The prototype is not an official NTRO assessment, does not connect to live network devices, and does not apply configuration changes.
