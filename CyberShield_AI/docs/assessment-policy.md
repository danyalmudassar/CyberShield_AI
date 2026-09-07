# Technical assessment policy

CyberShield's twelve legacy assessment groups organize automated technical signals. Their IDs are project IDs. They are not verified PISF section numbers. Existing ISO, NIST, CIS and OWASP cross-references are provisional project mappings; edition and control-level validation remain outstanding. A scan is not a PISF audit, compliance determination, or certification.

## Source review (2026-09-07)

The official [PKCERT GRC policies listing](https://pkcert.gov.pk/grc-policies.asp) labels its revised framework PISF 2026 and lists thirteen policy groups, including governance, asset/risk management, training, communication protection, identity/access, data/privacy, incident response, physical security, hosting, SSDLC, supply chain, audit and CII protection. This differs from the twelve legacy groups in this project. Direct page retrieval timed out; the official page's indexed content was available during this review.

The official [PISF introduction published under 2025/11](https://pkcert.gov.pk/uploads/2025/11/PISF-Introduction.pdf) identifies PISF 2025 and thirteen policy documents. The different labels mean edition applicability must be checked against the complete applicable publication before any formal mapping claim.

The official [Essential Governance Controls document](https://pkcert.gov.pk/uploads/2025/11/Essential-Governance-Controls.pdf) requires documented, approved policies and management commitment. Remote vulnerability results cannot supply that organizational evidence. No official section equivalence or prescribed remediation deadlines were established in this bounded review.

## Assessment rules

- Governance (project group 1) always remains `NOT_ASSESSABLE` for scanner-only inputs. Approved policies, assigned responsibilities, risk acceptance and management oversight require manual review. Technical findings remain separate inputs to that review.
- Component/development checks (project group 8) fail when live, confirmed vulnerability evidence exists, regardless of whether other lookups failed. Candidate matches do not become findings or clean results. Candidates, missing technology evidence, and empty lookups produce `NOT_ASSESSABLE`.
- The current CVE result contract cannot prove a completed negative assessment: `status=success` and an empty list can occur without sufficient coverage. Therefore group 8 has no automatic PASS path until source completion, applicable version coverage, exclusions and errors can be represented reliably.
- Product/version substrings do not establish end-of-support or vulnerability. The previous nginx substring and other banner heuristics were removed. Future support checks require a complete parsed version and attributable vendor lifecycle/advisory evidence, including vendor backports where relevant. This policy asserts no current supported-version list.
- Existing technical PASS/PARTIAL/FAIL results in other groups describe their stated scanner checks only; they do not validate the organizational domain. HR, physical security and audit still require manual evidence. Remaining heuristics (including access, third-party, incident and continuity proxies) need further evidence-level review before formal framework mapping.

## Score and coverage

The legacy `compliance_score` API field is retained for compatibility. It represents a technical score over assessable project groups: PASS=100, PARTIAL=50, FAIL=0, with NOT_ASSESSABLE excluded. No assessable groups yields zero, meaning no assessed coverage, not demonstrated failure or compliance. Always display assessable count and total group count beside the score. A high score with limited coverage does not establish security or organizational compliance.

Changes in these conservative rules can reduce assessable coverage and change historical scores. Compare results only with compatible policy versions, scope and evidence availability. Report/UI naming and persisted policy-version metadata require follow-up integration; this document does not claim those surfaces have all been migrated.
