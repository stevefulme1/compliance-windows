"""Filters to map CFF findings to regulatory framework controls."""


class FilterModule:
    """Crosswalk mapping filters for HIPAA, PCI-DSS, and other frameworks."""

    def filters(self):
        return {
            "map_controls": self.map_controls,
            "crosswalk_summary": self.crosswalk_summary,
        }

    @staticmethod
    def map_controls(findings, crosswalk, source_framework="CIS"):
        """Annotate CFF findings with regulatory control mappings.

        Args:
            findings: List of CFF finding dicts (must have ruleId).
            crosswalk: Parsed crosswalk profile dict (controls list).
            source_framework: Which rule set to match — "CIS" or "STIG".

        Returns:
            List of findings with an added ``regulatory_controls`` key.
        """
        if not findings or not isinstance(findings, list):
            return []
        if not crosswalk or not isinstance(crosswalk, dict):
            return findings

        controls = crosswalk.get("controls", [])
        rule_key = "cis_rules" if source_framework.upper() == "CIS" else "stig_rules"

        rule_to_controls = {}
        for ctrl in controls:
            for rule_id in ctrl.get(rule_key, []):
                rule_to_controls.setdefault(rule_id, []).append(
                    {
                        "control_id": ctrl["id"],
                        "title": ctrl.get("title", ""),
                        "framework": crosswalk.get("framework", ""),
                    }
                )

        result = []
        for finding in findings:
            if not isinstance(finding, dict):
                result.append(finding)
                continue
            rule_id = finding.get("ruleId", "")
            mapped = rule_to_controls.get(rule_id, [])
            annotated = dict(finding)
            annotated["regulatory_controls"] = mapped
            result.append(annotated)

        return result

    @staticmethod
    def crosswalk_summary(findings, crosswalk, source_framework="CIS"):
        """Produce a per-control compliance summary from annotated findings.

        Args:
            findings: List of CFF finding dicts (must have ruleId, status).
            crosswalk: Parsed crosswalk profile dict (controls list).
            source_framework: Which rule set to match — "CIS" or "STIG".

        Returns:
            List of control summary dicts with pass/fail/gap counts.
        """
        if not crosswalk or not isinstance(crosswalk, dict):
            return []

        controls = crosswalk.get("controls", [])
        rule_key = "cis_rules" if source_framework.upper() == "CIS" else "stig_rules"

        finding_map = {}
        for f in findings or []:
            if isinstance(f, dict):
                finding_map[f.get("ruleId", "")] = f.get("status", "notchecked")

        result = []
        for ctrl in controls:
            is_gap = ctrl.get("gap", False)
            mapped_rules = ctrl.get(rule_key, [])
            statuses = [finding_map.get(r, "notchecked") for r in mapped_rules]

            passed = sum(1 for s in statuses if s == "pass")
            failed = sum(1 for s in statuses if s == "fail")
            total = len(mapped_rules)

            if is_gap:
                status = "gap"
            elif total == 0:
                status = "unmapped"
            elif failed > 0:
                status = "fail"
            elif passed == total:
                status = "pass"
            else:
                status = "partial"

            result.append(
                {
                    "control_id": ctrl["id"],
                    "title": ctrl.get("title", ""),
                    "status": status,
                    "mapped_rules": total,
                    "passed": passed,
                    "failed": failed,
                    "gap": is_gap,
                    "gap_note": ctrl.get("gap_note", ""),
                }
            )

        return result
