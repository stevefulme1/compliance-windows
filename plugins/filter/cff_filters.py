"""Filters to transform compliance results to Common Findings Format (CFF)."""

import json

_STATUS_MAP = {
    "PASS": "pass",
    "FAIL": "fail",
    "MANUAL": "notchecked",
    "ERROR": "error",
    "NOT_APPLICABLE": "notapplicable",
}

_SEVERITY_MAP = {
    "CAT I": "CAT_I",
    "CAT II": "CAT_II",
    "CAT III": "CAT_III",
}

_EMPTY_FINDING = {
    "ruleId": "",
    "title": "",
    "description": "",
    "status": "error",
    "severity": "",
    "category": "",
    "section": "",
    "actualValue": "",
    "expectedValue": "",
    "checkType": "automated",
}


def _safe_str(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


class FilterModule:
    """CFF transformation filters for compliance normalization."""

    def filters(self):
        return {
            "to_cff_stig": self.to_cff_stig,
            "to_cff_cis": self.to_cff_cis,
            "to_cff_powerstig": self.to_cff_powerstig,
        }

    @staticmethod
    def to_cff_stig(result):
        """Transform a single STIG result dict to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        raw_status = result.get("status", "MANUAL")
        return {
            "ruleId": result.get("stig_id", ""),
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": _SEVERITY_MAP.get(
                result.get("severity", ""), result.get("severity", "")
            ),
            "category": result.get("category", ""),
            "section": result.get("section", ""),
            "actualValue": _safe_str(result.get("current_value", "")),
            "expectedValue": _safe_str(
                result.get("expected_value", result.get("value", ""))
            ),
            "checkType": result.get("check_type", "automated"),
        }

    @staticmethod
    def to_cff_cis(result):
        """Transform a single CIS result dict to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        raw_status = result.get("status", "MANUAL")
        return {
            "ruleId": result.get("cis_id", result.get("rule_id", "")),
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": result.get("level", result.get("profile", "")),
            "category": result.get("category", result.get("section", "")),
            "section": result.get("section", ""),
            "actualValue": _safe_str(result.get("current_value", "")),
            "expectedValue": _safe_str(
                result.get("expected_value", result.get("value", ""))
            ),
            "checkType": result.get("check_type", "automated"),
        }

    @staticmethod
    def to_cff_powerstig(result):
        """Transform a PowerSTIG DSC result to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        powerstig_status = {
            "True": "pass",
            "False": "fail",
            True: "pass",
            False: "fail",
        }
        in_desired = result.get(
            "InDesiredState", result.get("inDesiredState", "")
        )
        return {
            "ruleId": result.get("RuleId", result.get("ruleId", "")),
            "title": result.get("ResourceId", result.get("resourceId", "")),
            "description": result.get("ModuleName", ""),
            "status": powerstig_status.get(in_desired, "notchecked"),
            "severity": result.get("Severity", result.get("severity", "")),
            "category": "PowerSTIG",
            "section": result.get(
                "DscResource", result.get("dscResource", "")
            ),
            "actualValue": _safe_str(result.get("ActualValue", "")),
            "expectedValue": _safe_str(result.get("ExpectedValue", "")),
            "checkType": "automated",
            "scanner": "powerstig",
        }
