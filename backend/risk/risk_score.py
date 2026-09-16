"""
Risk Scoring Engine for Milestone 3 (`backend/risk/risk_score.py`).
Implements the core transparent 0-100 weighted risk calculation, factor normalization,
risk classification, and explainability breakdown.
"""
from typing import Dict, Any, Tuple, List

# Initial Documented Configuration Weights (Sum = 1.0 / 100%)
DEFAULT_RISK_WEIGHTS = {
    "threat_severity": 0.25,
    "ml_confidence": 0.25,
    "asset_criticality": 0.20,
    "vulnerability_exposure": 0.20,
    "threat_intelligence": 0.10
}

# Asset Criticality Normalization Scale
# Critical = 1.00, High = 0.75, Medium = 0.50, Low = 0.25
CRITICALITY_LEVEL_MAP = {
    "critical": 1.00,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25
}

KNOWN_ASSET_CRITICALITY = {
    "database-01": "critical",
    "db-001": "critical",
    "production database": "critical",
    "webserver": "high",
    "srv-002": "high",
    "application server": "high",
    "firewall": "high",
    "finance-pc-02": "medium",
    "hr-pc-01": "medium",
    "lap-101": "medium",
    "employee laptop": "medium",
    "test-001": "low",
    "testing server": "low"
}

SEVERITY_SCORE_MAP = {
    "critical": 95.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0
}

class RiskScoreEngine:
    """Calculates transparent, weighted 0-100 risk scores for SOC incidents and events."""

    @staticmethod
    def normalize_asset_criticality(asset_name: str = "", criticality_str: str = "") -> Tuple[float, str, float]:
        """
        Normalizes asset criticality to:
        Critical = 1.00 (100)
        High = 0.75 (75)
        Medium = 0.50 (50)
        Low = 0.25 (25)
        Returns: (normalized_multiplier, level_name, score_0_to_100)
        """
        clean_crit = str(criticality_str).strip().lower() if criticality_str else ""
        clean_asset = str(asset_name).strip().lower() if asset_name else ""

        level = "low"
        if clean_crit in CRITICALITY_LEVEL_MAP:
            level = clean_crit
        elif clean_asset in KNOWN_ASSET_CRITICALITY:
            level = KNOWN_ASSET_CRITICALITY[clean_asset]
        else:
            # Heuristic match for asset naming patterns
            if any(k in clean_asset for k in ["database", "db-", "prod"]):
                level = "critical"
            elif any(k in clean_asset for k in ["server", "srv", "firewall", "gateway"]):
                level = "high"
            elif any(k in clean_asset for k in ["pc", "laptop", "workstation", "finance", "hr"]):
                level = "medium"
            else:
                level = "low"

        multiplier = CRITICALITY_LEVEL_MAP.get(level, 0.25)
        score_100 = multiplier * 100.0
        return multiplier, level.capitalize(), score_100

    @staticmethod
    def normalize_vulnerability_exposure(cvss_score: float = 0.0,
                                         vulnerability_id: str = "",
                                         patch_status: str = "Open") -> Tuple[float, str]:
        """
        Normalizes CVSS (0.0 to 10.0) into a 0-100 vulnerability exposure rating.
        If no CVE or patch status is closed/resolved, returns minimal baseline.
        """
        if not vulnerability_id or vulnerability_id in ["No Vulnerability", "None", "nan", ""]:
            return 0.0, "No Vulnerability"

        status_clean = str(patch_status).strip().lower()
        if status_clean in ["closed", "resolved", "patched"]:
            return 10.0, f"Patched ({vulnerability_id})"

        cvss = float(cvss_score) if cvss_score is not None else 0.0
        # CVSS scales 0.0 - 10.0 -> multiply by 10.0 to normalize to 0 - 100
        score_100 = round(min(100.0, max(0.0, cvss * 10.0)), 1)
        return score_100, f"{vulnerability_id} (CVSS {cvss})"

    @staticmethod
    def normalize_threat_intelligence(threat_match: bool = False,
                                       malicious_ip_flag: int = 0,
                                       threat_indicator: bool = False,
                                       threat_severity: str = "None",
                                       threat_name: str = "") -> Tuple[float, str]:
        """
        Normalizes threat intelligence feeds into a 0-100 indicator score.
        Clearly distinguishes: Known Malicious IOC vs Rule Match vs Clean/No Match.
        """
        is_known_malicious = bool(threat_match) or bool(malicious_ip_flag == 1)
        
        if is_known_malicious:
            sev = str(threat_severity).strip().lower()
            if sev == "critical":
                return 100.0, f"Known Malicious IOC (Critical feed match: {threat_name or 'Active Indicator'})"
            elif sev == "high":
                return 85.0, f"Known Malicious IOC (High feed match: {threat_name or 'Active Indicator'})"
            elif sev == "medium":
                return 70.0, f"Known Malicious IOC (Medium feed match: {threat_name or 'Active Indicator'})"
            else:
                return 80.0, f"Known Malicious IOC ({threat_name or 'Matched Threat Feed'})"
        elif threat_indicator:
            return 60.0, "Suspicious Indicator / Behavioral Rule Flagged"
        else:
            return 0.0, "No Malicious Threat Intel Match"

    @staticmethod
    def normalize_threat_severity(severity_input: Any) -> float:
        """Normalizes threat severity rating (Critical, High, Medium, Low) to 0-100 scale."""
        if isinstance(severity_input, (int, float)):
            return min(100.0, max(0.0, float(severity_input)))

        sev_str = str(severity_input).strip().lower()
        return SEVERITY_SCORE_MAP.get(sev_str, 25.0)

    @staticmethod
    def classify_risk(risk_score: int) -> str:
        """
        Maps 0-100 risk score to standardized Priority classification:
        81–100: Critical
        61–80:  High
        41–60:  Medium
        0–40:   Low
        """
        if risk_score >= 81:
            return "Critical"
        elif risk_score >= 61:
            return "High"
        elif risk_score >= 41:
            return "Medium"
        else:
            return "Low"

    _active_weights: Dict[str, float] = dict(DEFAULT_RISK_WEIGHTS)

    @classmethod
    def validate_weights(cls, weights: Dict[str, float]) -> Tuple[bool, str]:
        """
        Validates that risk weights contain all 5 required factor keys,
        are non-negative, and sum to 1.0 (or 100% within a 0.001 margin).
        """
        if not isinstance(weights, dict):
            return False, "Weights payload must be a JSON object / dictionary."

        required_keys = [
            "threat_severity",
            "ml_confidence",
            "asset_criticality",
            "vulnerability_exposure",
            "threat_intelligence"
        ]
        missing = [k for k in required_keys if k not in weights]
        if missing:
            return False, f"Missing required weight keys: {', '.join(missing)}"

        try:
            total = 0.0
            for k in required_keys:
                val = float(weights[k])
                if val < 0.0 or val > 1.0:
                    return False, f"Weight '{k}' must be between 0.0 and 1.0 (got {val})."
                total += val
        except (ValueError, TypeError) as e:
            return False, f"Weights must contain numeric float values: {str(e)}"

        if abs(total - 1.0) > 0.005:
            return False, f"Weights must sum exactly to 1.00 (100%). Current sum: {total * 100:.1f}% ({total:.3f})."

        return True, "Weights are valid and sum to 1.00."

    @classmethod
    def get_active_weights(cls) -> Dict[str, float]:
        """Returns currently active risk weights."""
        return dict(cls._active_weights)

    @classmethod
    def set_active_weights(cls, weights: Dict[str, float]) -> bool:
        """Sets active risk weights after validation."""
        is_valid, msg = cls.validate_weights(weights)
        if not is_valid:
            raise ValueError(msg)
        cls._active_weights = {
            "threat_severity": round(float(weights["threat_severity"]), 3),
            "ml_confidence": round(float(weights["ml_confidence"]), 3),
            "asset_criticality": round(float(weights["asset_criticality"]), 3),
            "vulnerability_exposure": round(float(weights["vulnerability_exposure"]), 3),
            "threat_intelligence": round(float(weights["threat_intelligence"]), 3)
        }
        return True

    @classmethod
    def reset_active_weights(cls) -> Dict[str, float]:
        """Resets weights to default documented 0.25/0.25/0.20/0.20/0.10 baseline."""
        cls._active_weights = dict(DEFAULT_RISK_WEIGHTS)
        return dict(cls._active_weights)

    @classmethod
    def calculate_risk(cls,
                       threat_severity_input: Any = "Low",
                       ml_confidence: float = 0.0,
                       asset_name: str = "",
                       asset_criticality_str: str = "",
                       cvss_score: float = 0.0,
                       vulnerability_id: str = "",
                       threat_match: bool = False,
                       malicious_ip_flag: int = 0,
                       threat_indicator: bool = False,
                       threat_severity_feed: str = "None",
                       threat_name: str = "",
                       weights: Dict[str, float] = None,
                       related_events_count: int = 1) -> Dict[str, Any]:
        """
        Executes the transparent weighted risk calculation according to the M3 specification.
        Returns:
            {
                "risk_score": 92,
                "priority": "Critical",
                "factors": {...},
                "breakdown": {...},
                "explainability": [...]
            }
        """
        w = weights or cls.get_active_weights()

        # 1. Threat Severity Factor (default 25%)
        sev_score = cls.normalize_threat_severity(threat_severity_input)

        # 2. ML Confidence Factor (default 25%)
        conf_score = min(100.0, max(0.0, float(ml_confidence or 0.0)))

        # 3. Asset Criticality Factor (default 20%)
        _, asset_level, asset_score = cls.normalize_asset_criticality(asset_name, asset_criticality_str)

        # 4. Vulnerability Exposure Factor (default 20%)
        vuln_score, vuln_desc = cls.normalize_vulnerability_exposure(cvss_score, vulnerability_id)

        # 5. Threat Intelligence Factor (default 10%)
        intel_score, intel_desc = cls.normalize_threat_intelligence(
            threat_match=threat_match,
            malicious_ip_flag=malicious_ip_flag,
            threat_indicator=threat_indicator,
            threat_severity=threat_severity_feed,
            threat_name=threat_name
        )

        w_sev = w.get("threat_severity", 0.25)
        w_conf = w.get("ml_confidence", 0.25)
        w_asset = w.get("asset_criticality", 0.20)
        w_vuln = w.get("vulnerability_exposure", 0.20)
        w_intel = w.get("threat_intelligence", 0.10)

        # Weighted calculation
        raw_weighted = (
            (sev_score * w_sev) +
            (conf_score * w_conf) +
            (asset_score * w_asset) +
            (vuln_score * w_vuln) +
            (intel_score * w_intel)
        )

        # Multi-event correlation slight boost (cap to 100)
        correlation_bonus = 0.0
        if related_events_count > 3:
            correlation_bonus = min(5.0, (related_events_count - 3) * 1.0)
            raw_weighted = min(100.0, raw_weighted + correlation_bonus)

        final_risk_score = int(round(min(100.0, max(0.0, raw_weighted))))
        priority = cls.classify_risk(final_risk_score)

        formula_str = (
            f"(Severity * {w_sev:.2f}) + (Confidence * {w_conf:.2f}) + "
            f"(Asset * {w_asset:.2f}) + (Vuln * {w_vuln:.2f}) + (Intel * {w_intel:.2f})"
        )
        if correlation_bonus > 0:
            formula_str += f" + Correlation Bonus (+{correlation_bonus:.1f})"

        # Construct data-backed Explainability Checklist
        explainability = []
        if asset_level in ["Critical", "High"]:
            explainability.append(f"Critical / High-value asset targeted: {asset_name or 'Database/Server'} ({asset_level} criticality)")
        if conf_score >= 70.0:
            explainability.append(f"High AI detection confidence: {conf_score:.1f}%")
        if vuln_score >= 60.0:
            explainability.append(f"Critical vulnerability exposure: {vuln_desc}")
        if intel_score >= 60.0:
            explainability.append(f"Active threat intelligence alert: {intel_desc}")
        if sev_score >= 75.0:
            explainability.append(f"High underlying threat severity rating ({sev_score:.0f}/100)")
        if related_events_count >= 2:
            explainability.append(f"Multiple correlated security events ({related_events_count} events linked in attack window)")

        if not explainability:
            explainability.append("Routine event activity with baseline security parameters")

        return {
            "risk_score": final_risk_score,
            "priority": priority,
            "formula": formula_str,
            "factors": {
                "threat_severity": {
                    "raw": sev_score,
                    "weight": w_sev,
                    "contribution": round(sev_score * w_sev, 2)
                },
                "ml_confidence": {
                    "raw": conf_score,
                    "weight": w_conf,
                    "contribution": round(conf_score * w_conf, 2)
                },
                "asset_criticality": {
                    "raw": asset_score,
                    "level": asset_level,
                    "weight": w_asset,
                    "contribution": round(asset_score * w_asset, 2)
                },
                "vulnerability_exposure": {
                    "raw": vuln_score,
                    "description": vuln_desc,
                    "weight": w_vuln,
                    "contribution": round(vuln_score * w_vuln, 2)
                },
                "threat_intelligence": {
                    "raw": intel_score,
                    "description": intel_desc,
                    "weight": w_intel,
                    "contribution": round(intel_score * w_intel, 2)
                }
            },
            "explainability": explainability
        }

    @classmethod
    def calculate_isolated_event_risk(cls, event_data: Dict[str, Any], weights: Dict[str, float] = None) -> Dict[str, Any]:
        """
        Calculates the isolated, non-correlated baseline risk score for a single security event.
        Strictly sets related_events_count=1 with no multi-stage or correlation bonus.
        """
        sev = event_data.get("threat_severity") or event_data.get("severity") or event_data.get("m2_severity") or "Low"
        conf = float(event_data.get("confidence_score") or 50.0)
        asset = event_data.get("asset_name") or "Unknown"
        crit = event_data.get("criticality") or ""
        cvss = float(event_data.get("cvss_score") or 0.0)
        vuln = event_data.get("vulnerability_id") or ""
        threat_match = bool(event_data.get("threat_match") or False)
        malicious_ip = int(event_data.get("malicious_ip_flag") or 0)
        threat_indicator = bool(event_data.get("threat_indicator") or False)
        threat_sev_feed = str(event_data.get("threat_severity_feed") or event_data.get("threat_severity") or "None")
        threat_name = str(event_data.get("threat_name") or "")

        return cls.calculate_risk(
            threat_severity_input=sev,
            ml_confidence=conf,
            asset_name=asset,
            asset_criticality_str=crit,
            cvss_score=cvss,
            vulnerability_id=vuln,
            threat_match=threat_match,
            malicious_ip_flag=malicious_ip,
            threat_indicator=threat_indicator,
            threat_severity_feed=threat_sev_feed,
            threat_name=threat_name,
            weights=weights,
            related_events_count=1
        )

    @classmethod
    def explain_correlation_delta(cls,
                                  isolated_score: int,
                                  correlated_score: int,
                                  event_count: int,
                                  unique_types: int = 1,
                                  stages_count: int = 1) -> Dict[str, Any]:
        """
        Provides detailed analyst-grade explainability for WHY correlation increased,
        decreased, or retained risk relative to the isolated base event score.
        """
        delta = correlated_score - isolated_score
        reasons = []

        if delta > 0:
            if event_count > 1:
                reasons.append(
                    f"Temporal cluster correlation: {event_count} related security events were linked "
                    f"within the 30-minute sliding window, indicating coordinated activity."
                )
            if stages_count >= 2:
                reasons.append(
                    f"Multi-stage kill chain detected: sequence spans {stages_count} progression stages, "
                    f"signaling attack progression beyond initial reconnaissance."
                )
            if unique_types > 1:
                reasons.append(
                    f"Compound attack vector: involved {unique_types} distinct event types across "
                    f"the same target perimeter."
                )
            if not reasons:
                reasons.append(f"Aggregate risk escalation (+{delta} pts) resulting from correlated threat parameters.")
        elif delta < 0:
            reasons.append("Composite normalization adjusted score downward relative to peak single-event burst.")
        else:
            if event_count == 1:
                reasons.append("Single isolated event with no detected lateral movement or secondary stage activity.")
            else:
                reasons.append("Correlated cluster parameters align with baseline event evaluation.")

        return {
            "isolated_score": isolated_score,
            "correlated_score": correlated_score,
            "delta": delta,
            "delta_label": f"+{delta} pts" if delta > 0 else (f"{delta} pts" if delta < 0 else "0 pts"),
            "is_elevated": delta > 0,
            "reasons": reasons
        }

