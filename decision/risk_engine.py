from typing import List, Dict, Optional

RULE_WEIGHTS = {
    "ssh": 30,
    "file": 50,
    "privilege": 40
}

ML_WEIGHT = 40  #Maximum contribution from ML anomaly score (0–1 scaled)

def calculate_rule_score(events: List[Dict]) -> int:
    """
    Calculates deterministic rule-based score
    based on detector outputs.
    """
    score = 0

    for event in events:
        event_type = event.get("type")

        if event_type in RULE_WEIGHTS:
            score += RULE_WEIGHTS[event_type]

    return score


def calculate_ml_score(ml_probability: Optional[float]) -> int:
    """
    Converts ML anomaly probability (0–1)
    into weighted score contribution.
    """
    if ml_probability is None:
        return 0

    if not 0 <= ml_probability <= 1:
        return 0

    return int(ml_probability * ML_WEIGHT)


def determine_severity(final_score: int) -> str:
    """
    Maps final risk score to severity level.
    """
    if final_score >= 70:
        return "HIGH"
    elif final_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def recommended_action(severity: str) -> str:
    """
    Suggests automated response.
    """
    if severity == "HIGH":
        return "AUTO_RESPOND"
    elif severity == "MEDIUM":
        return "ALERT_ONLY"
    else:
        return "LOG_ONLY"


def evaluate(events: List[Dict], ml_probability: Optional[float] = None) -> Dict:
    """
    Main evaluation pipeline.

    Inputs:
        events → detector outputs
        ml_probability → anomaly score from ML engine (0–1)

    Returns:
        {
            "final_score": int,
            "severity": str,
            "action": str,
            "rule_score": int,
            "ml_score": int
        }
    """

    rule_score = calculate_rule_score(events)
    ml_score = calculate_ml_score(ml_probability)

    final_score = rule_score + ml_score
    severity = determine_severity(final_score)
    action = recommended_action(severity)

    return {
        "final_score": final_score,
        "severity": severity,
        "action": action,
        "rule_score": rule_score,
        "ml_score": ml_score
    }

