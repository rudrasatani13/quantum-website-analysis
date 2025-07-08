# ai/threat_scorer.py

def compute_threat_score(match_conf: float, context_score: float, weight: float, multiplier: float) -> float:
    """
    Computes a weighted threat score.

    Parameters:
    - match_conf: Confidence score from classification (0 to 1)
    - context_score: Contextual weight (like pattern density, entropy, etc.)
    - weight: How much to weigh context_score
    - multiplier: How much to amplify match_conf (e.g., high-severity threats)

    Returns:
    - Threat score (float)
    """
    return (match_conf * multiplier) + (context_score * weight)
