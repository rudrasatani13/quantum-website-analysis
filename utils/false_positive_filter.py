"""
Utility to detect and filter out false positives based on context
"""

def is_false_positive(payload: str, indicators: list) -> bool:
    """
    Return True if any indicator is present in the payload, meaning likely false positive.
    """
    for term in indicators:
        if term.lower() in payload.lower():
            return True
    return False
