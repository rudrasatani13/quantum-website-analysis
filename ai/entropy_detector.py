"""
Entropy Detector Module
Detects obfuscated or encoded payloads using Shannon entropy.
"""

import math


def entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a given string.

    Higher entropy values may indicate obfuscation such as:
    - Base64 encoding
    - URL encoding
    - Compressed or encrypted strings

    Parameters:
        s (str): The input string to analyze.

    Returns:
        float: Entropy score (0.0 to ~8.0)
    """
    if not s:
        return 0.0

    # Character probability distribution
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]

    # Shannon entropy formula
    return -sum([p * math.log(p, 2) for p in prob])
