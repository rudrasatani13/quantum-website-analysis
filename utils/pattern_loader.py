import json
import os


def load_attack_patterns(json_path: str = "config/attack_patterns.json") -> dict:
    """
    Load attack patterns and indicators from a JSON file.

    Args:
        json_path (str): Path to the JSON file.

    Returns:
        dict: Dictionary containing attack patterns and legitimate indicators.
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Attack pattern file not found at: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    required_keys = {"patterns", "legitimate_indicators"}
    if not required_keys.issubset(data.keys()):
        raise ValueError(f"Invalid pattern file structure. Required keys: {required_keys}")

    return data
