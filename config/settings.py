"""
Configuration management for QS-AI-IDS
"""

import os
import json
import yaml
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any


@dataclass
class QuantumSettings:
    """Quantum computing settings"""
    enabled: bool = True
    num_qubits: int = 8
    circuit_depth: int = 4
    shots: int = 1024
    backend: str = "qasm_simulator"
    noise_model: bool = False


@dataclass
class NetworkSettings:
    """Network monitoring settings"""
    interfaces: List[str] = None
    packet_buffer_size: int = 10000
    capture_filter: str = "tcp port 80 or tcp port 443"

    def __post_init__(self):
        if self.interfaces is None:
            self.interfaces = ["eth0", "wlan0"]


@dataclass
class AISettings:
    """AI/ML settings"""
    model_path: str = "models/threat_detector.pkl"
    confidence_threshold: float = 0.7
    batch_size: int = 32
    learning_rate: float = 0.001


@dataclass
class SecuritySettings:
    """Security settings"""
    encryption_enabled: bool = True
    audit_logging: bool = True
    threat_response: bool = False


class Settings:
    """Main settings class"""

    def __init__(self, config_file: str = None):
        self.config_file = config_file or "config/settings.yaml"

        # Initialize with defaults
        self.quantum = QuantumSettings()
        self.network = NetworkSettings()
        self.ai = AISettings()
        self.security = SecuritySettings()

        # Load from file if exists
        self.load_config()

    def load_config(self):
        """Load configuration from YAML file"""
        config_path = Path(self.config_file)

        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config_data = yaml.safe_load(f)

                if config_data:
                    # Update quantum settings
                    if 'quantum' in config_data:
                        quantum_data = config_data['quantum']
                        for key, value in quantum_data.items():
                            if hasattr(self.quantum, key):
                                setattr(self.quantum, key, value)

                    # Update network settings
                    if 'network' in config_data:
                        network_data = config_data['network']
                        for key, value in network_data.items():
                            if hasattr(self.network, key):
                                setattr(self.network, key, value)

                    # Update AI settings
                    if 'ai' in config_data:
                        ai_data = config_data['ai']
                        for key, value in ai_data.items():
                            if hasattr(self.ai, key):
                                setattr(self.ai, key, value)

                    # Update security settings
                    if 'security' in config_data:
                        security_data = config_data['security']
                        for key, value in security_data.items():
                            if hasattr(self.security, key):
                                setattr(self.security, key, value)

            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")

    def save_config(self):
        """Save configuration to YAML file"""
        config_data = {
            'quantum': asdict(self.quantum),
            'network': asdict(self.network),
            'ai': asdict(self.ai),
            'security': asdict(self.security)
        }

        # Ensure config directory exists
        config_path = Path(self.config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file {self.config_file}: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            'quantum': asdict(self.quantum),
            'network': asdict(self.network),
            'ai': asdict(self.ai),
            'security': asdict(self.security)
        }
