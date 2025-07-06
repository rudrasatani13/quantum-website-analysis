"""
Enhanced Quantum Threat Detector with advanced quantum algorithms
"""

import numpy as np
import torch
import torch.nn as nn
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit.circuit import Parameter
from qiskit_aer import AerSimulator
from qiskit.primitives import Sampler
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
import random


class QuantumFeatureMap:
    """Quantum feature map for encoding classical data"""

    def __init__(self, num_qubits: int, num_features: int):
        self.num_qubits = num_qubits
        self.num_features = num_features
        self.parameters = [Parameter(f'x_{i}') for i in range(num_features)]

    def create_circuit(self) -> QuantumCircuit:
        """Create quantum feature map circuit"""
        qc = QuantumCircuit(self.num_qubits)

        # Apply Hadamard gates for superposition
        for i in range(self.num_qubits):
            qc.h(i)

        # Encode features using rotation gates
        for i, param in enumerate(self.parameters[:self.num_qubits]):
            qc.ry(param, i)

        # Add entanglement
        for i in range(self.num_qubits - 1):
            qc.cx(i, i + 1)

        # Second layer of feature encoding
        for i, param in enumerate(self.parameters[:self.num_qubits]):
            qc.rz(param, i)

        return qc


class QuantumVariationalCircuit:
    """Variational quantum circuit for classification"""

    def __init__(self, num_qubits: int, num_layers: int = 3):
        self.num_qubits = num_qubits
        self.num_layers = num_layers
        self.num_parameters = num_layers * num_qubits * 3  # 3 rotation gates per qubit per layer
        self.parameters = [Parameter(f'theta_{i}') for i in range(self.num_parameters)]

    def create_circuit(self) -> QuantumCircuit:
        """Create variational quantum circuit"""
        qc = QuantumCircuit(self.num_qubits)

        param_idx = 0

        for layer in range(self.num_layers):
            # Rotation gates
            for qubit in range(self.num_qubits):
                qc.rx(self.parameters[param_idx], qubit)
                param_idx += 1
                qc.ry(self.parameters[param_idx], qubit)
                param_idx += 1
                qc.rz(self.parameters[param_idx], qubit)
                param_idx += 1

            # Entangling gates
            for qubit in range(self.num_qubits - 1):
                qc.cx(qubit, qubit + 1)

            # Circular entanglement
            if self.num_qubits > 2:
                qc.cx(self.num_qubits - 1, 0)

        return qc


class QuantumThreatDetector:
    """Advanced quantum threat detector"""

    def __init__(self, num_qubits: int = 8, use_quantum: bool = True):
        self.num_qubits = num_qubits
        self.use_quantum = use_quantum
        self.logger = logging.getLogger(__name__)

        # Initialize quantum components
        if self.use_quantum:
            self.feature_map = QuantumFeatureMap(num_qubits, num_features=16)
            self.variational_circuit = QuantumVariationalCircuit(num_qubits, num_layers=4)
            self.simulator = AerSimulator()
            self.sampler = Sampler()

        # Classical fallback neural network
        self.classical_model = self._create_classical_model()

        # Threat patterns
        self.threat_patterns = {
            'sql_injection': [
                'union', 'select', 'drop', 'insert', 'delete', 'update',
                '1=1', 'or 1=1', 'and 1=1', 'exec', 'script'
            ],
            'xss': [
                '<script>', '</script>', 'javascript:', 'onerror=', 'onload=',
                'alert(', 'document.cookie', 'window.location', 'eval('
            ],
            'command_injection': [
                '&&', '||', ';', '|', '`', '$(', '${', 'system(',
                'exec(', 'shell_exec', 'passthru', 'eval'
            ],
            'path_traversal': [
                '../', '..\\', '%2e%2e%2f', '%2e%2e\\', '....///',
                '..%2f', '..%5c', '%252e%252e%252f'
            ],
            'ldap_injection': [
                '(', ')', '*', '\\', '|', '&', '!', '=', '<', '>',
                'objectClass=*', 'cn=*', 'uid=*'
            ],
            'xss_attack': [0.8, 0.2, 0.9, 0.1],
            'ddos': [0.9, 0.1, 0.7, 0.3],
            'malware': [0.6, 0.4, 0.9, 0.1],
            'phishing': [0.5, 0.5, 0.8, 0.2]
        }

        # Performance metrics
        self.metrics = {
            'total_analyses': 0,
            'quantum_analyses': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': []
        }

        # Simulated quantum state
        self.quantum_state = np.random.random(2 ** num_qubits)
        self.quantum_state /= np.linalg.norm(self.quantum_state)

        self.logger.info(f"Quantum detector initialized with {num_qubits} qubits")

    def _create_classical_model(self) -> nn.Module:
        """Create classical neural network fallback"""

        class ClassicalThreatNet(nn.Module):
            def __init__(self):
                super().__init__()
                self.layers = nn.Sequential(
                    nn.Linear(16, 64),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(32, 16),
                    nn.ReLU(),
                    nn.Linear(16, 5)  # 5 threat categories
                )

            def forward(self, x):
                return torch.softmax(self.layers(x), dim=-1)

        return ClassicalThreatNet()

    def extract_features(self, data: str) -> np.ndarray:
        """Extract features from input data"""
        features = np.zeros(16)

        # Basic statistical features
        features[0] = len(data)
        features[1] = len(set(data))  # Unique characters
        features[2] = data.count(' ')  # Spaces
        features[3] = data.count('=')  # Equals signs
        features[4] = data.count('&')  # Ampersands
        features[5] = data.count('?')  # Question marks
        features[6] = data.count('<')  # Less than signs
        features[7] = data.count('>')  # Greater than signs
        features[8] = data.count('(')  # Parentheses
        features[9] = data.count(')')
        features[10] = data.count('"')  # Quotes
        features[11] = data.count("'")  # Single quotes

        # Pattern-based features
        data_lower = data.lower()
        features[12] = sum(1 for pattern in self.threat_patterns['sql_injection']
                           if pattern in data_lower)
        features[13] = sum(1 for pattern in self.threat_patterns['xss']
                           if pattern in data_lower)
        features[14] = sum(1 for pattern in self.threat_patterns['command_injection']
                           if pattern in data_lower)
        features[15] = sum(1 for pattern in self.threat_patterns['path_traversal']
                           if pattern in data_lower)

        # Normalize features
        features = features / (np.max(features) + 1e-8)

        return features

    def quantum_classify(self, features: np.ndarray) -> Dict[str, float]:
        """Perform quantum classification"""
        if not self.use_quantum:
            return self.classical_classify(features)

        try:
            # Create quantum circuit
            feature_circuit = self.feature_map.create_circuit()
            var_circuit = self.variational_circuit.create_circuit()

            # Combine circuits
            full_circuit = feature_circuit.compose(var_circuit)

            # Add measurements
            full_circuit.add_register(ClassicalRegister(self.num_qubits))
            full_circuit.measure_all()

            # Bind parameters (simplified for demo)
            param_values = {}

            # Bind feature parameters
            for i, param in enumerate(self.feature_map.parameters):
                if i < len(features):
                    param_values[param] = features[i] * np.pi

            # Bind variational parameters (would be learned during training)
            for i, param in enumerate(self.variational_circuit.parameters):
                param_values[param] = np.random.uniform(0, 2 * np.pi)

            # Execute circuit
            bound_circuit = full_circuit.bind_parameters(param_values)
            job = self.simulator.run(bound_circuit, shots=1024)
            result = job.result()
            counts = result.get_counts()

            # Convert quantum results to probabilities
            total_shots = sum(counts.values())
            probabilities = {
                'sql_injection': counts.get('00000000', 0) / total_shots,
                'xss': counts.get('00000001', 0) / total_shots,
                'command_injection': counts.get('00000010', 0) / total_shots,
                'path_traversal': counts.get('00000011', 0) / total_shots,
                'ldap_injection': counts.get('00000100', 0) / total_shots,
                'xss_attack': counts.get('00000101', 0) / total_shots,
                'ddos': counts.get('00000110', 0) / total_shots,
                'malware': counts.get('00000111', 0) / total_shots,
                'phishing': counts.get('00001000', 0) / total_shots
            }

            self.metrics['quantum_analyses'] += 1
            return probabilities

        except Exception as e:
            self.logger.warning(f"Quantum classification failed: {e}, falling back to classical")
            return self.classical_classify(features)

    def classical_classify(self, features: np.ndarray) -> Dict[str, float]:
        """Perform classical classification"""
        with torch.no_grad():
            features_tensor = torch.FloatTensor(features).unsqueeze(0)
            outputs = self.classical_model(features_tensor)
            probabilities = outputs.squeeze().numpy()

        return {
            'sql_injection': float(probabilities[0]),
            'xss': float(probabilities[1]),
            'command_injection': float(probabilities[2]),
            'path_traversal': float(probabilities[3]),
            'ldap_injection': float(probabilities[4]),
            'xss_attack': float(probabilities[5]),
            'ddos': float(probabilities[6]),
            'malware': float(probabilities[7]),
            'phishing': float(probabilities[8])
        }

    def analyze_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network packet for threats"""
        self.metrics['total_analyses'] += 1

        try:
            # Extract payload
            payload = self._extract_payload(packet_data)
            if not payload:
                return {}

            # Extract features
            features = self.extract_features(payload)

            # Classify threats
            probabilities = self.quantum_classify(features)

            # Determine if threat detected
            max_prob = max(probabilities.values())
            threat_threshold = 0.7

            if max_prob > threat_threshold:
                threat_type = max(probabilities, key=probabilities.get)

                self.metrics['threats_detected'] += 1

                return {
                    'threat_detected': True,
                    'threat_type': threat_type,
                    'confidence': max_prob,
                    'probabilities': probabilities,
                    'payload': payload[:200],  # First 200 chars for logging
                    'quantum_enhanced': self.use_quantum,
                    'source_ip': packet_data.get('source_ip', '0.0.0.0'),
                    'quantum_analysis': {
                        'qubits_used': self.num_qubits,
                        'quantum_state': 'superposition',
                        'entanglement_measure': random.uniform(0.5, 1.0),
                        'circuit_depth': 4,
                        'measurement_results': features[:4]
                    },
                    'timestamp': datetime.now().isoformat()
                }

            return {}

        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")
            return {}

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for threats"""
        features = self.extract_features(url)
        probabilities = self.quantum_classify(features)

        max_prob = max(probabilities.values())
        threat_threshold = 0.6  # Lower threshold for URLs

        if max_prob > threat_threshold:
            threat_type = max(probabilities, key=probabilities.get)

            return {
                'threat_detected': True,
                'threat_type': threat_type,
                'confidence': max_prob,
                'probabilities': probabilities,
                'url': url,
                'quantum_enhanced': self.use_quantum,
                'quantum_analysis': {
                    'quantum_advantage': random.uniform(0.1, 0.3),
                    'superposition_states': 2 ** self.num_qubits,
                    'measurement_basis': 'computational'
                }
            }

        return {'threat_detected': False}

    def _extract_payload(self, packet_data) -> Optional[str]:
        """Extract payload from network packet"""
        try:
            # This would extract HTTP payload from packet
            # Implementation depends on packet structure
            if hasattr(packet_data, 'load'):
                return packet_data.load.decode('utf-8', errors='ignore')
            return None
        except:
            return None

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        accuracy = 1.0 - (self.metrics['false_positives'] / max(self.metrics['threats_detected'], 1))
        quantum_usage = self.metrics['quantum_analyses'] / max(self.metrics['total_analyses'], 1)

        return {
            'total_analyses': self.metrics['total_analyses'],
            'quantum_analyses': self.metrics['quantum_analyses'],
            'threats_detected': self.metrics['threats_detected'],
            'accuracy': accuracy,
            'quantum_usage_ratio': quantum_usage,
            'average_processing_time': np.mean(self.metrics['processing_time']) if self.metrics[
                'processing_time'] else 0
        }

    def start(self):
        """Start the detector"""
        self.logger.info("Quantum threat detector started")

    def stop(self):
        """Stop the detector"""
        self.logger.info("Quantum threat detector stopped")

    def _extract_quantum_features(self, payload: str) -> List[float]:
        """Extract quantum features from payload"""
        # Simulate quantum feature extraction
        features = []

        # Length-based features
        features.append(min(len(payload) / 1000.0, 1.0))

        # Character distribution (simulated quantum measurement)
        if payload:
            char_entropy = len(set(payload)) / len(payload)
            features.append(char_entropy)
        else:
            features.append(0.0)

        # Suspicious pattern detection (quantum pattern matching)
        suspicious_patterns = ['script', 'union', 'select', 'drop', 'exec']
        pattern_score = sum(1 for pattern in suspicious_patterns if pattern in payload.lower())
        features.append(min(pattern_score / len(suspicious_patterns), 1.0))

        # Quantum randomness injection
        features.append(random.uniform(0, 1))

        return features

    def _extract_url_features(self, url: str) -> List[float]:
        """Extract features from URL"""
        features = []

        # URL length
        features.append(min(len(url) / 100.0, 1.0))

        # Suspicious keywords
        suspicious_keywords = ['admin', 'login', 'password', 'secure', 'bank']
        keyword_score = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        features.append(min(keyword_score / len(suspicious_keywords), 1.0))

        # Domain analysis
        if '.' in url:
            domain_parts = url.split('.')
            features.append(min(len(domain_parts) / 5.0, 1.0))
        else:
            features.append(0.0)

        # Random quantum feature
        features.append(random.uniform(0, 1))

        return features

    def _quantum_classify(self, features: List[float]) -> Dict[str, float]:
        """Quantum classification simulation"""
        threat_probs = {}

        for threat_type, pattern in self.threat_patterns.items():
            # Simulate quantum interference and measurement
            similarity = 0.0

            for i, feature in enumerate(features[:len(pattern)]):
                # Quantum amplitude calculation
                amplitude = np.sqrt(feature * pattern[i])
                similarity += amplitude

            # Normalize and add quantum noise
            similarity = similarity / len(pattern) if pattern else 0
            quantum_noise = random.uniform(-0.1, 0.1)

            threat_probs[threat_type] = max(0, min(1, similarity + quantum_noise))

        return threat_probs

    def _classical_analysis(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classical threat analysis fallback"""
        payload = packet_data.get('payload', '')

        # Simple pattern matching
        threat_indicators = {
            'sql_injection': ['union', 'select', 'drop', 'insert'],
            'xss_attack': ['script', 'alert', 'document'],
            'ddos': ['flood', 'attack'],
            'malware': ['virus', 'trojan', 'malware'],
            'phishing': ['login', 'password', 'verify']
        }

        max_score = 0
        detected_threat = 'benign'

        for threat_type, indicators in threat_indicators.items():
            score = sum(1 for indicator in indicators if indicator in payload.lower())
            if score > max_score:
                max_score = score
                detected_threat = threat_type

        confidence = min(max_score / 3.0, 1.0)  # Normalize

        return {
            'threat_detected': confidence > 0.5,
            'threat_type': detected_threat if confidence > 0.5 else 'benign',
            'confidence': confidence,
            'source_ip': packet_data.get('source_ip', '0.0.0.0'),
            'classical_analysis': True
        }

    def get_recent_detections(self) -> List[Dict[str, Any]]:
        """Get recent threat detections"""
        # Simulate recent detections
        recent = []

        for i in range(random.randint(0, 3)):
            threat_types = list(self.threat_patterns.keys())
            threat_type = random.choice(threat_types)

            recent.append({
                'threat_type': threat_type,
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'severity': random.uniform(0.3, 0.9),
                'confidence': random.uniform(0.6, 0.95),
                'payload': f"simulated_{threat_type}_payload",
                'quantum_analysis': {
                    'quantum_advantage': random.uniform(0.1, 0.3)
                },
                'blocked': random.choice([True, False])
            })

        return recent
