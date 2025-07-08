"""
Enhanced Quantum Threat Detector with advanced quantum algorithms and entropy-based obfuscation detection
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
from qiskit import IBMQ, transpile
from dotenv import load_dotenv
import os
from ai.entropy_detector import entropy  # ✅ Entropy detection imported
from ai.threat_scorer import compute_threat_score

dotenv_path = "/Users/apple/Desktop/qs-ai-ids-dashboard/.env"
load_dotenv(dotenv_path=dotenv_path)
ibmq_token = os.getenv("IBMQ_API_TOKEN")

class QuantumFeatureMap:
    def __init__(self, num_qubits: int, num_features: int):
        self.num_qubits = num_qubits
        self.num_features = num_features
        self.parameters = [Parameter(f'x_{i}') for i in range(num_features)]

    def create_circuit(self) -> QuantumCircuit:
        qc = QuantumCircuit(self.num_qubits)
        for i in range(self.num_qubits):
            qc.h(i)
        for i, param in enumerate(self.parameters[:self.num_qubits]):
            qc.ry(param, i)
        for i in range(self.num_qubits - 1):
            qc.cx(i, i + 1)
        for i, param in enumerate(self.parameters[:self.num_qubits]):
            qc.rz(param, i)
        return qc

class QuantumVariationalCircuit:
    def __init__(self, num_qubits: int, num_layers: int = 3):
        self.num_qubits = num_qubits
        self.num_layers = num_layers
        self.num_parameters = num_layers * num_qubits * 3
        self.parameters = [Parameter(f'theta_{i}') for i in range(self.num_parameters)]

    def create_circuit(self) -> QuantumCircuit:
        qc = QuantumCircuit(self.num_qubits)
        param_idx = 0
        for layer in range(self.num_layers):
            for qubit in range(self.num_qubits):
                qc.rx(self.parameters[param_idx], qubit)
                param_idx += 1
                qc.ry(self.parameters[param_idx], qubit)
                param_idx += 1
                qc.rz(self.parameters[param_idx], qubit)
                param_idx += 1
            for qubit in range(self.num_qubits - 1):
                qc.cx(qubit, qubit + 1)
            if self.num_qubits > 2:
                qc.cx(self.num_qubits - 1, 0)
        return qc

class QuantumThreatDetector:
    def __init__(self, num_qubits: int = 8, use_quantum: bool = True):
        load_dotenv()
        ibmq_token = os.getenv("IBMQ_API_TOKEN")
        self.num_qubits = num_qubits
        self.use_quantum = use_quantum
        self.logger = logging.getLogger(__name__)

        if self.use_quantum:
            self.feature_map = QuantumFeatureMap(num_qubits, num_features=17)  # ✅ updated to 17 features
            self.variational_circuit = QuantumVariationalCircuit(num_qubits, num_layers=4)
            self.simulator = AerSimulator()

            try:
                self.provider = IBMQ.load_account()
            except Exception:
                if ibmq_token:
                    IBMQ.save_account(ibmq_token, overwrite=True)
                    self.provider = IBMQ.load_account()
                else:
                    raise Exception("IBMQ token not found in environment variables!")
            self.real_backend = self.provider.get_backend("ibmq_manila")
            self.sampler = Sampler()

        self.classical_model = self._create_classical_model()

    def _create_classical_model(self) -> nn.Module:
        class ClassicalThreatNet(nn.Module):
            def __init__(self):
                super().__init__()
                self.layers = nn.Sequential(
                    nn.Linear(17, 64),  # ✅ 17 input features
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(32, 16),
                    nn.ReLU(),
                    nn.Linear(16, 5)
                )

            def forward(self, x):
                return torch.softmax(self.layers(x), dim=-1)

        return ClassicalThreatNet()

    def extract_features(self, data: str) -> np.ndarray:
        features = np.zeros(17)
        features[0] = len(data)
        features[1] = len(set(data))
        features[2] = data.count(' ')
        features[3] = data.count('=')
        features[4] = data.count('&')
        features[5] = data.count('?')
        features[6] = data.count('<')
        features[7] = data.count('>')
        features[8] = data.count('(')
        features[9] = data.count(')')
        features[10] = data.count('"')
        features[11] = data.count("'")

        data_lower = data.lower()
        features[12] = sum(1 for p in ['union', 'select', 'drop', 'insert', 'delete', 'update'] if p in data_lower)
        features[13] = sum(1 for p in ['<script>', 'alert(', 'eval('] if p in data_lower)
        features[14] = sum(1 for p in ['&&', ';', 'exec'] if p in data_lower)
        features[15] = sum(1 for p in ['../', '..\\', '%2e%2e'] if p in data_lower)

        features[16] = entropy(data) / 8.0  # ✅ Entropy normalized

        features = features / (np.max(features) + 1e-8)
        return features

    # ... rest of the class stays the same

    def analyze_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        self.metrics['total_analyses'] += 1
        payload = packet_data.get('payload') or self._extract_payload(packet_data)
        if not payload:
            return {}
        features = self.extract_features(payload)
        probabilities = self.quantum_classify(features)
        max_prob = max(probabilities.values())
        threat_threshold = 0.7
        if max_prob > threat_threshold:
            threat_type = max(probabilities, key=probabilities.get)
            context_score = features[12:16].sum()
            weight = 1.5
            multiplier = 2.0 if threat_type in ["ddos", "malware"] else 1.2
            threat_score = compute_threat_score(max_prob, context_score, weight, multiplier)
            self.metrics['threats_detected'] += 1
            return {
                'threat_detected': True,
                'threat_type': threat_type,
                'confidence': max_prob,
                'threat_score': round(threat_score, 3),
                'probabilities': probabilities,
                'payload': payload[:200],
                'source_ip': packet_data.get('source_ip', '0.0.0.0'),
                'timestamp': datetime.now().isoformat()
            }
        return {'threat_detected': False}

    def quantum_classify(self, features: np.ndarray) -> Dict[str, float]:
        if not self.use_quantum:
            return self.classical_classify(features)
        try:
            feature_circuit = self.feature_map.create_circuit()
            var_circuit = self.variational_circuit.create_circuit()
            full_circuit = feature_circuit.compose(var_circuit)
            full_circuit.add_register(ClassicalRegister(self.num_qubits))
            full_circuit.measure_all()
            param_values = {}
            for i, param in enumerate(self.feature_map.parameters):
                if i < len(features):
                    param_values[param] = features[i] * np.pi
            for i, param in enumerate(self.variational_circuit.parameters):
                param_values[param] = np.random.uniform(0, 2 * np.pi)
            bound_circuit = full_circuit.bind_parameters(param_values)
            transpiled = transpile(bound_circuit, backend=self.real_backend)
            job = self.real_backend.run(transpiled, shots=1024)
            result = job.result()
            counts = result.get_counts()
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

    def _extract_payload(self, packet_data: Dict[str, Any]) -> Optional[str]:
        try:
            if hasattr(packet_data, 'load'):
                return packet_data.load.decode('utf-8', errors='ignore')
            return None
        except:
            return None