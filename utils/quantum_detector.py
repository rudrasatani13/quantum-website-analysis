import numpy as np
from typing import Optional, Literal

# Qiskit imports
try:
    from qiskit import Aer, QuantumCircuit
    from qiskit.primitives import Sampler
    from qiskit_machine_learning.kernels import QuantumKernel
    from qiskit_machine_learning.algorithms import QSVC
    from qiskit_ibm_provider import IBMProvider
    _qiskit_available = True
except ImportError as e:
    print(f"Qiskit import error: {e}")
    _qiskit_available = False

# PennyLane imports
try:
    import pennylane as qml
    from pennylane import numpy as pnp
    _pennylane_available = True
except ImportError as e:
    print(f"PennyLane import error: {e}")
    _pennylane_available = False

class QuantumDetector:
    """
    QuantumDetector for anomaly/fraud detection using quantum algorithms.
    Supports Qiskit and PennyLane backends. Provides a scikit-learn-like interface.
    """
    def __init__(self, backend: Literal['qiskit', 'pennylane'] = 'qiskit',
                 use_real_hardware: bool = False,
                 qiskit_backend_name: str = 'aer_simulator',
                 pennylane_device: str = 'default.qubit',
                 n_qubits: int = 2):
        self.backend = backend
        self.use_real_hardware = use_real_hardware
        self.qiskit_backend_name = qiskit_backend_name
        self.pennylane_device = pennylane_device
        self.n_qubits = n_qubits
        self.model = None
        self.W = None
        self.circuit = None
        self._init_backend()

    def _init_backend(self):
        if self.backend == 'qiskit':
            if not _qiskit_available:
                raise ImportError('Qiskit and Qiskit Machine Learning are not installed. Please install them to use the Qiskit backend.')
            if self.use_real_hardware:
                try:
                    # Use the new IBMProvider for real hardware
                    provider = IBMProvider()
                    self.qiskit_backend = provider.get_backend(self.qiskit_backend_name)
                except Exception as e:
                    print(f"Warning: Could not connect to IBM Quantum backend '{self.qiskit_backend_name}'. Falling back to AerSimulator. Error: {e}")
                    self.qiskit_backend = Aer.get_backend(self.qiskit_backend_name)
            else:
                self.qiskit_backend = Aer.get_backend(self.qiskit_backend_name)
        elif self.backend == 'pennylane':
            if not _pennylane_available:
                raise ImportError('PennyLane is not installed. Please install it to use the PennyLane backend.')
            self.pennylane_dev = qml.device(self.pennylane_device, wires=self.n_qubits)
        else:
            raise ValueError('Unsupported backend.')

    def fit(self, X, y):
        """
        Fit the quantum model to the data.
        X: np.ndarray, shape (n_samples, n_features)
        y: np.ndarray, shape (n_samples,)
        """
        if self.backend == 'qiskit':
            self._fit_qiskit(X, y)
        elif self.backend == 'pennylane':
            self._fit_pennylane(X, y)

    def predict(self, X):
        """
        Predict using the trained quantum model.
        X: np.ndarray, shape (n_samples, n_features)
        Returns: np.ndarray, shape (n_samples,)
        """
        if self.model is None and self.backend == 'qiskit':
            raise ValueError('Qiskit model has not been fit yet.')
        if (self.circuit is None or self.W is None) and self.backend == 'pennylane':
            raise ValueError('PennyLane model has not been fit yet.')

        if self.backend == 'qiskit':
            return self._predict_qiskit(X)
        elif self.backend == 'pennylane':
            return self._predict_pennylane(X)

    def _fit_qiskit(self, X, y):
        if not _qiskit_available:
            raise ImportError('Qiskit and Qiskit Machine Learning are not installed.')
        # Use a simple quantum kernel SVM for demonstration
        feature_map = QuantumCircuit(self.n_qubits)
        for i in range(self.n_qubits):
            feature_map.h(i)
        # QuantumInstance is deprecated in Qiskit 1.0+. Use Sampler.
        sampler = Sampler()
        quantum_kernel = QuantumKernel(feature_map=feature_map, sampler=sampler)
        self.model = QSVC(quantum_kernel=quantum_kernel)
        self.model.fit(X, y)

    def _predict_qiskit(self, X):
        if self.model is None:
            raise ValueError('Qiskit model has not been fit yet.')
        return self.model.predict(X)

    def _fit_pennylane(self, X, y):
        if not _pennylane_available:
            raise ImportError('PennyLane is not installed.')
        # Simple variational classifier for demonstration
        dev = self.pennylane_dev
        n_qubits = self.n_qubits
        n_layers = 2

        def layer(W):
            for i in range(n_qubits):
                qml.Rot(*W[i], wires=i)
            for i in range(n_qubits):
                qml.CNOT(wires=[i, (i+1)%n_qubits])

        def variational_circuit(x, W):
            for i in range(n_qubits):
                qml.RY(x[i], wires=i)
            layer(W)

        @qml.qnode(dev)
        def circuit(x, W):
            variational_circuit(x, W)
            return [qml.expval(qml.PauliZ(i)) for i in range(n_qubits)]

        def cost(W, X, Y):
            loss = 0
            for x, y in zip(X, Y):
                # Ensure y is compatible with np.sign output (-1 or 1)
                # Assuming y is 0 or 1, convert to -1 or 1
                y_mapped = 2 * y - 1
                pred = np.sign(np.sum(circuit(x, W)))
                loss += (pred - y_mapped)**2
            return loss / len(X)

        W = 0.01 * np.random.randn(n_qubits, 3)
        opt = qml.GradientDescentOptimizer(stepsize=0.1)
        steps = 50
        for i in range(steps):
            W = opt.step(lambda w: cost(w, X, y), W)
        self.W = W
        self.circuit = circuit

    def _predict_pennylane(self, X):
        if self.circuit is None or self.W is None:
            raise ValueError('PennyLane model has not been fit yet.')
        preds = []
        for x in X:
            pred = np.sign(np.sum(self.circuit(x, self.W)))
            # Map -1, 1 back to 0, 1 if original labels were 0, 1
            preds.append((pred + 1) / 2) # Assuming original labels were 0, 1
        return np.array(preds)
