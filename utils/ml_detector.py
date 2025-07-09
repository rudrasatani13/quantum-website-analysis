import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os


class MLDetector:
    """Machine Learning based threat detection"""

    def __init__(self):
        self.model_path = os.path.join(os.path.dirname(__file__), 'models', 'threat_model.joblib')
        self.vectorizer_path = os.path.join(os.path.dirname(__file__), 'models', 'vectorizer.joblib')

        # Try to load models if they exist, otherwise use defaults
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.model_loaded = True
        except:
            self.model_loaded = False
            # Initialize with default model
            self.vectorizer = TfidfVectorizer(max_features=10000)
            self.model = RandomForestClassifier(n_estimators=100)

    def extract_features(self, content):
        """Extract features from website content"""
        features = {}

        # Basic text features
        features['content_length'] = len(content)
        features['js_count'] = content.lower().count('<script')
        features['iframe_count'] = content.lower().count('<iframe')
        features['url_count'] = content.lower().count('http')
        features['input_count'] = content.lower().count('<input')
        features['form_count'] = content.lower().count('<form')

        # Suspicious patterns
        features['eval_count'] = content.lower().count('eval(')
        features['document_write'] = content.lower().count('document.write')
        features['unescape'] = content.lower().count('unescape')
        features['exec_count'] = content.lower().count('exec(')

        # Create feature vector
        feature_vector = np.array([list(features.values())])

        return features, feature_vector

    def detect_threats(self, content):
        """Detect threats using ML model"""
        results = {
            'threats_detected': [],
            'confidence': 0.0,
            'ml_available': self.model_loaded
        }

        if not self.model_loaded:
            # Return default results if model isn't available
            return results

        # Extract features
        features, feature_vector = self.extract_features(content)

        # Convert content to vector using TF-IDF
        try:
            content_vector = self.vectorizer.transform([content])

            # Make prediction
            prediction = self.model.predict(content_vector)
            probabilities = self.model.predict_proba(content_vector)

            if prediction[0] == 1:  # Assuming 1 means malicious
                results['threats_detected'].append({
                    'type': 'ML-Detected Threat',
                    'confidence': float(probabilities[0][1]),  # Probability of malicious class
                    'features': features
                })
                results['confidence'] = float(probabilities[0][1])
        except Exception as e:
            results['error'] = str(e)

        return results