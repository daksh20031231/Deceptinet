#!/usr/bin/env python3
"""
Machine Learning Pipeline for Cyber Attack Classification
Combines supervised and unsupervised learning for comprehensive threat detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    roc_auc_score, precision_recall_curve
)
import joblib
import json
import math
from datetime import datetime, timedelta
from collections import Counter
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Try importing SHAP for explainability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("[WARNING] SHAP not installed. Run: pip install shap")


# ============================================================================
# FEATURE EXTRACTION ENGINE
# ============================================================================

class FeatureExtractor:
    """
    Extracts relevant features from raw cyber security events.
    Converts log data into ML-ready feature vectors.
    """
    
    def __init__(self):
        self.user_agent_frequencies = {}
        self.baseline_intervals = []
        
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        High entropy often indicates random/obfuscated payloads.
        
        Args:
            text: Input string (command, payload, etc.)
            
        Returns:
            Entropy value (0.0 to ~8.0 for typical text)
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_command_entropy(self, command: str) -> float:
        """
        Calculate entropy specifically for commands.
        Adds additional context for shell commands.
        """
        return self.calculate_entropy(command)
    
    def calculate_payload_features(self, payload: str) -> Dict[str, float]:
        """
        Extract multiple features from a payload string.
        
        Returns:
            Dictionary with payload characteristics
        """
        if not payload:
            return {
                'payload_length': 0,
                'payload_entropy': 0.0,
                'special_char_ratio': 0.0,
                'digit_ratio': 0.0,
                'uppercase_ratio': 0.0
            }
        
        length = len(payload)
        special_chars = sum(1 for c in payload if not c.isalnum() and not c.isspace())
        digits = sum(1 for c in payload if c.isdigit())
        uppercase = sum(1 for c in payload if c.isupper())
        
        return {
            'payload_length': length,
            'payload_entropy': self.calculate_entropy(payload),
            'special_char_ratio': special_chars / length if length > 0 else 0,
            'digit_ratio': digits / length if length > 0 else 0,
            'uppercase_ratio': uppercase / length if length > 0 else 0
        }
    
    def calculate_request_interval_features(self, 
                                           timestamps: List[datetime]) -> Dict[str, float]:
        """
        Analyze timing patterns in request sequences.
        
        Args:
            timestamps: List of request timestamps
            
        Returns:
            Statistical features about request intervals
        """
        if len(timestamps) < 2:
            return {
                'mean_interval': 0.0,
                'std_interval': 0.0,
                'min_interval': 0.0,
                'max_interval': 0.0,
                'interval_regularity': 0.0
            }
        
        # Calculate intervals in seconds
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        intervals = np.array(intervals)
        
        # Calculate regularity (inverse of coefficient of variation)
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        regularity = 0.0
        if mean_interval > 0:
            cv = std_interval / mean_interval
            regularity = 1.0 / (1.0 + cv)  # Normalize to [0, 1]
        
        return {
            'mean_interval': mean_interval,
            'std_interval': std_interval,
            'min_interval': np.min(intervals),
            'max_interval': np.max(intervals),
            'interval_regularity': regularity
        }
    
    def calculate_user_agent_rarity(self, 
                                    user_agent: str, 
                                    all_user_agents: List[str]) -> float:
        """
        Calculate rarity score for a user agent.
        Rare user agents may indicate automated tools.
        
        Args:
            user_agent: Current user agent string
            all_user_agents: Historical list of user agents
            
        Returns:
            Rarity score (0.0 = common, 1.0 = very rare)
        """
        if not all_user_agents:
            return 0.5  # Unknown
        
        # Count frequencies
        ua_counts = Counter(all_user_agents)
        total = len(all_user_agents)
        
        # Calculate rarity (inverse frequency)
        count = ua_counts.get(user_agent, 0)
        frequency = count / total if total > 0 else 0
        
        # Convert to rarity score
        rarity = 1.0 - frequency
        
        return rarity
    
    def extract_features(self, event: Dict) -> Dict[str, float]:
        """
        Extract all features from a single security event.
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            Feature dictionary ready for ML model
        """
        features = {}
        
        # Login failure features
        features['login_failures'] = event.get('login_failures', 0)
        features['consecutive_failures'] = event.get('consecutive_failures', 0)
        
        # Command entropy
        command = event.get('command', '')
        features['command_entropy'] = self.calculate_command_entropy(command)
        features['command_length'] = len(command)
        
        # Request interval features
        timestamps = event.get('timestamps', [])
        if isinstance(timestamps, list) and len(timestamps) > 0:
            # Convert strings to datetime if needed
            if isinstance(timestamps[0], str):
                timestamps = [datetime.fromisoformat(ts) for ts in timestamps]
            
            interval_features = self.calculate_request_interval_features(timestamps)
            features.update(interval_features)
        else:
            features.update({
                'mean_interval': 0.0,
                'std_interval': 0.0,
                'min_interval': 0.0,
                'max_interval': 0.0,
                'interval_regularity': 0.0
            })
        
        # Payload features
        payload = event.get('payload', '')
        payload_features = self.calculate_payload_features(payload)
        features.update(payload_features)
        
        # User agent rarity
        user_agent = event.get('user_agent', '')
        all_user_agents = event.get('all_user_agents', [user_agent])
        features['user_agent_rarity'] = self.calculate_user_agent_rarity(
            user_agent, all_user_agents
        )
        
        # Additional derived features
        features['total_requests'] = event.get('total_requests', 1)
        features['unique_commands'] = event.get('unique_commands', 1)
        features['session_duration'] = event.get('session_duration', 0.0)
        
        return features


# ============================================================================
# ML MODEL PIPELINE
# ============================================================================

class CyberAttackClassifier:
    """
    Main ML pipeline for attack classification.
    Combines Random Forest (supervised) and Isolation Forest (unsupervised).
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        
        # Supervised model for known attack patterns
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1
        )
        
        # Unsupervised model for anomaly/zero-day detection
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expect 10% anomalies
            random_state=random_state,
            n_jobs=-1
        )
        
        self.feature_names = []
        self.is_trained = False
        
    def prepare_features(self, events: List[Dict]) -> pd.DataFrame:
        """
        Convert raw events to feature matrix.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            DataFrame with extracted features
        """
        feature_list = []
        
        for event in events:
            features = self.feature_extractor.extract_features(event)
            feature_list.append(features)
        
        df = pd.DataFrame(feature_list)
        
        # Store feature names
        if not self.feature_names:
            self.feature_names = df.columns.tolist()
        
        return df
    
    def train(self, 
              events: List[Dict], 
              labels: List[int],
              validation_split: float = 0.2) -> Dict:
        """
        Train both supervised and unsupervised models.
        
        Args:
            events: Training events
            labels: Binary labels (0=benign, 1=attack)
            validation_split: Fraction for validation
            
        Returns:
            Training metrics
        """
        print("[*] Extracting features from training data...")
        X = self.prepare_features(events)
        y = np.array(labels)
        
        print(f"[*] Feature matrix shape: {X.shape}")
        print(f"[*] Attack samples: {sum(y)}, Benign samples: {len(y) - sum(y)}")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, 
            random_state=self.random_state, stratify=y
        )
        
        # Scale features
        print("[*] Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Train Random Forest (supervised)
        print("[*] Training Random Forest classifier...")
        self.rf_classifier.fit(X_train_scaled, y_train)
        
        # Train Isolation Forest (unsupervised, using all data)
        print("[*] Training Isolation Forest for anomaly detection...")
        X_all_scaled = self.scaler.transform(X)
        self.isolation_forest.fit(X_all_scaled)
        
        self.is_trained = True
        
        # Evaluate
        print("[*] Evaluating models...")
        metrics = self._evaluate(X_val_scaled, y_val)
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.rf_classifier.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\n[*] Top 10 Most Important Features:")
        print(feature_importance.head(10).to_string(index=False))
        
        metrics['feature_importance'] = feature_importance.to_dict('records')
        
        return metrics
    
    def _evaluate(self, X_val: np.ndarray, y_val: np.ndarray) -> Dict:
        """Internal evaluation method"""
        y_pred = self.rf_classifier.predict(X_val)
        y_pred_proba = self.rf_classifier.predict_proba(X_val)[:, 1]
        
        metrics = {
            'accuracy': np.mean(y_pred == y_val),
            'confusion_matrix': confusion_matrix(y_val, y_pred).tolist(),
            'classification_report': classification_report(
                y_val, y_pred, 
                target_names=['Benign', 'Attack'],
                output_dict=True
            ),
            'roc_auc': roc_auc_score(y_val, y_pred_proba)
        }
        
        print(f"\n[+] Validation Accuracy: {metrics['accuracy']:.3f}")
        print(f"[+] ROC-AUC Score: {metrics['roc_auc']:.3f}")
        print("\n[+] Classification Report:")
        print(classification_report(y_val, y_pred, target_names=['Benign', 'Attack']))
        
        return metrics
    
    def predict(self, events: List[Dict]) -> np.ndarray:
        """
        Predict attack probability for events.
        
        Returns:
            Array of threat scores (0-100)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        X = self.prepare_features(events)
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from both models
        rf_proba = self.rf_classifier.predict_proba(X_scaled)[:, 1]
        iso_scores = self.isolation_forest.score_samples(X_scaled)
        
        # Normalize isolation forest scores to [0, 1]
        # More negative = more anomalous
        iso_min, iso_max = iso_scores.min(), iso_scores.max()
        if iso_max > iso_min:
            iso_normalized = 1 - (iso_scores - iso_min) / (iso_max - iso_min)
        else:
            iso_normalized = np.zeros_like(iso_scores)
        
        # Combine predictions (weighted average)
        # RF gets 70% weight (supervised), IF gets 30% (anomaly detection)
        combined_score = 0.7 * rf_proba + 0.3 * iso_normalized
        
        # Convert to 0-100 scale
        threat_scores = (combined_score * 100).astype(int)
        
        return threat_scores
    
    def explain_prediction(self, 
                          event: Dict, 
                          use_shap: bool = True) -> Dict:
        """
        Explain why a prediction was made.
        
        Args:
            event: Single event to explain
            use_shap: Use SHAP for explanation (if available)
            
        Returns:
            Explanation dictionary
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before explanation")
        
        X = self.prepare_features([event])
        X_scaled = self.scaler.transform(X)
        
        # Get prediction
        threat_score = self.predict([event])[0]
        rf_proba = self.rf_classifier.predict_proba(X_scaled)[0, 1]
        
        explanation = {
            'threat_score': int(threat_score),
            'rf_probability': float(rf_proba),
            'feature_values': X.iloc[0].to_dict()
        }
        
        # Feature importance based explanation
        importances = self.rf_classifier.feature_importances_
        feature_contributions = []
        
        for i, (name, value) in enumerate(X.iloc[0].items()):
            feature_contributions.append({
                'feature': name,
                'value': float(value),
                'importance': float(importances[i]),
                'contribution': float(importances[i] * value)
            })
        
        feature_contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
        explanation['top_contributors'] = feature_contributions[:5]
        
        # SHAP explanation (if available)
        if use_shap and SHAP_AVAILABLE:
            try:
                explainer = shap.TreeExplainer(self.rf_classifier)
                shap_values = explainer.shap_values(X_scaled)
                
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # Get values for attack class
                
                shap_explanation = []
                for i, name in enumerate(self.feature_names):
                    shap_explanation.append({
                        'feature': name,
                        'shap_value': float(shap_values[0][i]),
                        'feature_value': float(X.iloc[0, i])
                    })
                
                shap_explanation.sort(key=lambda x: abs(x['shap_value']), reverse=True)
                explanation['shap_values'] = shap_explanation[:10]
                
            except Exception as e:
                print(f"[!] SHAP explanation failed: {e}")
        
        return explanation
    
    def save_model(self, path: str = 'models/'):
        """Save trained models to disk"""
        import os
        os.makedirs(path, exist_ok=True)
        
        joblib.dump(self.rf_classifier, f'{path}/rf_classifier.pkl')
        joblib.dump(self.isolation_forest, f'{path}/isolation_forest.pkl')
        joblib.dump(self.scaler, f'{path}/scaler.pkl')
        
        metadata = {
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'random_state': self.random_state
        }
        
        with open(f'{path}/metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[+] Models saved to {path}")
    
    def load_model(self, path: str = 'models/'):
        """Load trained models from disk"""
        self.rf_classifier = joblib.load(f'{path}/rf_classifier.pkl')
        self.isolation_forest = joblib.load(f'{path}/isolation_forest.pkl')
        self.scaler = joblib.load(f'{path}/scaler.pkl')
        
        with open(f'{path}/metadata.json', 'r') as f:
            metadata = json.load(f)
        
        self.feature_names = metadata['feature_names']
        self.is_trained = metadata['is_trained']
        self.random_state = metadata['random_state']
        
        print(f"[+] Models loaded from {path}")


# ============================================================================
# SYNTHETIC DATASET GENERATOR
# ============================================================================

class DatasetGenerator:
    """
    Generates realistic synthetic cybersecurity event data.
    Useful for testing and demonstration.
    """
    
    @staticmethod
    def generate_benign_event(index: int) -> Dict:
        """Generate a benign user event"""
        base_time = datetime.now() - timedelta(hours=np.random.randint(0, 24))
        
        # Normal user behavior
        timestamps = [
            base_time + timedelta(seconds=np.random.uniform(10, 300) * i)
            for i in range(np.random.randint(3, 10))
        ]
        
        benign_commands = ['ls', 'pwd', 'whoami', 'cat file.txt', 'cd /home']
        
        return {
            'event_id': f'benign_{index}',
            'login_failures': np.random.randint(0, 2),
            'consecutive_failures': 0,
            'command': np.random.choice(benign_commands),
            'timestamps': timestamps,
            'payload': f'username=user{np.random.randint(1, 100)}',
            'user_agent': np.random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]),
            'all_user_agents': [],  # Will be filled later
            'total_requests': len(timestamps),
            'unique_commands': np.random.randint(2, 6),
            'session_duration': (timestamps[-1] - timestamps[0]).total_seconds()
        }
    
    @staticmethod
    def generate_attack_event(index: int, attack_type: str = 'sql_injection') -> Dict:
        """Generate an attack event"""
        base_time = datetime.now() - timedelta(hours=np.random.randint(0, 24))
        
        # Attack patterns have regular intervals (automated)
        timestamps = [
            base_time + timedelta(seconds=i * np.random.uniform(0.5, 2))
            for i in range(np.random.randint(10, 50))
        ]
        
        if attack_type == 'sql_injection':
            payloads = [
                "admin' OR '1'='1",
                "'; DROP TABLE users--",
                "admin' UNION SELECT * FROM passwords--",
                "1' AND 1=1--"
            ]
            commands = [f"query: {p}" for p in payloads]
            
        elif attack_type == 'brute_force':
            payloads = [f"password{i}" for i in range(100)]
            commands = ['login'] * len(payloads)
            
        elif attack_type == 'xss':
            payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert(document.cookie)",
                "<img src=x onerror=alert(1)>"
            ]
            commands = [f"input: {p}" for p in payloads]
        
        else:  # generic attack
            payloads = ['malicious_payload'] * 10
            commands = ['suspicious_command'] * 10
        
        return {
            'event_id': f'attack_{attack_type}_{index}',
            'login_failures': np.random.randint(5, 50),
            'consecutive_failures': np.random.randint(5, 20),
            'command': np.random.choice(commands),
            'timestamps': timestamps,
            'payload': np.random.choice(payloads),
            'user_agent': np.random.choice([
                'sqlmap/1.4.7',
                'python-requests/2.28.0',
                'curl/7.68.0',
                'Nikto/2.1.6'
            ]),
            'all_user_agents': [],  # Will be filled later
            'total_requests': len(timestamps),
            'unique_commands': np.random.randint(1, 3),
            'session_duration': (timestamps[-1] - timestamps[0]).total_seconds()
        }
    
    @staticmethod
    def generate_dataset(n_benign: int = 500, 
                        n_attacks: int = 200) -> Tuple[List[Dict], List[int]]:
        """
        Generate complete dataset with benign and attack events.
        
        Returns:
            Tuple of (events, labels)
        """
        events = []
        labels = []
        
        print(f"[*] Generating {n_benign} benign events...")
        for i in range(n_benign):
            events.append(DatasetGenerator.generate_benign_event(i))
            labels.append(0)
        
        print(f"[*] Generating {n_attacks} attack events...")
        attack_types = ['sql_injection', 'brute_force', 'xss', 'generic']
        for i in range(n_attacks):
            attack_type = np.random.choice(attack_types)
            events.append(DatasetGenerator.generate_attack_event(i, attack_type))
            labels.append(1)
        
        # Fill in user agent frequencies
        all_uas = [e['user_agent'] for e in events]
        for event in events:
            event['all_user_agents'] = all_uas
        
        # Shuffle
        indices = np.random.permutation(len(events))
        events = [events[i] for i in indices]
        labels = [labels[i] for i in indices]
        
        print(f"[+] Generated {len(events)} total events")
        
        return events, labels


# ============================================================================
# MAIN DEMONSTRATION
# ============================================================================

def main():
    """Demonstrate the complete ML pipeline"""
    
    print("=" * 70)
    print("CYBERSECURITY ML ATTACK CLASSIFICATION PIPELINE")
    print("=" * 70)
    
    # Generate synthetic dataset
    print("\n[1] GENERATING SYNTHETIC DATASET")
    print("-" * 70)
    generator = DatasetGenerator()
    events, labels = generator.generate_dataset(n_benign=600, n_attacks=300)
    
    # Initialize classifier
    print("\n[2] INITIALIZING ML PIPELINE")
    print("-" * 70)
    classifier = CyberAttackClassifier(random_state=42)
    
    # Train models
    print("\n[3] TRAINING MODELS")
    print("-" * 70)
    metrics = classifier.train(events, labels, validation_split=0.2)
    
    # Save models
    print("\n[4] SAVING MODELS")
    print("-" * 70)
    classifier.save_model()
    
    # Test predictions on new data
    print("\n[5] TESTING INFERENCE")
    print("-" * 70)
    
    test_events = [
        generator.generate_benign_event(999),
        generator.generate_attack_event(999, 'sql_injection'),
        generator.generate_attack_event(1000, 'brute_force')
    ]
    
    threat_scores = classifier.predict(test_events)
    
    print("\nTest Predictions:")
    for i, (event, score) in enumerate(zip(test_events, threat_scores)):
        print(f"  Event {i+1} ({event['event_id']}): Threat Score = {score}/100")
    
    # Explain a prediction
    print("\n[6] EXPLAINING PREDICTIONS")
    print("-" * 70)
    attack_event = test_events[1]
    explanation = classifier.explain_prediction(attack_event, use_shap=SHAP_AVAILABLE)
    
    print(f"\nExplanation for: {attack_event['event_id']}")
    print(f"Threat Score: {explanation['threat_score']}/100")
    print(f"Attack Probability: {explanation['rf_probability']:.3f}")
    print("\nTop Contributing Features:")
    for contrib in explanation['top_contributors']:
        print(f"  {contrib['feature']}: {contrib['value']:.3f} "
              f"(importance: {contrib['importance']:.3f})")
    
    if 'shap_values' in explanation:
        print("\nSHAP Values (Top Features):")
        for shap_item in explanation['shap_values'][:5]:
            print(f"  {shap_item['feature']}: {shap_item['shap_value']:.3f}")
    
    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)
    print(f"\nModels saved to: models/")
    print(f"Feature importance and metrics available in training output")
    
    if SHAP_AVAILABLE:
        print("\n[✓] SHAP explainability enabled")
    else:
        print("\n[!] Install SHAP for enhanced explainability: pip install shap")
    
    return classifier, metrics


if __name__ == "__main__":
    classifier, metrics = main()
