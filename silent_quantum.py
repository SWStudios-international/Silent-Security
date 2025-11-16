import random
import logging
from collections import Counter

# Quantum ternary states (decorative, could be used for key generation)
QUANTUM_STATES = ['|0⟩', '|1⟩', '(|0⟩ + |1⟩)/√2', '(|0⟩ - |1⟩)/√2', '(|0⟩ + i|1⟩)/√2', '(|0⟩ - i|1⟩)/√2']

def generate_quantum_key(length=16):
    """Generate a decorative quantum key"""
    return ''.join(random.choice(QUANTUM_STATES) for _ in range(length))

# Default thresholds
SUSPICIOUS_THRESHOLD = 1
HIGHLY_SUSPICIOUS_THRESHOLD = 2

# Base patterns and their weights
BASE_PATTERNS = {
    'malware': 1, 
    'unauthorized access': 1, 
    'data exfiltration': 2,
    'privilege escalation': 2,
    'qkd': 2,
    'entanglement': 2,
    'superposition': 2,
    'quantum computer': 2,
    'quantum algorithm': 2,
    'quantum gate': 2,
}

def quantum_score(entry, patterns=BASE_PATTERNS):
    """Calculate a quantum-style score for a log entry"""
    entry_lower = entry.lower()
    score = 0
    for pattern, weight in patterns.items():
        if pattern in entry_lower:
            score = max(score, weight)  # take the highest weight match
    return score

def aggregate_log_entries(entries, patterns=BASE_PATTERNS):
    """
    Aggregate multiple entries, calculate quantum scores
    Returns dict with safe/suspicious/highly_suspicious counts + detailed scores
    """
    summary_counts = Counter({'safe':0, 'suspicious':0, 'highly_suspicious':0})
    detailed_scores = {}

    for entry in entries:
        score = quantum_score(entry, patterns)
        detailed_scores[entry] = score
        if score == 0:
            summary_counts['safe'] += 1
        elif score == 1:
            summary_counts['suspicious'] += 1
        else:
            summary_counts['highly_suspicious'] += 1

    return {**summary_counts, 'detailed': detailed_scores}

def detect_quantum_patterns(entry):
    """Detect quantum-specific terms in a log entry"""
    quantum_terms = ['qubit', 'superposition', 'entanglement', 'quantum gate', 'quantum circuit']
    return [term for term in quantum_terms if term in entry.lower()]

# Example usage
if __name__ == "__main__":
    test_entries = [
        "User login successful",
        "Failed login attempt from 192.168.1.23",
        "Detected ransomware process XYZ",
        "Quantum computing experiment initialized",
        "Unauthorized access detected"
    ]

    results = aggregate_log_entries(test_entries)
    print("Summary:", {k: results[k] for k in ['safe','suspicious','highly_suspicious']})
    print("Detailed Scores:")
    for entry, score in results['detailed'].items():
        print(f"{entry} -> {score}")
