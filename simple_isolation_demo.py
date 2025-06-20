#!/usr/bin/env python3
"""
Simple demonstration of Isolation Forest in telecom anomaly detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

def demonstrate_isolation_forest():
    """Show how Isolation Forest detects telecom anomalies."""
    
    print("ISOLATION FOREST IN TELECOM ANOMALY DETECTION")
    print("=" * 50)
    
    # Create sample telecom features (simplified)
    print("\n1. NORMAL TELECOM TRAFFIC:")
    normal_traffic = np.array([
        [0.3, 0.4, 0.1, 150, 140, 0.9],  # Balanced F1_C, F1_U, unknown, DU->RU, RU->DU, bidirectional
        [0.32, 0.38, 0.02, 120, 115, 0.85],
        [0.28, 0.42, 0.01, 180, 175, 0.92],
        [0.31, 0.39, 0.015, 135, 130, 0.88]
    ])
    
    print("Features: [F1_C_ratio, F1_U_ratio, unknown_ratio, DU->RU_packets, RU->DU_packets, bidirectional_ratio]")
    for i, sample in enumerate(normal_traffic):
        print(f"Normal {i+1}: {sample}")
    
    print("\n2. ANOMALOUS TELECOM TRAFFIC:")
    anomalous_traffic = np.array([
        [0.5, 0.3, 0.02, 200, 0, 0.2],     # Unidirectional failure
        [0.8, 0.0, 0.01, 80, 75, 0.7],     # Missing user plane
        [0.15, 0.2, 0.5, 90, 85, 0.6]      # Protocol deviation
    ])
    
    for i, sample in enumerate(anomalous_traffic):
        print(f"Anomaly {i+1}: {sample}")
    
    # Train Isolation Forest
    print("\n3. TRAINING ISOLATION FOREST:")
    all_data = np.vstack([normal_traffic, anomalous_traffic])
    
    iso_forest = IsolationForest(contamination=0.3, random_state=42)
    iso_forest.fit(all_data)
    
    # Test predictions
    print("\n4. ANOMALY DETECTION RESULTS:")
    print("-" * 40)
    
    test_cases = [
        ("Normal Traffic", normal_traffic[0]),
        ("Unidirectional Failure", anomalous_traffic[0]),
        ("Missing User Plane", anomalous_traffic[1]),
        ("Protocol Deviation", anomalous_traffic[2])
    ]
    
    for name, sample in test_cases:
        prediction = iso_forest.predict([sample])[0]
        score = iso_forest.decision_function([sample])[0]
        status = "ANOMALY" if prediction == -1 else "NORMAL"
        print(f"{name:20} | Score: {score:7.3f} | {status}")
    
    print("\n5. HOW IT WORKS:")
    print("- Creates random decision trees that split data")
    print("- Normal points need many splits to isolate (longer paths)")
    print("- Anomalies need fewer splits to isolate (shorter paths)")
    print("- Shorter path = higher anomaly score = detected anomaly")
    
    print("\n6. IN OUR TELECOM SYSTEM:")
    print("- Unidirectional failure: Detected by imbalanced RU-DU traffic")
    print("- Missing user plane: Detected by zero F1_U ratio")
    print("- Protocol deviations: Detected by high unknown protocol ratio")

if __name__ == "__main__":
    demonstrate_isolation_forest()