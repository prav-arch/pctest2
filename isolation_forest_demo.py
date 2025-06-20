#!/usr/bin/env python3
"""
Demonstration of how Isolation Forest detects telecom anomalies.
Shows the algorithm's decision process step by step.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

def demonstrate_isolation_forest():
    """Demonstrate how Isolation Forest identifies telecom anomalies."""
    
    print("=" * 60)
    print("ISOLATION FOREST ANOMALY DETECTION DEMONSTRATION")
    print("=" * 60)
    
    # Create realistic telecom feature vectors
    print("\n1. NORMAL TELECOM TRAFFIC PATTERNS:")
    normal_features = create_normal_telecom_features()
    display_feature_patterns("Normal Traffic", normal_features)
    
    print("\n2. ANOMALOUS TELECOM TRAFFIC PATTERNS:")
    anomalous_features = create_anomalous_telecom_features()
    display_feature_patterns("Anomalous Traffic", anomalous_features)
    
    # Combine all data for training
    all_features = np.vstack([normal_features, anomalous_features])
    
    print("\n3. TRAINING ISOLATION FOREST:")
    print(f"Training on {len(all_features)} telecom traffic samples...")
    
    # Create and train Isolation Forest
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(all_features)
    
    iso_forest = IsolationForest(
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_estimators=100,
        verbose=1
    )
    
    iso_forest.fit(scaled_features)
    
    print("\n4. ANOMALY DETECTION RESULTS:")
    print("-" * 40)
    
    # Test on individual samples
    test_samples = [
        ("Normal RU-DU Traffic", normal_features[0]),
        ("Unidirectional Failure", anomalous_features[0]),
        ("Missing User Plane", anomalous_features[1]),
        ("Protocol Deviation", anomalous_features[2])
    ]
    
    for name, sample in test_samples:
        sample_scaled = scaler.transform([sample])
        prediction = iso_forest.predict(sample_scaled)[0]
        anomaly_score = iso_forest.decision_function(sample_scaled)[0]
        
        status = "ANOMALY" if prediction == -1 else "NORMAL"
        print(f"{name:20} | Score: {anomaly_score:8.4f} | {status}")
        
        if prediction == -1:
            explain_anomaly_detection(name, sample, normal_features[0])
    
    print("\n5. HOW ISOLATION FOREST WORKS:")
    explain_isolation_forest_mechanism()

def create_normal_telecom_features():
    """Create feature vectors representing normal telecom traffic."""
    # Features: [F1_C_ratio, F1_U_ratio, CPRI_ratio, eCPRI_ratio, NGAP_ratio, 
    #           unknown_ratio, protocol_count, flow_count, avg_packets_per_flow,
    #           bidirectional_ratio, ru_du_pairs, du_to_ru_packets, ru_to_du_packets,
    #           unidirectional_ratio, c_plane_ratio, u_plane_ratio]
    
    normal_patterns = np.array([
        # Normal balanced RU-DU communication
        [0.3, 0.4, 0.1, 0.1, 0.05, 0.01, 5, 12, 25.5, 0.9, 3, 150, 140, 0.1, 0.35, 0.45],
        [0.32, 0.38, 0.12, 0.08, 0.06, 0.02, 6, 10, 28.0, 0.85, 2, 120, 115, 0.05, 0.38, 0.42],
        [0.28, 0.42, 0.08, 0.14, 0.04, 0.01, 4, 15, 22.3, 0.92, 4, 180, 175, 0.08, 0.33, 0.47],
        [0.31, 0.39, 0.11, 0.09, 0.07, 0.015, 5, 11, 26.8, 0.88, 3, 135, 130, 0.12, 0.36, 0.44],
        [0.29, 0.41, 0.13, 0.07, 0.05, 0.008, 5, 13, 24.1, 0.91, 2, 160, 155, 0.09, 0.34, 0.46]
    ])
    
    return normal_patterns

def create_anomalous_telecom_features():
    """Create feature vectors representing anomalous telecom traffic."""
    anomalous_patterns = np.array([
        # Unidirectional communication failure (high DU->RU, zero RU->DU)
        [0.5, 0.3, 0.1, 0.05, 0.03, 0.02, 4, 8, 35.0, 0.2, 1, 200, 0, 1.0, 0.6, 0.2],
        
        # Missing user plane (only control plane traffic)
        [0.8, 0.0, 0.1, 0.05, 0.04, 0.01, 3, 6, 18.5, 0.7, 2, 80, 75, 0.15, 0.85, 0.0],
        
        # Protocol deviation (high unknown protocol ratio)
        [0.15, 0.2, 0.05, 0.03, 0.02, 0.5, 8, 20, 45.2, 0.6, 3, 90, 85, 0.2, 0.25, 0.3],
        
        # Excessive flow imbalance
        [0.25, 0.35, 0.08, 0.12, 0.06, 0.02, 6, 30, 85.7, 0.3, 5, 300, 50, 0.8, 0.4, 0.4]
    ])
    
    return anomalous_patterns

def display_feature_patterns(label, features):
    """Display key feature patterns for analysis."""
    print(f"{label} Features (showing key metrics):")
    feature_names = ["F1_C", "F1_U", "Unknown", "Flows", "Bidir%", "RU-DU", "Undir%"]
    
    for i, sample in enumerate(features):
        key_features = [sample[0], sample[1], sample[5], sample[7], sample[9], sample[10], sample[13]]
        print(f"  Sample {i+1}: ", end="")
        for j, (name, value) in enumerate(zip(feature_names, key_features)):
            print(f"{name}:{value:.2f}", end=" | " if j < len(key_features)-1 else "")
        print()

def explain_anomaly_detection(anomaly_name, anomaly_features, normal_features):
    """Explain why specific features indicate an anomaly."""
    print(f"\n    → WHY {anomaly_name.upper()} IS DETECTED:")
    
    if "Unidirectional" in anomaly_name:
        print(f"      • Unidirectional ratio: {anomaly_features[13]:.2f} (normal: {normal_features[13]:.2f})")
        print(f"      • RU→DU packets: {anomaly_features[12]:.0f} (normal: {normal_features[12]:.0f})")
        print("      • Complete communication failure detected!")
    
    elif "Missing User Plane" in anomaly_name:
        print(f"      • User plane ratio: {anomaly_features[15]:.2f} (normal: {normal_features[15]:.2f})")
        print(f"      • Control plane ratio: {anomaly_features[14]:.2f} (normal: {normal_features[14]:.2f})")
        print("      • Service degradation: no user data transmission!")
    
    elif "Protocol Deviation" in anomaly_name:
        print(f"      • Unknown protocol ratio: {anomaly_features[5]:.2f} (normal: {normal_features[5]:.2f})")
        print(f"      • Protocol diversity: {anomaly_features[6]:.0f} (normal: {normal_features[6]:.0f})")
        print("      • Potential security threat or misconfiguration!")

def explain_isolation_forest_mechanism():
    """Explain how Isolation Forest algorithm works."""
    print("Isolation Forest Algorithm Mechanism:")
    print("=====================================")
    print("1. TREE CONSTRUCTION:")
    print("   • Creates 100 random decision trees")
    print("   • Each tree randomly selects features and split values")
    print("   • Builds trees until each point is isolated")
    print()
    print("2. ISOLATION PATH LENGTH:")
    print("   • Normal points: Require many splits to isolate (long path)")
    print("   • Anomalous points: Few splits needed (short path)")
    print("   • Path length becomes the anomaly score")
    print()
    print("3. TELECOM-SPECIFIC DETECTION:")
    print("   • Unidirectional communication: Isolated by RU-DU imbalance")
    print("   • Missing planes: Isolated by control/user plane ratios")
    print("   • Protocol deviations: Isolated by unknown protocol ratios")
    print("   • Flow anomalies: Isolated by traffic pattern irregularities")
    print()
    print("4. DECISION THRESHOLD:")
    print("   • Contamination=0.1 sets threshold for top 10% anomalies")
    print("   • Score < threshold → ANOMALY (-1)")
    print("   • Score ≥ threshold → NORMAL (+1)")

def main():
    """Run the Isolation Forest demonstration."""
    demonstrate_isolation_forest()
    
    print("\n" + "=" * 60)
    print("ISOLATION FOREST SUMMARY")
    print("=" * 60)
    print("✓ Unsupervised learning: No labeled training data needed")
    print("✓ Telecom-aware: Uses 28 network-specific features")
    print("✓ Real-time detection: Fast prediction on new traffic")
    print("✓ Robust: Handles various anomaly types simultaneously")
    print("✓ Scalable: Efficient for large-scale network monitoring")

if __name__ == "__main__":
    main()