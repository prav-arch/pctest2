#!/usr/bin/env python3
"""
Example script showing how to train the Isolation Forest model
for telecom anomaly detection.
"""

from telecom_anomaly_detector import TelecomAnomalyDetector
import os

def main():
    """Example of how to train the model with your data."""
    
    print("Telecom Anomaly Detection - Model Training Example")
    print("=" * 55)
    
    # Initialize the detector
    detector = TelecomAnomalyDetector()
    
    # Check available data files
    pcap_files = []
    hdf_files = []
    
    # Scan for PCAP files
    for pcap_dir in detector.config.PCAP_DIRS:
        if os.path.exists(pcap_dir):
            import glob
            pcap_files.extend(glob.glob(os.path.join(pcap_dir, "*.pcap")))
            pcap_files.extend(glob.glob(os.path.join(pcap_dir, "*.cap")))
    
    # Scan for HDF files
    for hdf_dir in detector.config.HDF_DIRS:
        if os.path.exists(hdf_dir):
            import glob
            hdf_files.extend(glob.glob(os.path.join(hdf_dir, "*.h5")))
            hdf_files.extend(glob.glob(os.path.join(hdf_dir, "*.hdf5")))
    
    print(f"Found {len(pcap_files)} PCAP files and {len(hdf_files)} HDF files")
    
    if not pcap_files and not hdf_files:
        print("\nNo training data found. Please ensure you have:")
        print("- PCAP files in one of these directories:")
        for d in detector.config.PCAP_DIRS:
            print(f"  {d}")
        print("- HDF files in one of these directories:")
        for d in detector.config.HDF_DIRS:
            print(f"  {d}")
        return
    
    # Process files and extract features
    print("\nExtracting features from training data...")
    all_features = []
    file_count = 0
    
    # Process PCAP files
    for pcap_file in pcap_files:
        print(f"Processing PCAP: {os.path.basename(pcap_file)}")
        result = detector.analyze_pcap_file(pcap_file)
        if 'error' not in result and 'features' in result:
            all_features.append(result['features'])
            file_count += 1
    
    # Process HDF files
    for hdf_file in hdf_files:
        print(f"Processing HDF: {os.path.basename(hdf_file)}")
        result = detector.analyze_hdf_file(hdf_file)
        if 'error' not in result and 'features' in result:
            all_features.append(result['features'])
            file_count += 1
    
    print(f"\nExtracted features from {file_count} files")
    
    if not all_features:
        print("No valid features extracted. Cannot train model.")
        return
    
    # Show feature statistics
    feature_lengths = [len(f) for f in all_features]
    print(f"Feature vector lengths: min={min(feature_lengths)}, max={max(feature_lengths)}, avg={sum(feature_lengths)/len(feature_lengths):.1f}")
    
    # Train the model
    print("\nTraining Isolation Forest model...")
    detector.train_model(all_features)
    
    if detector.model_trained:
        print("\nModel training completed successfully!")
        print(f"Model saved to: {detector.config.MODEL_DIR}")
        print("\nModel configuration:")
        print(f"- Algorithm: Isolation Forest")
        print(f"- Contamination rate: {detector.config.CONTAMINATION_RATE}")
        print(f"- Number of estimators: {detector.config.N_ESTIMATORS}")
        print(f"- Training samples: {len(all_features)}")
        
        # Test prediction on one sample
        if all_features:
            test_features = all_features[0]
            prediction, score = detector.predict_anomalies(test_features)
            print(f"\nTest prediction on first sample:")
            print(f"- Prediction: {'Anomaly' if prediction == -1 else 'Normal'}")
            print(f"- Anomaly score: {score:.4f}")
    else:
        print("\nModel training failed. Check logs for details.")

if __name__ == "__main__":
    main()