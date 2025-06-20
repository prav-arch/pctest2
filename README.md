# Telecom Anomaly Detection System

A standalone Python script for detecting anomalies in telecom network traffic using unsupervised machine learning. The system analyzes PCAP files for protocol-level anomalies and HDF files for UE (User Equipment) mobility events using the Isolation Forest algorithm.

## Features

### PCAP File Analysis
- **Protocol Detection**: Identifies telecom protocols (CPRI, eCPRI, F1-C, F1-U, NGAP, S1-MME, etc.)
- **RU-DU Communication Analysis**: Monitors bidirectional traffic between Radio Units and Distributed Units
- **Plane Separation**: Analyzes Control Plane (C-Plane) and User Plane (U-Plane) traffic
- **Unidirectional Communication Detection**: Identifies cases where DU sends but RU doesn't respond
- **Flow Analysis**: Monitors network flows and traffic patterns

### HDF File Analysis
- **UE Event Processing**: Extracts and analyzes UE Attach/Detach events
- **Mobility Pattern Analysis**: Detects unusual mobility patterns and handover events
- **Event Correlation**: Identifies rapid attach/detach cycles and unbalanced event ratios

### Anomaly Detection
- **Unsupervised Learning**: Uses Isolation Forest algorithm requiring no labeled training data
- **Feature Extraction**: Extracts meaningful features from telecom protocols and UE events
- **Real-time Analysis**: Provides immediate anomaly detection with confidence scores
- **Model Persistence**: Saves and loads trained models for continuous improvement

## Installation

### Prerequisites
```bash
# Install required packages
pip install scapy h5py scikit-learn numpy pandas
