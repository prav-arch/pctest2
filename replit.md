# Telecom Anomaly Detection System

## Overview

This is a standalone Python application for detecting anomalies in telecom network traffic using unsupervised machine learning. The system analyzes PCAP files for protocol-level anomalies and HDF files for UE (User Equipment) events. It uses the Isolation Forest algorithm to identify unusual patterns without requiring labeled training data.

## System Architecture

The application follows a modular architecture with clear separation of concerns:

### Core Components
- **Main Application**: `telecom_anomaly_detector.py` - Primary detection engine
- **Configuration Management**: `config.py` - Centralized configuration with hardcoded paths
- **Utilities**: `utils.py` - Helper functions for logging, feature extraction, and file processing
- **Web Interface**: Streamlit-based frontend for visualization and interaction

### Technology Stack
- **Runtime**: Python 3.11
- **Machine Learning**: scikit-learn (Isolation Forest algorithm)
- **Network Analysis**: Scapy for PCAP file processing
- **Data Processing**: NumPy, Pandas for data manipulation
- **File Handling**: h5py for HDF file processing
- **Web Framework**: Streamlit for user interface
- **Deployment**: Autoscale deployment on Replit

## Key Components

### 1. Anomaly Detection Engine
- **Algorithm**: Isolation Forest for unsupervised anomaly detection
- **Features**: Extracts meaningful features from telecom protocols and UE events
- **Model Persistence**: Saves and loads trained models for continuous improvement
- **Configurable Parameters**: Contamination rate (10%), n_estimators (100), random state for reproducibility

### 2. PCAP Analysis Module
- **Protocol Detection**: Identifies telecom protocols (CPRI, eCPRI, F1-C, F1-U, NGAP, S1-MME)
- **RU-DU Communication**: Monitors bidirectional traffic between Radio Units and Distributed Units
- **Traffic Analysis**: Separates Control Plane and User Plane traffic
- **Flow Monitoring**: Analyzes network flows and traffic patterns

### 3. HDF Analysis Module
- **UE Event Processing**: Extracts UE Attach/Detach events
- **Mobility Analysis**: Detects unusual mobility patterns and handover events
- **Event Correlation**: Identifies rapid cycles and unbalanced ratios

### 4. Configuration System
- **Hardcoded Paths**: Multiple directory paths for PCAP and HDF files
- **Detection Thresholds**: Configurable anomaly detection parameters
- **Model Storage**: Dedicated directory for ML model persistence

## Data Flow

1. **File Discovery**: System scans predefined directories for PCAP and HDF files
2. **Feature Extraction**: Processes files to extract telecom-specific features
3. **Model Training/Loading**: Trains new Isolation Forest model or loads existing one
4. **Anomaly Detection**: Applies model to identify anomalies with confidence scores
5. **Result Presentation**: Displays findings through Streamlit interface

## External Dependencies

### Core Libraries
- **scapy**: Network packet analysis and PCAP processing
- **h5py**: HDF5 file format handling for UE event data
- **scikit-learn**: Machine learning algorithms (Isolation Forest)
- **numpy**: Numerical computations and array operations
- **pandas**: Data manipulation and analysis
- **streamlit**: Web application framework

### System Requirements
- **Python 3.11**: Base runtime environment
- **Additional Packages**: glibcLocales, hdf5, imagemagickBig, openssh, pkg-config, sox, tcpdump, wireshark

## Deployment Strategy

### Replit Configuration
- **Environment**: Nix-based with stable-24_05 channel
- **Deployment Target**: Autoscale for dynamic resource allocation
- **Port Configuration**: Streamlit server on port 5000
- **Workflow**: Automated dependency installation and project execution

### Directory Structure
- **Data Directories**: Multiple fallback paths for PCAP and HDF files
- **Model Storage**: Local models directory for ML model persistence
- **Logging**: Centralized logging with file and console output

### Scalability Considerations
- **Unsupervised Learning**: No need for labeled training data
- **Model Persistence**: Trained models can be reused across sessions
- **Configurable Thresholds**: Adjustable parameters for different network environments

## Changelog

```
Changelog:
- June 20, 2025. Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```