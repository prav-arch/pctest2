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
- **Data Directories**: Hardcoded Linux system paths with local fallbacks for development
- **Model Storage**: Linux production paths (/var/lib/telecom/models) with local fallback
- **Logging**: Linux system logging (/var/log/telecom/) with local fallback

### Scalability Considerations
- **Unsupervised Learning**: No need for labeled training data
- **Model Persistence**: Trained models can be reused across sessions
- **Configurable Thresholds**: Adjustable parameters for different network environments

## Changelog

```
Changelog:
- June 20, 2025. Initial setup
- June 20, 2025. Enhanced anomaly detection with specific log details:
  * Added detailed packet logs for PCAP anomalies
  * Added UE event logs for HDF anomalies  
  * Enhanced unidirectional communication detection
  * Added missing plane data detection with sample packets
  * Improved output formatting with specific timestamps and packet details
- June 20, 2025. Linux deployment configuration:
  * Hardcoded Linux directory paths for production deployment
  * Created linux_setup.sh script for automated system setup
  * Added linux_deployment_guide.md with comprehensive deployment instructions
  * Created linux_config.py for production-specific configuration
  * Added dual-mode operation: development (local) and production (Linux system paths)
  * Configured system directories: /var/log/telecom/, /opt/telecom/, /data/telecom/
  * Created wrapper scripts for seamless production deployment
- June 20, 2025. Silent operation mode implementation:
  * Modified system to only display output when anomalies are detected
  * Prints "no anomalies found" when all files are normal
  * Logging redirected to file-only for production use
  * Maintains detailed anomaly reporting with packet logs and event details
  * Optimized for Linux deployment with clear status indication
- June 20, 2025. MAC address-based RU/DU identification:
  * Replaced IP-based patterns with MAC address patterns for device identification
  * Updated DU MAC patterns to include specific addresses: 00:11:22:33:44:67, 00:11:22:33:44:66
  * Enhanced detection accuracy using Layer 2 addressing instead of Layer 3
  * Maintains telecom standards in main config, Linux-specific paths in linux_config
  * Created MAC-based sample data for testing with user's specific DU addresses
  * Successfully tested unidirectional communication detection with MAC-based patterns
  * Communication keys now display MAC addresses instead of IP patterns for clearer identification
- June 20, 2025. Anomaly severity classification system implementation:
  * Created comprehensive severity classifier with 5 levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
  * Integrated priority scoring based on network impact, service impact, urgency, frequency, and duration
  * Added contextual severity assessment considering device count, packet loss, duration, and business hours
  * Enhanced anomaly reporting with impact descriptions, response times, and escalation requirements
  * Implemented severity distribution statistics with automatic escalation identification
  * Successfully tested all severity levels with comprehensive test data scenarios
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```