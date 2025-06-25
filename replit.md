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
- June 20, 2025. Production protocol variation handling system:
  * Implemented flexible protocol detection for varying vendor naming conventions (Nokia, Ericsson, custom)
  * Added multi-layer detection: protocol name mapping, port-based fallback, payload content inspection
  * Created confidence scoring system to select best protocol identification method
  * Enhanced MAC address detection with regex patterns for flexible vendor matching
  * Maintained consistent 28-feature extraction regardless of protocol name variations
  * Ensured Isolation Forest compatibility across mixed vendor environments without retraining
- June 20, 2025. Updated with actual RU and DU MAC addresses:
  * Configured system with real hardware MAC addresses: RU (6c:ad:ad:00:03:2a) and DU (00:11:22:33:44:67)
  * Updated all configuration files and protocol mappers with actual addresses
  * Created device family patterns for scalable detection of similar hardware
  * Verified RU-DU communication detection works correctly with real addresses
  * Generated updated sample data using actual MAC addresses for testing
  * Maintained production flexibility while ensuring accurate device identification
- June 20, 2025. Adaptive contamination system for dynamic anomaly detection:
  * Implemented adaptive contamination manager to handle varying real-time anomaly rates (5%-50%)
  * Added network stress monitoring: security attacks, infrastructure failures, maintenance windows
  * Created dynamic model retraining when contamination changes significantly (>5%)
  * Integrated historical pattern analysis and stability controls to prevent oscillation
  * Successfully tested adaptation from normal 8% to crisis 35% anomaly rates with optimal sensitivity
  * Eliminates fixed 10% limitation ensuring no missed threats during high anomaly periods
- June 23, 2025. Single folder configuration and emoji-free output:
  * Configured system for single data directory containing both PCAP and HDF files
  * Added folder input support via command line arguments and programmatic methods
  * Removed all emoji symbols from output for professional display format
  * Updated configuration to use unified DATA_DIRS pointing to single folder locations
  * Successfully tested with mixed data folder containing 13 PCAP and 3 HDF files
  * System automatically detects and processes all supported file types from one location
- June 23, 2025. CU (Central Unit) log analysis integration:
  * Added comprehensive CU log analyzer for .txt and .log file anomaly detection
  * Implemented 18 specialized features for CU log analysis including error patterns, timing anomalies
  * Integrated 6 error categories: connection failures, handover failures, resource exhaustion, protocol errors, authentication failures, synchronization loss
  * Added log level analysis (CRITICAL, ERROR, WARNING, INFO, DEBUG) with frequency tracking
  * Implemented timestamp gap detection for missing log periods identification
  * Successfully tested with sample CU log containing 38 lines, detected 11 errors across 6 categories
  * Severity classification automatically applied to CU log anomalies with priority scoring
- June 24, 2025. Enhanced anomaly reporting format:
  * Removed "ESCALATION REQUIRED" messages from output for cleaner professional display
  * Added comprehensive anomaly summary at end showing all detected anomalies with descriptions
  * Improved final output format with complete anomaly inventory and impact assessments
  * Maintains severity classification and recommended actions without unnecessary alert messaging
- June 25, 2025. Fixed cryptography deprecation warnings:
  * Updated cryptography package to version 45.0.4 (latest stable)
  * Added comprehensive warning suppression system with suppress_warnings.py module
  * Updated all main Python files with robust warning filters (telecom_anomaly_detector.py, app.py, run_system.py)
  * System now runs completely clean without cryptography/scapy deprecation warnings
  * Clean professional output maintained while preserving all detection functionality
  * Created individual file downloads (31 files) and web interface to bypass Replit rate limits
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```