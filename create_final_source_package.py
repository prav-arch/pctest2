#!/usr/bin/env python3
"""
Create final source code package for download.
"""

import os
import zipfile
from datetime import datetime

def create_final_source_package():
    """Create comprehensive source code package."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"telecom_anomaly_detection_source_{timestamp}.zip"
    
    # Core source files
    source_files = [
        'telecom_anomaly_detector.py',
        'clickhouse_integration.py',
        'config.py',
        'utils.py',
        'run_system.py',
        'app.py',
        'pcap_analyzer.py',
        'cu_log_analyzer.py',
        'severity_classifier.py',
        'adaptive_contamination_system.py',
        'production_protocol_mapper.py',
        'suppress_warnings.py',
        'linux_config.py',
        'pyproject.toml',
        'README.md',
        'replit.md'
    ]
    
    # Configuration and setup files
    config_files = [
        '.replit',
        'linux_setup.sh',
        'linux_deployment_guide.md'
    ]
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        print("Creating comprehensive source package...")
        
        # Add core source files
        for file in source_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"Added: {file}")
        
        # Add configuration files
        for file in config_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"Added: {file}")
        
        # Create comprehensive documentation
        documentation = """# Telecom Anomaly Detection System - Complete Source Code

## Package Contents

### Core Detection Engine
- **telecom_anomaly_detector.py**: Main anomaly detection engine with Isolation Forest ML
- **utils.py**: Helper functions for feature extraction and logging
- **config.py**: Configuration management with hardcoded paths
- **run_system.py**: Simple execution script for running the system

### Specialized Analyzers
- **pcap_analyzer.py**: PCAP file analysis for network traffic anomalies
- **cu_log_analyzer.py**: CU (Central Unit) log file analysis
- **production_protocol_mapper.py**: Protocol detection for varying vendor equipment

### Classification and Management
- **severity_classifier.py**: Anomaly severity classification (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **adaptive_contamination_system.py**: Dynamic contamination adjustment (5%-50%)

### Database Integration
- **clickhouse_integration.py**: Complete ClickHouse database integration
  - Stores anomalies in exact fh_violations table structure
  - Uses now() function for event_time column
  - Enum8 severity mapping ('none'=0,'low'=1,'medium'=2,'high'=3)
  - UInt8 transport_ok field (0=violation, 1=ok)

### Web Interface
- **app.py**: Streamlit web interface for visualization and interaction

### Production Deployment
- **linux_config.py**: Production Linux configuration with system paths
- **linux_setup.sh**: Automated Linux deployment script
- **linux_deployment_guide.md**: Comprehensive deployment instructions

### System Configuration
- **suppress_warnings.py**: Cryptography warning suppression
- **pyproject.toml**: Python dependencies and project configuration
- **.replit**: Replit environment configuration

## Quick Start

### Basic Usage
```bash
# Run with default directories
python3 run_system.py

# Run with specific folder
python3 run_system.py /path/to/data/folder

# Start web interface
streamlit run app.py --server.port 5000
```

### ClickHouse Integration
```sql
-- Your fh_violations table structure:
CREATE TABLE fh_violations (
    event_time DateTime,
    type String,
    severity Enum8('none'=0,'low'=1,'medium'=2,'high'=3),
    description String,
    log_line String,
    transport_ok UInt8
) ENGINE = MergeTree()
ORDER BY event_time;
```

## System Capabilities

### File Type Support
- **PCAP files**: Network traffic analysis (.pcap, .pcapng)
- **HDF files**: UE event data (.hdf, .hdf5, .h5)
- **Log files**: CU log analysis (.txt, .log)

### Anomaly Detection (18 Types)
1. **Network Anomalies**:
   - Unidirectional communication (DU→RU, no response)
   - Missing control plane data
   - Missing user plane data
   - Protocol anomalies

2. **UE Event Anomalies**:
   - Rapid attach/detach cycles
   - Missing attach events
   - Missing detach events
   - Unbalanced event ratios

3. **CU Log Anomalies**:
   - Connection failures
   - Handover failures
   - Resource exhaustion
   - Authentication failures
   - Synchronization loss
   - Error frequency spikes
   - Timestamp gaps
   - Message frequency anomalies

### Production MAC Addresses
- **RU (Radio Unit)**: 6c:ad:ad:00:03:2a
- **DU (Distributed Unit)**: 00:11:22:33:44:67

### Machine Learning Features
- **Algorithm**: Isolation Forest (unsupervised)
- **Feature Extraction**: 28 telecom-specific features
- **Contamination**: Adaptive 5%-50% based on network conditions
- **Model Persistence**: Saves/loads trained models

### Severity Classification
- **CRITICAL**: Service-impacting failures requiring immediate response
- **HIGH**: Network degradation requiring urgent attention
- **MEDIUM**: Performance issues requiring planned response
- **LOW**: Minor issues for monitoring
- **INFO**: Informational events for analysis

## Dependencies

### Core Libraries
```
scapy>=2.6.1          # Network packet analysis
h5py>=3.14.0           # HDF5 file processing
scikit-learn>=1.7.0    # Machine learning algorithms
numpy>=2.3.0           # Numerical computations
pandas>=2.3.0          # Data manipulation
streamlit              # Web interface
clickhouse-driver      # ClickHouse database integration
```

### Installation
```bash
# Install dependencies
pip install scapy h5py scikit-learn numpy pandas streamlit clickhouse-driver

# Or use uv (faster)
uv add scapy h5py scikit-learn numpy pandas streamlit clickhouse-driver
```

## Configuration

### Data Directories
The system automatically detects and processes files from:
- Single folder with mixed file types
- Multiple predefined directories
- Command-line specified paths

### ClickHouse Configuration
```python
# Default connection settings
host = 'localhost'
port = 9000
database = 'l1_app_db'
table = 'fh_violations'
```

### Production Deployment
```bash
# Linux system setup
chmod +x linux_setup.sh
sudo ./linux_setup.sh

# Create system directories
sudo mkdir -p /var/log/telecom/
sudo mkdir -p /opt/telecom/
sudo mkdir -p /data/telecom/
```

## Output Examples

### Anomaly Detection
```
Analyzing PCAP files...
Processing: sample_network_traffic.pcap
  ✓ 200 packets analyzed
  ✓ 1 unidirectional communication detected
  ✓ DU sending to RU but no response from RU

Analyzing HDF files...
Processing: ue_events.hdf5
  ✓ 150 UE events processed
  ✓ 2 rapid attach/detach cycles detected

Total anomalies found: 18
Anomalies stored in ClickHouse: 18
```

### ClickHouse Storage
```sql
-- Sample stored record
SELECT * FROM fh_violations LIMIT 1;

event_time: 2025-06-26 05:50:15
type: unidirectional_communication
severity: high
description: DU sending to RU but no response from RU
log_line: Packet analysis showing one-way communication pattern
transport_ok: 0
```

## Support

This system is designed for production telecom network monitoring with:
- Real hardware MAC address detection
- Vendor-agnostic protocol support
- Scalable anomaly detection
- Professional reporting format
- Database integration for historical analysis

For technical support, refer to the comprehensive documentation included in each module.

---
*Generated: {timestamp}*
*Version: Production Release with ClickHouse Integration*
""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        zipf.writestr("README_COMPLETE.md", documentation)
        
        # Create deployment checklist
        checklist = """# Deployment Checklist

## Pre-Deployment
- [ ] Python 3.11+ installed
- [ ] Required packages installed (scapy, h5py, scikit-learn, etc.)
- [ ] ClickHouse server running and accessible
- [ ] fh_violations table created with exact schema
- [ ] Data directories prepared with PCAP/HDF/log files

## ClickHouse Setup
- [ ] Create database: CREATE DATABASE l1_app_db
- [ ] Create table with exact schema:
```sql
CREATE TABLE fh_violations (
    event_time DateTime,
    type String,
    severity Enum8('none'=0,'low'=1,'medium'=2,'high'=3),
    description String,
    log_line String,
    transport_ok UInt8
) ENGINE = MergeTree()
ORDER BY event_time;
```

## Testing
- [ ] Run: python3 run_system.py mixed_data_folder
- [ ] Verify anomaly detection output
- [ ] Check ClickHouse records inserted
- [ ] Test web interface: streamlit run app.py

## Production
- [ ] Configure system paths in linux_config.py
- [ ] Run linux_setup.sh for system directories
- [ ] Set up monitoring and alerting
- [ ] Schedule regular analysis runs

## Verification Queries
```sql
-- Check stored anomalies
SELECT COUNT(*) FROM fh_violations;

-- View recent violations
SELECT * FROM fh_violations ORDER BY event_time DESC LIMIT 10;

-- Severity distribution
SELECT severity, COUNT(*) FROM fh_violations GROUP BY severity;
```
"""
        zipf.writestr("DEPLOYMENT_CHECKLIST.md", checklist)
    
    size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
    
    print(f"\n✓ Complete Source Package Created: {zip_filename}")
    print(f"✓ Package Size: {size_mb:.2f} MB")
    print(f"✓ Files Included: {len(source_files + config_files)} core files")
    print("\nPackage Contents:")
    print("  ✓ Complete anomaly detection system")
    print("  ✓ ClickHouse integration with exact table structure")
    print("  ✓ Production deployment scripts")
    print("  ✓ Comprehensive documentation")
    print("  ✓ Web interface and configuration files")
    
    return zip_filename

if __name__ == "__main__":
    create_final_source_package()