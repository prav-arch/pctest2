# Telecom Anomaly Detection - Linux Deployment Guide

## Quick Setup

1. **Make setup script executable and run:**
```bash
chmod +x linux_setup.sh
sudo ./linux_setup.sh
```

2. **Place your data files:**
```bash
# Copy PCAP files to any of these directories:
sudo cp your_files.pcap /var/log/telecom/pcap/
sudo cp your_files.pcap /opt/telecom/pcap/
sudo cp your_files.pcap /data/telecom/pcap/

# Copy HDF files to any of these directories:
sudo cp your_files.hdf5 /var/log/telecom/hdf/
sudo cp your_files.hdf5 /opt/telecom/hdf/
sudo cp your_files.hdf5 /data/telecom/hdf/
```

3. **Run the anomaly detector:**
```bash
# Development mode (uses local directories):
telecom-detector

# Production mode (uses Linux system directories):
telecom-detector-production

# Or directly:
python3 /opt/telecom/bin/telecom_anomaly_detector.py
```

## Hardcoded Linux Directories

### PCAP File Locations (searched in order):
- `/var/log/telecom/pcap/`
- `/opt/telecom/pcap/`
- `/data/telecom/pcap/`
- `/home/telecom/pcap/`
- `/usr/local/telecom/pcap/`
- `/tmp/telecom/pcap/`

### HDF File Locations (searched in order):
- `/var/log/telecom/hdf/`
- `/opt/telecom/hdf/`
- `/data/telecom/hdf/`
- `/home/telecom/hdf/`
- `/usr/local/telecom/hdf/`
- `/tmp/telecom/hdf/`

### System Directories:
- **Models**: `/var/lib/telecom/models/`
- **Logs**: `/var/log/telecom/telecom_anomaly_detection.log`
- **Results**: `/var/log/telecom/results/`
- **Python**: `/usr/bin/python3`

## Anomaly Detection Features

### Output Behavior:
- **Normal operation**: Prints "no anomalies found"
- **Anomaly detection**: Shows detailed analysis with packet logs
- **Exit code 0**: Always returns success for monitoring compatibility

### Detects Your Specific Scenarios:
1. **DU sending but RU not responding** (HIGH severity)
2. **Missing Control/User Plane data** (MEDIUM severity)
3. **Unbalanced UE Attach/Detach events** (MEDIUM severity)

### Sample Output:
```
============================================================
FILE: unidirectional_anomaly.pcap
============================================================
Type: PCAP
Anomaly Status: ANOMALY DETECTED
Anomaly Score: -0.0006 (lower = more anomalous)

Detected Issues (1):
  1. [HIGH] unidirectional_communication
     Description: DU sending to RU but no response from RU: 192.168.2.10-192.168.1.20

     ANOMALY LOG DETAILS:
     → Total DU→RU packets: 200, RU→DU responses: 0
     → Sample DU packets with no RU response:
        1. Packet #0 at 12:36:45.534
           192.168.2.10:38472 → 192.168.1.20:38472
           Protocol: F1_C, Size: 66 bytes
     Log file: /var/log/telecom/pcap/unidirectional_anomaly.pcap
```

## Manual Installation (Alternative)

If you prefer manual setup:

```bash
# Create directories
sudo mkdir -p /var/log/telecom/{pcap,hdf,results}
sudo mkdir -p /opt/telecom/{pcap,hdf,bin}
sudo mkdir -p /data/telecom/{pcap,hdf}
sudo mkdir -p /var/lib/telecom/models

# Install dependencies
sudo python3 -m pip install scapy h5py scikit-learn numpy pandas

# Copy files
sudo cp telecom_anomaly_detector.py /opt/telecom/bin/
sudo cp config.py /opt/telecom/bin/
sudo cp utils.py /opt/telecom/bin/
sudo chmod +x /opt/telecom/bin/telecom_anomaly_detector.py

# Create symlink
sudo ln -sf /opt/telecom/bin/telecom_anomaly_detector.py /usr/local/bin/telecom-detector
```

## File Permissions

The setup script creates appropriate permissions:
- System directories: 755 (read/execute for all)
- Temporary directories: 777 (full access)
- Script files: executable permissions

## Troubleshooting

1. **Permission denied**: Run with sudo
2. **No data found**: Check file locations match hardcoded paths
3. **Python errors**: Ensure all dependencies installed
4. **Model training fails**: Verify sufficient data files exist

## System Requirements

- Linux distribution (Ubuntu, RHEL, CentOS, etc.)
- Python 3.6+
- Root or sudo access for setup
- Sufficient disk space for models and logs