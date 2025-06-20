"""
Configuration file for Telecom Anomaly Detection System.
Contains hardcoded directory paths and system parameters.
"""

import os
from typing import List

class Config:
    """Configuration class with hardcoded paths and parameters."""
    
    def __init__(self):
        # Python script directory (hardcoded for Linux)
        self.PYTHON_DIRECTORY: str = "/usr/bin/python3"
        
        # Hardcoded Linux directory paths for PCAP files (with local fallback)
        self.PCAP_DIRS: List[str] = [
            "/var/log/telecom/pcap",
            "/opt/telecom/pcap",
            "/data/telecom/pcap", 
            "/home/telecom/pcap",
            "/usr/local/telecom/pcap",
            "/tmp/telecom/pcap",
            "./pcap_files"  # Local fallback for development
        ]
        
        # Hardcoded Linux directory paths for HDF files (with local fallback)
        self.HDF_DIRS: List[str] = [
            "/var/log/telecom/hdf",
            "/opt/telecom/hdf",
            "/data/telecom/hdf",
            "/home/telecom/hdf", 
            "/usr/local/telecom/hdf",
            "/tmp/telecom/hdf",
            "./hdf_files"  # Local fallback for development
        ]
        
        # Model storage directory (Linux with local fallback)
        self.MODEL_DIR: str = "./models"
        
        # Logging configuration (Linux with local fallback)
        self.LOG_LEVEL: str = "INFO"
        self.LOG_FILE: str = "./telecom_anomaly_detection.log"
        
        # Isolation Forest parameters
        self.CONTAMINATION_RATE: float = 0.1  # Expected anomaly rate (10%)
        self.N_ESTIMATORS: int = 100
        self.MAX_SAMPLES: str = "auto"
        self.RANDOM_STATE: int = 42
        
        # Anomaly detection thresholds
        self.UNIDIRECTIONAL_THRESHOLD: int = 5  # Packets before flagging unidirectional
        self.PLANE_RATIO_THRESHOLD: float = 0.1  # Minimum ratio for plane traffic
        self.RAPID_CYCLE_THRESHOLD: int = 5  # Max attach/detach events per UE
        self.UNKNOWN_PROTOCOL_THRESHOLD: float = 0.5  # Max ratio of unknown protocols
        
        # Feature extraction parameters
        self.FEATURE_WINDOW_SIZE: int = 1000  # Packets per analysis window
        self.MIN_FLOW_PACKETS: int = 5  # Minimum packets to consider a flow
        
        # RU-DU communication patterns based on MAC addresses
        self.RU_MAC_PATTERNS: List[str] = [
            "00:11:22:",   # RU vendor prefix 1
            "AA:BB:CC:",   # RU vendor prefix 2
            "44:55:66:",   # RU vendor prefix 3
        ]
        
        self.DU_MAC_PATTERNS: List[str] = [
            "00:11:22:33:44:67",   # Specific DU MAC address 1
            "00:11:22:33:44:66",   # Specific DU MAC address 2
            "00:11:22:",           # DU vendor prefix for other devices
        ]
        
        # Telecom protocol configurations
        self.TELECOM_PROTOCOLS: dict = {
            'CPRI': {
                'ports': [8080, 8081, 8082],
                'description': 'Common Public Radio Interface',
                'plane': 'fronthaul'
            },
            'eCPRI': {
                'ports': [3200, 3201, 3202],
                'description': 'Enhanced Common Public Radio Interface',
                'plane': 'fronthaul'
            },
            'F1_C': {
                'ports': [38472],
                'description': 'F1 Control Plane',
                'plane': 'control'
            },
            'F1_U': {
                'ports': [2152],
                'description': 'F1 User Plane (GTP-U)',
                'plane': 'user'
            },
            'NGAP': {
                'ports': [38412],
                'description': 'NG Application Protocol',
                'plane': 'control'
            },
            'S1_MME': {
                'ports': [36412],
                'description': 'S1 MME Interface',
                'plane': 'control'
            },
            'S1_U': {
                'ports': [2152],
                'description': 'S1 User Plane (GTP-U)',
                'plane': 'user'
            },
            'X2': {
                'ports': [36422],
                'description': 'X2 Interface',
                'plane': 'control'
            }
        }
        
        # Protocol port mappings (telecom standards)
        self.PROTOCOL_PORTS = {
            38472: {'protocol': 'F1_C', 'plane': 'control'},    # F1-C Control
            2152: {'protocol': 'F1_U', 'plane': 'user'},        # F1-U User
            36412: {'protocol': 'NGAP', 'plane': 'control'},    # NG-AP
            36413: {'protocol': 'S1_MME', 'plane': 'control'},  # S1-MME
            4789: {'protocol': 'VXLAN', 'plane': 'user'},       # VXLAN
            2123: {'protocol': 'GTP_C', 'plane': 'control'},    # GTP-C
            2152: {'protocol': 'GTP_U', 'plane': 'user'}        # GTP-U
        }
        
        # HDF file structure expectations
        self.HDF_EXPECTED_DATASETS: List[str] = [
            'ue_events',
            'attach_events',
            'detach_events',
            'mobility_events',
            'handover_events'
        ]
        
        # Performance settings
        self.MAX_PACKETS_PER_FILE: int = 100000  # Limit for memory management
        self.BATCH_SIZE: int = 1000  # Processing batch size
        self.PARALLEL_PROCESSING: bool = True
        self.MAX_WORKERS: int = 4
        
        # Output formatting (Linux with local fallback)
        self.DISPLAY_DETAILED_STATS: bool = True
        self.SAVE_RESULTS_TO_FILE: bool = True
        self.RESULTS_OUTPUT_DIR: str = "./results"
        
        # Create necessary directories
        self._create_directories()
    
    def _create_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        directories = [
            self.MODEL_DIR,
            self.RESULTS_OUTPUT_DIR,
            "./logs"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get_pcap_directories(self) -> List[str]:
        """Get list of existing PCAP directories."""
        return [d for d in self.PCAP_DIRS if os.path.exists(d)]
    
    def get_hdf_directories(self) -> List[str]:
        """Get list of existing HDF directories."""
        return [d for d in self.HDF_DIRS if os.path.exists(d)]
    
    def is_ru_mac(self, mac: str) -> bool:
        """Check if MAC address matches RU patterns."""
        if not mac:
            return False
        mac_upper = mac.upper()
        return any(mac_upper.startswith(pattern.upper()) for pattern in self.RU_MAC_PATTERNS)
    
    def is_du_mac(self, mac: str) -> bool:
        """Check if MAC address matches DU patterns."""
        if not mac:
            return False
        mac_upper = mac.upper()
        for pattern in self.DU_MAC_PATTERNS:
            pattern_upper = pattern.upper()
            # Check for exact match or prefix match
            if mac_upper == pattern_upper or mac_upper.startswith(pattern_upper):
                return True
        return False
    
    def get_protocol_info(self, port: int) -> dict:
        """Get protocol information based on port number."""
        for protocol, info in self.TELECOM_PROTOCOLS.items():
            if port in info['ports']:
                return {
                    'protocol': protocol,
                    'description': info['description'],
                    'plane': info['plane']
                }
        return {
            'protocol': 'unknown',
            'description': 'Unknown Protocol',
            'plane': 'other'
        }
