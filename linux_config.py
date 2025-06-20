"""
Production Linux Configuration for Telecom Anomaly Detection System.
This configuration uses hardcoded Linux system directories for deployment.
"""

import os
from typing import List

class LinuxConfig:
    """Production Linux configuration class with hardcoded system paths."""
    
    def __init__(self):
        # Python script directory (hardcoded for Linux)
        self.PYTHON_DIRECTORY: str = "/usr/bin/python3"
        
        # Production Linux directory paths for PCAP files
        self.PCAP_DIRS: List[str] = [
            "/var/log/telecom/pcap",
            "/opt/telecom/pcap",
            "/data/telecom/pcap", 
            "/home/telecom/pcap",
            "/usr/local/telecom/pcap",
            "/tmp/telecom/pcap"
        ]
        
        # Production Linux directory paths for HDF files
        self.HDF_DIRS: List[str] = [
            "/var/log/telecom/hdf",
            "/opt/telecom/hdf",
            "/data/telecom/hdf",
            "/home/telecom/hdf", 
            "/usr/local/telecom/hdf",
            "/tmp/telecom/hdf"
        ]
        
        # Production model storage directory
        self.MODEL_DIR: str = "/var/lib/telecom/models"
        
        # Production logging configuration
        self.LOG_LEVEL: str = "INFO"
        self.LOG_FILE: str = "/var/log/telecom/telecom_anomaly_detection.log"
        
        # Isolation Forest parameters
        self.CONTAMINATION_RATE: float = 0.1  # Expect 10% anomalies
        self.N_ESTIMATORS: int = 100
        self.RANDOM_STATE: int = 42
        
        # Anomaly detection thresholds
        self.UNIDIRECTIONAL_THRESHOLD: float = 0.95  # 95% unidirectional is anomaly
        self.PLANE_IMBALANCE_THRESHOLD: float = 0.1   # <10% of either plane is anomaly
        self.UE_RATIO_THRESHOLD: float = 0.2          # <20% or >80% attach ratio is anomaly
        self.RAPID_CYCLE_THRESHOLD: int = 10          # >10 cycles per minute is anomaly
        
        # Import telecom standards from base config
        from config import Config
        base_config = Config()
        self.PROTOCOL_PORTS = base_config.PROTOCOL_PORTS
        self.RU_MAC_PATTERNS = base_config.RU_MAC_PATTERNS
        self.DU_MAC_PATTERNS = base_config.DU_MAC_PATTERNS
        
        # Processing configuration
        self.BATCH_SIZE: int = 1000
        self.PARALLEL_PROCESSING: bool = True
        self.MAX_WORKERS: int = 4
        
        # Output formatting
        self.DISPLAY_DETAILED_STATS: bool = True
        self.SAVE_RESULTS_TO_FILE: bool = True
        self.RESULTS_OUTPUT_DIR: str = "/var/log/telecom/results"
        
        # Create necessary directories
        self._create_directories()
    
    def _create_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        directories = [
            self.MODEL_DIR,
            self.RESULTS_OUTPUT_DIR,
            "/var/log/telecom"
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except PermissionError:
                print(f"Warning: Cannot create directory {directory} - permission denied")
            except Exception as e:
                print(f"Warning: Cannot create directory {directory} - {e}")
    
    def get_pcap_directories(self) -> List[str]:
        """Get list of existing PCAP directories."""
        existing_dirs = []
        for directory in self.PCAP_DIRS:
            if os.path.exists(directory):
                existing_dirs.append(directory)
        return existing_dirs
    
    def get_hdf_directories(self) -> List[str]:
        """Get list of existing HDF directories."""
        existing_dirs = []
        for directory in self.HDF_DIRS:
            if os.path.exists(directory):
                existing_dirs.append(directory)
        return existing_dirs
    
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
        return any(mac_upper.startswith(pattern.upper()) for pattern in self.DU_MAC_PATTERNS)
    
    def get_protocol_info(self, port: int) -> dict:
        """Get protocol information based on port number."""
        return self.PROTOCOL_PORTS.get(port, {'protocol': 'unknown', 'plane': 'other'})