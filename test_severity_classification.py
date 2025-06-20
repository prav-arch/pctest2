#!/usr/bin/env python3
"""
Comprehensive test suite for the severity classification system.
Creates various types of anomalies to demonstrate all severity levels.
"""

import os
from scapy.all import *
import h5py
import numpy as np
from datetime import datetime

def create_test_data_for_severity_testing():
    """Create comprehensive test data to demonstrate all severity levels."""
    print("Creating comprehensive test data for severity classification...")
    
    # Create directories
    os.makedirs("./pcap_files", exist_ok=True)
    os.makedirs("./hdf_files", exist_ok=True)
    
    # 1. CRITICAL severity: Complete network failure
    create_critical_network_failure()
    
    # 2. HIGH severity: Unidirectional communication
    create_high_severity_unidirectional()
    
    # 3. MEDIUM severity: Missing user plane
    create_medium_severity_missing_plane()
    
    # 4. LOW severity: Minor protocol deviations
    create_low_severity_protocol_deviation()
    
    # 5. Create various HDF anomalies
    create_severity_test_hdf_files()
    
    print("All severity test data created successfully!")

def create_critical_network_failure():
    """Create PCAP with complete network failure scenario."""
    print("Creating CRITICAL severity test data...")
    
    packets = []
    du_mac = "00:11:22:33:44:67"
    ru_mac = "AA:BB:CC:DD:EE:FF"
    
    # Create only DU packets with no RU responses (complete failure)
    for i in range(50):
        packet = Ether(src=du_mac, dst=ru_mac) / \
                IP(src="192.168.2.10", dst="192.168.1.20") / \
                UDP(sport=38472, dport=38472) / \
                Raw(b"F1-C Control Data - NO RESPONSE")
        
        packet.time = 1734700000.0 + i * 0.1  # Faster intervals
        packets.append(packet)
    
    wrpcap("./pcap_files/critical_network_failure.pcap", packets)
    print("  → Critical network failure PCAP created")

def create_high_severity_unidirectional():
    """Create HIGH severity unidirectional communication."""
    print("Creating HIGH severity test data...")
    
    packets = []
    du_mac = "00:11:22:33:44:66"
    ru_mac = "AA:BB:CC:DD:EE:11"
    
    # Create mostly DU packets with very few RU responses
    for i in range(100):
        if i < 95:  # 95% DU packets
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=38472 if i % 2 == 0 else 2152, 
                        dport=38472 if i % 2 == 0 else 2152) / \
                    Raw(b"F1 Data - Mostly Unidirectional")
        else:  # 5% RU responses
            packet = Ether(src=ru_mac, dst=du_mac) / \
                    IP(src="192.168.1.20", dst="192.168.2.10") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1 Response - Rare")
        
        packet.time = 1734700000.0 + i * 0.01
        packets.append(packet)
    
    wrpcap("./pcap_files/high_severity_unidirectional.pcap", packets)
    print("  → High severity unidirectional PCAP created")

def create_medium_severity_missing_plane():
    """Create MEDIUM severity missing plane data."""
    print("Creating MEDIUM severity test data...")
    
    packets = []
    du_mac = "00:11:22:33:44:67"
    ru_mac = "88:99:AA:BB:CC:DD"
    
    # Create only control plane traffic (missing user plane)
    for i in range(80):
        if i % 2 == 0:
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Only")
        else:
            packet = Ether(src=ru_mac, dst=du_mac) / \
                    IP(src="192.168.1.20", dst="192.168.2.10") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Response")
        
        packet.time = 1734700000.0 + i * 0.05
        packets.append(packet)
    
    wrpcap("./pcap_files/medium_severity_missing_plane.pcap", packets)
    print("  → Medium severity missing plane PCAP created")

def create_low_severity_protocol_deviation():
    """Create LOW severity protocol deviation."""
    print("Creating LOW severity test data...")
    
    packets = []
    du_mac = "00:11:22:33:44:66"
    ru_mac = "44:55:66:77:88:99"
    
    # Create mostly normal traffic with some unknown protocols
    for i in range(60):
        if i < 45:  # 75% normal traffic
            if i % 2 == 0:
                packet = Ether(src=du_mac, dst=ru_mac) / \
                        IP(src="192.168.2.10", dst="192.168.1.20") / \
                        UDP(sport=38472, dport=38472) / \
                        Raw(b"Normal F1-C")
            else:
                packet = Ether(src=ru_mac, dst=du_mac) / \
                        IP(src="192.168.1.20", dst="192.168.2.10") / \
                        UDP(sport=2152, dport=2152) / \
                        Raw(b"Normal F1-U")
        else:  # 25% unknown protocol
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=9999, dport=9999) / \
                    Raw(b"Unknown Protocol")
        
        packet.time = 1734700000.0 + i * 0.02
        packets.append(packet)
    
    wrpcap("./pcap_files/low_severity_protocol_deviation.pcap", packets)
    print("  → Low severity protocol deviation PCAP created")

def create_severity_test_hdf_files():
    """Create HDF files to test different severity levels."""
    print("Creating HDF files for severity testing...")
    
    # CRITICAL: Rapid UE cycling
    create_critical_hdf()
    
    # HIGH: Severely unbalanced attach/detach
    create_high_hdf()
    
    # MEDIUM: Moderately unbalanced events
    create_medium_hdf()
    
    # LOW: Minor imbalances
    create_low_hdf()

def create_critical_hdf():
    """Create CRITICAL severity HDF with rapid UE cycling."""
    with h5py.File('./hdf_files/critical_ue_cycling.hdf5', 'w') as f:
        # Create rapid cycling for UE_001
        attach_data = []
        detach_data = []
        
        base_time = 1734700000.0
        
        # UE_001 cycles rapidly (attach/detach every 30 seconds)
        for i in range(12):  # 12 cycles in 6 minutes
            attach_data.append([f"UE_001", "cell_1", base_time + i * 30, 1])
            detach_data.append([f"UE_001", "cell_1", base_time + i * 30 + 15, 0])
        
        # Add a few normal UEs
        for i in range(3):
            attach_data.append([f"UE_00{i+2}", f"cell_{i+1}", base_time + i * 300, 1])
        
        attach_array = np.array(attach_data, dtype=object)
        detach_array = np.array(detach_data, dtype=object)
        
        f.create_dataset('ue_attach_events', data=attach_array)
        f.create_dataset('ue_detach_events', data=detach_array)
    
    print("  → Critical UE cycling HDF created")

def create_high_hdf():
    """Create HIGH severity HDF with severe imbalance."""
    with h5py.File('./hdf_files/high_severity_imbalance.hdf5', 'w') as f:
        attach_data = []
        detach_data = []
        
        base_time = 1734700000.0
        
        # 20 attach events, only 1 detach event (95% imbalance)
        for i in range(20):
            attach_data.append([f"UE_{i:03d}", f"cell_{i%3+1}", base_time + i * 60, 1])
        
        # Only one detach
        detach_data.append(["UE_000", "cell_1", base_time + 1200, 0])
        
        attach_array = np.array(attach_data, dtype=object)
        detach_array = np.array(detach_data, dtype=object)
        
        f.create_dataset('ue_attach_events', data=attach_array)
        f.create_dataset('ue_detach_events', data=detach_array)
    
    print("  → High severity imbalance HDF created")

def create_medium_hdf():
    """Create MEDIUM severity HDF with moderate imbalance."""
    with h5py.File('./hdf_files/medium_severity_imbalance.hdf5', 'w') as f:
        attach_data = []
        detach_data = []
        
        base_time = 1734700000.0
        
        # 12 attach events, 4 detach events (75%/25% ratio)
        for i in range(12):
            attach_data.append([f"UE_{i:03d}", f"cell_{i%2+1}", base_time + i * 120, 1])
        
        for i in range(4):
            detach_data.append([f"UE_{i:03d}", f"cell_{i%2+1}", base_time + i * 300 + 600, 0])
        
        attach_array = np.array(attach_data, dtype=object)
        detach_array = np.array(detach_data, dtype=object)
        
        f.create_dataset('ue_attach_events', data=attach_array)
        f.create_dataset('ue_detach_events', data=detach_array)
    
    print("  → Medium severity imbalance HDF created")

def create_low_hdf():
    """Create LOW severity HDF with minor imbalance."""
    with h5py.File('./hdf_files/low_severity_imbalance.hdf5', 'w') as f:
        attach_data = []
        detach_data = []
        
        base_time = 1734700000.0
        
        # 8 attach events, 5 detach events (62%/38% ratio - minor imbalance)
        for i in range(8):
            attach_data.append([f"UE_{i:03d}", f"cell_{i%3+1}", base_time + i * 150, 1])
        
        for i in range(5):
            detach_data.append([f"UE_{i:03d}", f"cell_{i%3+1}", base_time + i * 240 + 300, 0])
        
        attach_array = np.array(attach_data, dtype=object)
        detach_array = np.array(detach_data, dtype=object)
        
        f.create_dataset('ue_attach_events', data=attach_array)
        f.create_dataset('ue_detach_events', data=detach_array)
    
    print("  → Low severity imbalance HDF created")

def clean_existing_test_files():
    """Clean existing test files to ensure clean testing."""
    print("Cleaning existing test files...")
    
    # Move existing anomaly files
    test_files = [
        "unidirectional_mac_anomaly.pcap",
        "missing_plane_mac_anomaly.pcap",
        "normal_mac_traffic.pcap"
    ]
    
    for file in test_files:
        file_path = f"./pcap_files/{file}"
        backup_path = f"./pcap_files/{file}.backup"
        if os.path.exists(file_path):
            os.rename(file_path, backup_path)
    
    print("  → Existing files backed up")

def main():
    """Create comprehensive severity classification test data."""
    print("=" * 60)
    print("SEVERITY CLASSIFICATION TEST DATA GENERATOR")
    print("=" * 60)
    
    clean_existing_test_files()
    create_test_data_for_severity_testing()
    
    print("\n" + "=" * 60)
    print("TEST DATA CREATION COMPLETE")
    print("=" * 60)
    print("Files created for severity testing:")
    print("PCAP Files:")
    print("  - critical_network_failure.pcap (CRITICAL)")
    print("  - high_severity_unidirectional.pcap (HIGH)")
    print("  - medium_severity_missing_plane.pcap (MEDIUM)")
    print("  - low_severity_protocol_deviation.pcap (LOW)")
    print("\nHDF Files:")
    print("  - critical_ue_cycling.hdf5 (CRITICAL)")
    print("  - high_severity_imbalance.hdf5 (HIGH)")
    print("  - medium_severity_imbalance.hdf5 (MEDIUM)")
    print("  - low_severity_imbalance.hdf5 (LOW)")
    print("\nRun 'python3 telecom_anomaly_detector.py' to test severity classification")

if __name__ == "__main__":
    main()