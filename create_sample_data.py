#!/usr/bin/env python3
"""
Create sample PCAP and HDF files for testing the telecom anomaly detection system.
This demonstrates the types of anomalies the system can detect.
"""

import os
import numpy as np
import h5py
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
import random
import time

def create_sample_directories():
    """Create sample data directories."""
    os.makedirs("./pcap_files", exist_ok=True)
    os.makedirs("./hdf_files", exist_ok=True)
    print("Created sample data directories")

def create_normal_pcap():
    """Create a normal PCAP file with balanced RU-DU communication."""
    packets = []
    
    # Normal bidirectional RU-DU communication
    for i in range(50):
        # DU to RU (F1-C control plane)
        pkt1 = Ether()/IP(src="192.168.2.10", dst="192.168.1.20")/UDP(sport=38472, dport=38472)/Raw(b"F1-C_CONTROL_DATA")
        packets.append(pkt1)
        
        # RU to DU response
        pkt2 = Ether()/IP(src="192.168.1.20", dst="192.168.2.10")/UDP(sport=38472, dport=38472)/Raw(b"F1-C_RESPONSE")
        packets.append(pkt2)
        
        # DU to RU (F1-U user plane)
        pkt3 = Ether()/IP(src="192.168.2.10", dst="192.168.1.20")/UDP(sport=2152, dport=2152)/Raw(b"F1-U_USER_DATA")
        packets.append(pkt3)
        
        # RU to DU response
        pkt4 = Ether()/IP(src="192.168.1.20", dst="192.168.2.10")/UDP(sport=2152, dport=2152)/Raw(b"F1-U_RESPONSE")
        packets.append(pkt4)
    
    wrpcap("./pcap_files/normal_traffic.pcap", packets)
    print(f"Created normal_traffic.pcap with {len(packets)} packets")

def create_anomalous_pcap_unidirectional():
    """Create PCAP with unidirectional communication anomaly."""
    packets = []
    
    # DU sending to RU but RU not responding (your specific scenario)
    for i in range(100):
        # Only DU to RU traffic, no responses from RU
        pkt1 = Ether()/IP(src="192.168.2.10", dst="192.168.1.20")/UDP(sport=38472, dport=38472)/Raw(b"F1-C_CONTROL_NO_RESPONSE")
        packets.append(pkt1)
        
        pkt2 = Ether()/IP(src="192.168.2.10", dst="192.168.1.20")/UDP(sport=2152, dport=2152)/Raw(b"F1-U_USER_NO_RESPONSE")
        packets.append(pkt2)
    
    wrpcap("./pcap_files/unidirectional_anomaly.pcap", packets)
    print(f"Created unidirectional_anomaly.pcap with {len(packets)} packets")

def create_anomalous_pcap_partial_plane():
    """Create PCAP with partial plane data (only C-plane or only U-plane)."""
    packets = []
    
    # Only Control Plane traffic, missing User Plane
    for i in range(80):
        # DU to RU (only F1-C control plane)
        pkt1 = Ether()/IP(src="192.168.2.10", dst="192.168.1.20")/UDP(sport=38472, dport=38472)/Raw(b"ONLY_CONTROL_PLANE")
        packets.append(pkt1)
        
        # RU to DU response (control plane only)
        pkt2 = Ether()/IP(src="192.168.1.20", dst="192.168.2.10")/UDP(sport=38472, dport=38472)/Raw(b"CONTROL_RESPONSE")
        packets.append(pkt2)
    
    wrpcap("./pcap_files/missing_user_plane.pcap", packets)
    print(f"Created missing_user_plane.pcap with {len(packets)} packets")

def create_sample_hdf_normal():
    """Create normal HDF file with balanced UE events."""
    with h5py.File("./hdf_files/normal_ue_events.hdf5", "w") as f:
        # Create balanced attach/detach events
        num_events = 100
        
        # Attach events
        attach_data = []
        for i in range(num_events//2):
            attach_data.append((f"UE_{i:04d}", int(time.time()) + i, "attach", f"cell_{i%10}", 1))
        
        # Detach events
        detach_data = []
        for i in range(num_events//2):
            detach_data.append((f"UE_{i:04d}", int(time.time()) + i + 1000, "detach", f"cell_{i%10}", 0))
        
        # Create structured datasets
        attach_dtype = np.dtype([
            ('ue_id', 'S20'),
            ('timestamp', 'i8'),
            ('event_type', 'S20'),
            ('cell_id', 'S20'),
            ('status', 'i4')
        ])
        
        detach_dtype = np.dtype([
            ('ue_id', 'S20'),
            ('timestamp', 'i8'),
            ('event_type', 'S20'),
            ('cell_id', 'S20'),
            ('status', 'i4')
        ])
        
        f.create_dataset("attach_events", data=np.array(attach_data, dtype=attach_dtype))
        f.create_dataset("detach_events", data=np.array(detach_data, dtype=detach_dtype))
        
        # Add metadata
        f.attrs['file_type'] = 'UE_Events'
        f.attrs['creation_time'] = str(time.time())
        f.attrs['total_events'] = num_events
    
    print("Created normal_ue_events.hdf5 with balanced attach/detach events")

def create_sample_hdf_anomalous():
    """Create anomalous HDF file with unbalanced events and rapid cycling."""
    with h5py.File("./hdf_files/anomalous_ue_events.hdf5", "w") as f:
        # Create unbalanced events (many more attaches than detaches)
        attach_data = []
        for i in range(150):  # Many attach events
            attach_data.append((f"UE_{i:04d}", int(time.time()) + i, "attach", f"cell_{i%5}", 1))
        
        detach_data = []
        for i in range(20):   # Few detach events
            detach_data.append((f"UE_{i:04d}", int(time.time()) + i + 2000, "detach", f"cell_{i%5}", 0))
        
        # Add rapid cycling UE (same UE attaching/detaching multiple times)
        rapid_ue_id = "UE_RAPID_CYCLE"
        for i in range(10):
            attach_data.append((rapid_ue_id, int(time.time()) + i*60, "attach", "cell_99", 1))
            detach_data.append((rapid_ue_id, int(time.time()) + i*60 + 30, "detach", "cell_99", 0))
        
        attach_dtype = np.dtype([
            ('ue_id', 'U20'),
            ('timestamp', 'i8'),
            ('event_type', 'U10'),
            ('cell_id', 'U10'),
            ('status', 'i4')
        ])
        
        detach_dtype = np.dtype([
            ('ue_id', 'U20'),
            ('timestamp', 'i8'),
            ('event_type', 'U10'),
            ('cell_id', 'U10'),
            ('status', 'i4')
        ])
        
        f.create_dataset("attach_events", data=np.array(attach_data, dtype=attach_dtype))
        f.create_dataset("detach_events", data=np.array(detach_data, dtype=detach_dtype))
        
        f.attrs['file_type'] = 'UE_Events_Anomalous'
        f.attrs['creation_time'] = str(time.time())
        f.attrs['total_events'] = len(attach_data) + len(detach_data)
    
    print("Created anomalous_ue_events.hdf5 with unbalanced events and rapid cycling")

if __name__ == "__main__":
    print("Creating sample data for telecom anomaly detection testing...")
    
    create_sample_directories()
    
    # Create PCAP files
    create_normal_pcap()
    create_anomalous_pcap_unidirectional()
    create_anomalous_pcap_partial_plane()
    
    # Create HDF files
    create_sample_hdf_normal()
    create_sample_hdf_anomalous()
    
    print("\nSample data creation completed!")
    print("Files created:")
    print("  PCAP files:")
    print("    - ./pcap_files/normal_traffic.pcap")
    print("    - ./pcap_files/unidirectional_anomaly.pcap")
    print("    - ./pcap_files/missing_user_plane.pcap")
    print("  HDF files:")
    print("    - ./hdf_files/normal_ue_events.hdf5")
    print("    - ./hdf_files/anomalous_ue_events.hdf5")