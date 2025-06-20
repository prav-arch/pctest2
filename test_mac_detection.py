#!/usr/bin/env python3
"""
Comprehensive test suite for MAC address-based RU-DU anomaly detection.
Tests various scenarios with user's specific DU MAC addresses.
"""

import os
import sys
from telecom_anomaly_detector import TelecomAnomalyDetector
from config import Config

def test_du_mac_identification():
    """Test DU MAC address identification with specific addresses."""
    print("Testing DU MAC address identification...")
    
    config = Config()
    detector = TelecomAnomalyDetector()
    
    # Test specific DU MAC addresses
    test_cases = [
        ("00:11:22:33:44:67", True, "User's first DU MAC"),
        ("00:11:22:33:44:66", True, "User's second DU MAC"),
        ("00:11:22:33:44:65", True, "DU MAC with pattern match"),
        ("AA:BB:CC:DD:EE:FF", False, "RU MAC address"),
        ("11:22:33:44:55:66", False, "Random MAC address"),
        ("00:11:22:44:44:67", False, "Similar but different MAC"),
    ]
    
    for mac, expected, description in test_cases:
        result = detector._is_du_mac(mac)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {mac} - {description}: {result}")
    
    print()

def test_ru_mac_identification():
    """Test RU MAC address identification with pattern matching."""
    print("Testing RU MAC address identification...")
    
    detector = TelecomAnomalyDetector()
    
    test_cases = [
        ("AA:BB:CC:DD:EE:FF", True, "RU MAC pattern 1"),
        ("44:55:66:77:88:99", True, "RU MAC pattern 2"),
        ("88:99:AA:BB:CC:DD", True, "RU MAC pattern 3"),
        ("00:11:22:33:44:67", False, "DU MAC address"),
        ("FF:EE:DD:CC:BB:AA", False, "Random MAC address"),
    ]
    
    for mac, expected, description in test_cases:
        result = detector._is_ru_mac(mac)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {mac} - {description}: {result}")
    
    print()

def test_ru_du_communication():
    """Test RU-DU communication pattern detection."""
    print("Testing RU-DU communication detection...")
    
    detector = TelecomAnomalyDetector()
    
    test_cases = [
        ("00:11:22:33:44:67", "AA:BB:CC:DD:EE:FF", True, "DU to RU"),
        ("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:67", True, "RU to DU"),
        ("00:11:22:33:44:66", "44:55:66:77:88:99", True, "DU to RU (second DU)"),
        ("11:22:33:44:55:66", "77:88:99:AA:BB:CC", False, "Non-RU-DU communication"),
        ("00:11:22:33:44:67", "00:11:22:33:44:66", False, "DU to DU"),
    ]
    
    for src_mac, dst_mac, expected, description in test_cases:
        result = detector._is_ru_du_communication(src_mac, dst_mac)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {src_mac} → {dst_mac} - {description}: {result}")
    
    print()

def test_file_analysis():
    """Test analysis of MAC-based sample files."""
    print("Testing file analysis with MAC-based data...")
    
    detector = TelecomAnomalyDetector()
    
    # Test files that should exist
    test_files = [
        ("./pcap_files/normal_mac_traffic.pcap", "Normal MAC traffic"),
        ("./pcap_files/unidirectional_mac_anomaly.pcap.bak", "Unidirectional anomaly"),
        ("./pcap_files/missing_plane_mac_anomaly.pcap.bak", "Missing plane anomaly"),
    ]
    
    for file_path, description in test_files:
        if os.path.exists(file_path):
            print(f"  Analyzing {description}...")
            try:
                result = detector.analyze_pcap_file(file_path)
                print(f"    ✓ File analyzed successfully")
                print(f"    → Total packets: {result.get('total_packets', 0)}")
                print(f"    → RU-DU communications: {result.get('ru_du_communications', 0)}")
                print(f"    → Anomalies: {len(result.get('anomalies', []))}")
            except Exception as e:
                print(f"    ✗ Analysis failed: {e}")
        else:
            print(f"  ✗ File not found: {file_path}")
    
    print()

def run_comprehensive_test():
    """Run comprehensive MAC address detection tests."""
    print("=" * 60)
    print("MAC ADDRESS-BASED ANOMALY DETECTION TEST SUITE")
    print("=" * 60)
    print(f"Testing with DU MAC addresses: 00:11:22:33:44:67, 00:11:22:33:44:66")
    print(f"Testing with RU MAC patterns: AA:BB:CC:*, 44:55:66:*, 88:99:AA:*")
    print()
    
    test_du_mac_identification()
    test_ru_mac_identification()
    test_ru_du_communication()
    test_file_analysis()
    
    print("=" * 60)
    print("TEST SUITE COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    run_comprehensive_test()