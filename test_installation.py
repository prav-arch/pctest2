#!/usr/bin/env python3
# Test script to verify installation

import sys
import importlib

def test_installation():
    print("Testing Telecom Anomaly Detection Installation")
    print("=" * 50)
    
    # Test imports
    modules = ['scapy', 'h5py', 'sklearn', 'numpy', 'pandas', 'streamlit']
    failed = []
    
    for module in modules:
        try:
            importlib.import_module(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module}")
            failed.append(module)
    
    if failed:
        print(f"\nFailed imports: {', '.join(failed)}")
        print("Run: pip install " + ' '.join(failed))
        return False
    
    # Test main modules
    try:
        from telecom_anomaly_detector import TelecomAnomalyDetector
        print("✓ Main detection engine")
        
        from config import Config
        config = Config()
        print(f"✓ Configuration (RU: {config.RU_MAC_ADDRESSES[0][:8]}...)")
        
        print("\n✓ All tests passed!")
        print("System ready for production use.")
        return True
        
    except Exception as e:
        print(f"✗ System test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_installation()
    sys.exit(0 if success else 1)
