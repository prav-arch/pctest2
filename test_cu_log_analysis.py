#!/usr/bin/env python3
"""
Test script for CU log analysis functionality.
Demonstrates anomaly detection in Central Unit log files.
"""

import os
import sys
from telecom_anomaly_detector import TelecomAnomalyDetector

def test_cu_log_analysis():
    """Test CU log analysis with sample log file."""
    print("Testing CU Log Analysis Functionality")
    print("=" * 50)
    
    # Initialize detector with mixed data folder
    detector = TelecomAnomalyDetector(input_folder="mixed_data_folder")
    
    # Test individual CU log file analysis
    log_file = "mixed_data_folder/sample_cu_log.txt"
    
    if os.path.exists(log_file):
        print(f"\nAnalyzing CU log file: {log_file}")
        result = detector.analyze_cu_log_file(log_file)
        
        if 'error' in result:
            print(f"Error: {result['error']}")
            return
        
        print(f"\nCU Log Analysis Results:")
        print(f"File: {result['file']}")
        print(f"Type: {result['type']}")
        print(f"Total Lines: {result['total_lines']}")
        
        # Display error analysis
        if 'error_analysis' in result:
            print(f"\nError Analysis:")
            for error_type, count in result['error_analysis'].items():
                if count > 0:
                    print(f"  {error_type.replace('_', ' ').title()}: {count}")
        
        # Display log level analysis
        if 'log_level_analysis' in result:
            print(f"\nLog Level Distribution:")
            for level, count in result['log_level_analysis'].items():
                if count > 0:
                    print(f"  {level}: {count}")
        
        # Display detected anomalies
        if 'anomalies' in result and result['anomalies']:
            print(f"\nDetected Anomalies: {len(result['anomalies'])}")
            for i, anomaly in enumerate(result['anomalies'], 1):
                print(f"\n  {i}. [{anomaly.get('severity', 'UNKNOWN')}] {anomaly.get('type', 'unknown')}")
                print(f"     Description: {anomaly.get('description', 'No description')}")
                
                # Show severity classification if available
                if 'severity_level' in anomaly:
                    print(f"     Severity Level: {anomaly['severity_level']}")
                    print(f"     Priority Score: {anomaly.get('priority_score', 0):.3f}")
                    print(f"     Impact: {anomaly.get('impact_description', 'Unknown')}")
                    print(f"     Response Time: {anomaly.get('response_time', 'Unknown')}")
                    if anomaly.get('escalation_required', False):
                        print(f"     ESCALATION REQUIRED")
        else:
            print("\nNo anomalies detected in CU log")
        
        # Display sample errors
        if 'sample_errors' in result and result['sample_errors']:
            print(f"\nSample Error Messages:")
            for i, error in enumerate(result['sample_errors'][:5], 1):
                print(f"  {i}. Line {error['line_number']}: {error['error_type'].replace('_', ' ').title()}")
                print(f"     Message: {error['message']}")
        
        # Display extracted features
        print(f"\nExtracted Features: {len(result['features'])} features")
        print(f"Feature Vector: {result['features'][:10]}..." if len(result['features']) > 10 else f"Feature Vector: {result['features']}")
    
    else:
        print(f"Sample CU log file not found: {log_file}")

def test_mixed_folder_analysis():
    """Test analysis of mixed data folder with all file types."""
    print("\n\nTesting Mixed Folder Analysis")
    print("=" * 50)
    
    # Initialize detector
    detector = TelecomAnomalyDetector(input_folder="mixed_data_folder")
    
    # Run complete analysis
    print("Running complete analysis on mixed data folder...")
    detector.process_all_files()

if __name__ == "__main__":
    try:
        test_cu_log_analysis()
        test_mixed_folder_analysis()
        print("\n\nCU log analysis testing completed successfully!")
        
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)