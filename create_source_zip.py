#!/usr/bin/env python3
"""
Create a zip file containing only the source code files.
"""

import os
import zipfile
from datetime import datetime

def create_source_zip():
    """Create zip file with source code only."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"telecom_source_code_{timestamp}.zip"
    
    # List of source files to include
    source_files = [
        'telecom_anomaly_detector.py',
        'config.py',
        'cu_log_analyzer.py',
        'severity_classifier.py',
        'adaptive_contamination_system.py',
        'production_protocol_mapper.py',
        'utils.py',
        'run_system.py',
        'app.py',
        'suppress_warnings.py',
        'pyproject.toml',
        'README.md',
        'replit.md'
    ]
    
    # Create zip file
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in source_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"Added: {file}")
    
    # Get file size
    size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
    
    print(f"\nCreated: {zip_filename}")
    print(f"Size: {size_mb:.2f} MB")
    print(f"Contains {len(source_files)} source files")
    print("\nRight-click the zip file in file explorer to download")
    
    return zip_filename

if __name__ == "__main__":
    create_source_zip()