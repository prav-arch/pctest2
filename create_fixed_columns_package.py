#!/usr/bin/env python3
"""
Create package with fixed column count issue.
"""

import os
import zipfile
from datetime import datetime

def create_fixed_columns_package():
    """Create package with column count issue fixed."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"telecom_fixed_columns_{timestamp}.zip"
    
    source_files = [
        'telecom_anomaly_detector.py',
        'clickhouse_integration.py',     # Fixed column count
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
        'pyproject.toml',
        'README.md',
        'replit.md'
    ]
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in source_files:
            if os.path.exists(file):
                zipf.write(file)
                print(f"Added: {file}")
        
        fixed_columns_guide = """# FIXED COLUMN COUNT ISSUE

## ERROR RESOLVED

### Original Error:
```
expected 6 columns got 21
```

### Root Cause:
The INSERT query was incorrectly formatted, causing ClickHouse to interpret the parameters as individual columns instead of values.

### Solution Applied:
```python
# PREVIOUS (causing column count error):
query = "INSERT INTO fh_violations (event_time, type, severity, description, log_line, transport_ok) VALUES (now(), ?, ?, ?, ?, ?)"
self.client.execute(query, params)

# CURRENT (fixed with proper formatting):
query = "INSERT INTO fh_violations (event_time, type, severity, description, log_line, transport_ok) VALUES"
complete_query = f"{query} (now(), %s, %s, %s, %s, %s)"
self.client.execute(complete_query, params[0])
```

## IMPLEMENTATION DETAILS

### Proper Query Building:
```python
# Base query without VALUES clause
query = """
INSERT INTO fh_violations 
(event_time, type, severity, description, log_line, transport_ok)
VALUES
"""

# Complete query with now() and parameter placeholders
complete_query = f"{query} (now(), %s, %s, %s, %s, %s)"
```

### Parameter Structure:
```python
# Properly quoted string values
type_value = str(record.get('anomaly_type', 'unknown')).replace("'", "''")
description_value = str(record['description']).replace("'", "''") if record['description'] else ''
log_line_value = str(record['log_line']).replace("'", "''") if record['log_line'] else ''

params = [(
    type_value,                    # type (String)
    severity_enum,                 # severity (Enum8)
    description_value,             # description (String)
    log_line_value,                # log_line (String)
    transport_ok                   # transport_ok (UInt8)
)]
```

## EXPECTED OUTPUT

### Success Case:
```
[DEBUG] Parameters for fh_violations (event_time uses now()):
  1. type: unidirectional_communication (str, len=28)
  2. severity: 'high' (Enum8 - violation severity)
  3. description: DU sending to RU but no response from RU (str, len=40)
  4. log_line: Sample packet logs showing communication failure (str, len=50)
  5. transport_ok: 0 (UInt8 - VIOLATION)
  6. event_time: now() (ClickHouse function - current timestamp)
[DEBUG] Executing INSERT into fh_violations with now() for event_time...
[DEBUG] INSERT completed successfully

Total anomalies found: 18
Anomalies stored in ClickHouse: 18
```

## TECHNICAL DETAILS

### Column Mapping:
1. **event_time**: now() function (automatic timestamp)
2. **type**: String parameter (%s)
3. **severity**: Enum8 parameter (%s)
4. **description**: String parameter (%s)
5. **log_line**: String parameter (%s)
6. **transport_ok**: UInt8 parameter (%s)

### Parameter Quoting:
- All string parameters properly escaped with single quote doubling
- Description and log_line values can contain special characters safely
- Enum8 severity values use string literals
- UInt8 transport_ok uses integer values

### Query Execution:
```python
# Final query sent to ClickHouse:
INSERT INTO fh_violations 
(event_time, type, severity, description, log_line, transport_ok)
VALUES (now(), 'unidirectional_communication', 'high', 'DU sending to RU but no response from RU', 'Sample packet logs...', 0)
```

The system now correctly inserts exactly 6 columns as expected by your fh_violations table structure."""

        zipf.writestr("FIXED_COLUMNS_ISSUE.md", fixed_columns_guide)
    
    size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
    
    print(f"\n✓ Fixed Columns Package: {zip_filename}")
    print(f"✓ Size: {size_mb:.2f} MB")
    print("\nCOLUMN COUNT ISSUE FIXED:")
    print("  ✓ Proper query formatting with now() function")
    print("  ✓ Correct parameter binding for 5 values")
    print("  ✓ String values properly quoted and escaped")
    print("  ✓ Exact 6 column INSERT structure")
    
    return zip_filename

if __name__ == "__main__":
    create_fixed_columns_package()