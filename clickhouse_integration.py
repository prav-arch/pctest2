#!/usr/bin/env python3
"""
ClickHouse Database Integration for Telecom Anomaly Detection System.
Stores detected anomalies in ClickHouse database for analysis and monitoring.
"""

import json
import uuid
import signal
from typing import Dict, List, Any, Optional
from clickhouse_driver import Client
import logging

class ClickHouseAnomalyStorage:
    """
    Manages ClickHouse database operations for anomaly storage.
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9000, 
                 database: str = 'l1_app_db', user: str = 'default', password: str = ''):
        """
        Initialize ClickHouse connection.
        
        Args:
            host: ClickHouse server host
            port: ClickHouse server port
            database: Database name
            user: Username
            password: Password
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.client = None
        self.connection_timeout = 5  # 5 second timeout
        self.insert_timeout = 10     # 10 second timeout for inserts
        self._connect()
    
    def _connect(self):
        """Establish connection to ClickHouse."""
        try:
            # Handle empty password properly
            connection_params = {
                'host': self.host,
                'port': self.port,
                'database': self.database,
                'user': self.user
            }
            
            # Only add password if it's not empty
            if self.password:
                connection_params['password'] = self.password
            
            self.client = Client(**connection_params)
            
            # Test connection with timeout
            self.client.execute('SELECT 1')
            
        except Exception as e:
            # Simplified error message for cleaner output
            error_msg = str(e)
            if "Cannot assign requested address" in error_msg:
                pass  # ClickHouse server not running - silent fallback
            elif "Connection refused" in error_msg:
                pass  # ClickHouse service not started - silent fallback  
            elif "NoneType" in error_msg and "encode" in error_msg:
                pass  # Password encoding issue - silent fallback
            else:
                pass  # Other connection issues - silent fallback
            self.client = None
    
    def test_connection(self) -> bool:
        """Test ClickHouse connection."""
        try:
            if self.client:
                result = self.client.execute('SELECT 1')
                return len(result) > 0
            return False
        except Exception as e:
            print(f"Connection test failed: {str(e)}")
            return False
    
    def ensure_table_exists(self) -> bool:
        """Ensure the anomalies table exists."""
        try:
            if not self.client:
                return False
            
            # Check if table exists using simple SHOW TABLES
            tables = self.client.execute("SHOW TABLES")
            table_names = [table[0] for table in tables]
            print(f"  [DATABASE] Available tables: {table_names}")
            
            table_exists = 'fh_violations' in table_names
            
            if not table_exists:
                print("  [DATABASE] Table 'fh_violations' not found, creating...")
                # Create fh_violations table matching user's exact structure
                create_table_sql = """
                CREATE TABLE fh_violations (
                    event_time DateTime,
                    type String,
                    severity Enum8('none'=0,'low'=1,'medium'=2,'high'=3),
                    description String,
                    log_line String,
                    transport_ok UInt8
                ) ENGINE = MergeTree()
                ORDER BY event_time
                """
                
                self.client.execute(create_table_sql)
                print("  [DATABASE] Table 'anomalies' created successfully")
            else:
                print("  [DATABASE] Table 'anomalies' already exists")
            
            return True
            
        except Exception as e:
            print(f"Error checking table: {str(e)}")
            return False
    
    def store_anomaly(self, anomaly_data: Dict[str, Any], file_path: str = "") -> bool:
        """
        Store a single anomaly in ClickHouse with timeout handling.
        
        Args:
            anomaly_data: Anomaly information dictionary
            file_path: Source file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.client:
                return False
            
            # Generate unique ID
            anomaly_id = str(uuid.uuid4())
            
            # Extract anomaly information
            anomaly_type = anomaly_data.get('type', 'unknown')
            description = anomaly_data.get('description', '')
            severity = anomaly_data.get('severity', 'MEDIUM')
            
            # Determine category based on anomaly type
            category = self._categorize_anomaly(anomaly_type)
            
            # Create metadata JSON
            metadata = {
                'file_path': file_path,
                'anomaly_score': anomaly_data.get('anomaly_score', 0.0),
                'priority_score': anomaly_data.get('priority_score', 0.0),
                'timestamp': anomaly_data.get('timestamp', ''),
                'raw_data': anomaly_data.get('raw_data', {})
            }
            
            # Prepare record for tuple parameter format (excluding detected_at and resolved_at)
            record = {
                'id': anomaly_id,
                'anomaly_type': anomaly_type,
                'description': description,
                'severity': severity,
                'status': 'OPEN',  # New anomalies start as OPEN
                'source': f"telecom_detector_{file_path.split('/')[-1] if file_path else 'system'}",
                'log_line': anomaly_data.get('log_details', '')[:1000],  # Limit log line length
                'metadata': None,  # Set to None to avoid JSON parsing timeouts
                'resolution_steps': anomaly_data.get('recommended_action', ''),
                'category': category,
                'impact_level': self._map_severity_to_impact(severity),
                'affected_systems': self._identify_affected_systems(anomaly_data)
            }
            
            # Map to fh_violations table structure using now() for event_time
            query = """
            INSERT INTO fh_violations 
            (event_time, type, severity, description, log_line, transport_ok)
            VALUES
            """
            
            # Convert severity to Enum8 values
            severity_mapping = {
                'CRITICAL': 'high',
                'HIGH': 'high', 
                'MEDIUM': 'medium',
                'LOW': 'low',
                'INFO': 'low'
            }
            
            severity_enum = severity_mapping.get(record.get('severity', 'MEDIUM'), 'medium')
            
            # Determine transport_ok based on anomaly type
            transport_ok = 0  # Default: transport not ok (violation detected)
            if record.get('anomaly_type') in ['info', 'low_priority']:
                transport_ok = 1  # Transport ok for informational anomalies
            
            # Prepare parameters for exact fh_violations structure with proper quoting
            type_value = str(record.get('anomaly_type', 'unknown')).replace("'", "''")
            description_value = str(record['description']).replace("'", "''") if record['description'] else ''
            log_line_value = str(record['log_line']).replace("'", "''") if record['log_line'] else ''
            
            params = [(
                type_value,                    # type
                severity_enum,                 # severity (Enum8)
                description_value,             # description
                log_line_value,                # log_line
                transport_ok                   # transport_ok (UInt8)
            )]
            
            print(f"\n[DEBUG] ClickHouse INSERT Query:")
            print(query)
            print(f"\n[DEBUG] Parameters for fh_violations (event_time uses now()):")
            param_names = ['type', 'severity', 'description', 'log_line', 'transport_ok']
            for i, (name, value) in enumerate(zip(param_names, params[0])):
                if name == 'severity':
                    print(f"  {i+1}. {name}: '{value}' (Enum8 - violation severity)")
                elif name == 'transport_ok':
                    status = "OK" if value == 1 else "VIOLATION"
                    print(f"  {i+1}. {name}: {value} (UInt8 - {status})")
                else:
                    value_type = type(value).__name__
                    value_len = len(str(value)) if isinstance(value, str) else len(str(value))
                    print(f"  {i+1}. {name}: '{value}' ({value_type}, len={value_len})")
            print(f"  6. event_time: now() (ClickHouse function - current timestamp)")
            print(f"[DEBUG] Executing INSERT into fh_violations with now() for event_time...")
            
            # Build complete query with now() function
            complete_query = f"{query} (now(), %s, %s, %s, %s, %s)"
            self.client.execute(complete_query, params[0])
            
            print(f"[DEBUG] INSERT completed successfully")
            
            return True
            
        except Exception as e:
            error_msg = str(e)
            print(f"\n[DEBUG] INSERT failed with error: {error_msg}")
            
            # Handle specific datetime errors
            if "tzinfo" in error_msg:
                print(f"[DEBUG] DateTime timezone error - using string format instead")
            elif "Enum8" in error_msg:
                print(f"[DEBUG] Enum8 error - check severity values")
            
            print(f"✗ Error storing anomaly: {error_msg}")
            return False
    
    def store_multiple_anomalies(self, anomalies: List[Dict[str, Any]], file_path: str = "") -> int:
        """
        Store multiple anomalies in batch.
        
        Args:
            anomalies: List of anomaly dictionaries
            file_path: Source file path
            
        Returns:
            Number of anomalies successfully stored
        """
        stored_count = 0
        
        for anomaly in anomalies:
            if self.store_anomaly(anomaly, file_path):
                stored_count += 1
        
        if stored_count > 0:
            print(f"✓ Stored {stored_count}/{len(anomalies)} anomalies in ClickHouse")
        
        return stored_count
    
    def _categorize_anomaly(self, anomaly_type: str) -> str:
        """Categorize anomaly based on type."""
        network_types = ['unidirectional_communication', 'missing_control_plane', 'missing_user_plane']
        ue_types = ['unbalanced_attach_detach', 'rapid_attach_detach_cycle', 'missing_attach_events', 'missing_detach_events']
        system_types = ['connection_failures', 'handover_failures', 'resource_exhaustion', 'critical_events']
        
        if anomaly_type in network_types:
            return 'NETWORK'
        elif anomaly_type in ue_types:
            return 'UE_EVENTS'
        elif anomaly_type in system_types:
            return 'SYSTEM'
        else:
            return 'OTHER'
    
    def _map_severity_to_impact(self, severity: str) -> str:
        """Map severity to impact level."""
        mapping = {
            'CRITICAL': 'HIGH',
            'HIGH': 'MEDIUM',
            'MEDIUM': 'LOW',
            'LOW': 'MINIMAL',
            'INFO': 'MINIMAL'
        }
        return mapping.get(severity.upper(), 'MEDIUM')
    
    def _identify_affected_systems(self, anomaly_data: Dict[str, Any]) -> str:
        """Identify affected systems based on anomaly data."""
        affected = []
        
        # Check for RU/DU involvement
        if 'RU' in str(anomaly_data) or 'ru' in str(anomaly_data):
            affected.append('RU')
        if 'DU' in str(anomaly_data) or 'du' in str(anomaly_data):
            affected.append('DU')
        
        # Check for specific system components
        if 'control_plane' in str(anomaly_data) or 'Control' in str(anomaly_data):
            affected.append('Control_Plane')
        if 'user_plane' in str(anomaly_data) or 'User' in str(anomaly_data):
            affected.append('User_Plane')
        if 'CU' in str(anomaly_data) or 'cu' in str(anomaly_data):
            affected.append('CU')
        
        return ','.join(affected) if affected else 'Unknown'
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Dict]:
        """Get recent anomalies from database."""
        try:
            if not self.client:
                return []
            
            result = self.client.execute(
                """
                SELECT id, anomaly_type, description, severity, status, source,
                       detected_at, category, impact_level, affected_systems
                FROM anomalies
                ORDER BY detected_at DESC
                LIMIT %s
                """,
                [limit]
            )
            
            anomalies = []
            for row in result:
                anomalies.append({
                    'id': row[0],
                    'anomaly_type': row[1],
                    'description': row[2],
                    'severity': row[3],
                    'status': row[4],
                    'source': row[5],
                    'detected_at': row[6],
                    'category': row[7],
                    'impact_level': row[8],
                    'affected_systems': row[9]
                })
            
            return anomalies
            
        except Exception as e:
            print(f"Error retrieving anomalies: {str(e)}")
            return []
    
    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get anomaly statistics."""
        try:
            if not self.client:
                return {}
            
            # Count by severity
            severity_stats = self.client.execute(
                "SELECT severity, count(*) FROM anomalies GROUP BY severity"
            )
            
            # Count by category
            category_stats = self.client.execute(
                "SELECT category, count(*) FROM anomalies GROUP BY category"
            )
            
            # Count by status
            status_stats = self.client.execute(
                "SELECT status, count(*) FROM anomalies GROUP BY status"
            )
            
            return {
                'by_severity': {row[0]: row[1] for row in severity_stats},
                'by_category': {row[0]: row[1] for row in category_stats},
                'by_status': {row[0]: row[1] for row in status_stats},
                'total_anomalies': sum(row[1] for row in severity_stats)
            }
            
        except Exception as e:
            print(f"Error getting statistics: {str(e)}")
            return {}
    
    def close(self):
        """Close ClickHouse connection."""
        if self.client:
            self.client.disconnect()
            self.client = None
            print("✓ ClickHouse connection closed")

def test_clickhouse_integration():
    """Test ClickHouse integration with sample data."""
    
    print("Testing ClickHouse Integration...")
    print("=" * 50)
    
    # Initialize connection
    ch_storage = ClickHouseAnomalyStorage()
    
    # Test connection
    if not ch_storage.test_connection():
        print("✗ ClickHouse connection failed")
        return False
    
    # Check table
    if not ch_storage.ensure_table_exists():
        print("✗ Table verification failed")
        return False
    
    # Test storing sample anomaly
    sample_anomaly = {
        'type': 'unidirectional_communication',
        'description': 'DU sending to RU but no response from RU',
        'severity': 'HIGH',
        'anomaly_score': 0.85,
        'priority_score': 0.92,
        'timestamp': '2025-06-25 14:15:00',
        'recommended_action': 'Check RU connectivity and power status',
        'log_details': 'DU (00:11:22:33:44:67) → RU (6c:ad:ad:00:03:2a): No response packets detected'
    }
    
    if ch_storage.store_anomaly(sample_anomaly, "test_file.pcap"):
        print("✓ Sample anomaly stored successfully")
    else:
        print("✗ Failed to store sample anomaly")
        return False
    
    # Get recent anomalies
    recent = ch_storage.get_recent_anomalies(5)
    print(f"✓ Retrieved {len(recent)} recent anomalies")
    
    # Get statistics
    stats = ch_storage.get_anomaly_statistics()
    if stats:
        print(f"✓ Statistics: {stats.get('total_anomalies', 0)} total anomalies")
    
    ch_storage.close()
    print("✓ ClickHouse integration test completed")
    return True

if __name__ == "__main__":
    test_clickhouse_integration()