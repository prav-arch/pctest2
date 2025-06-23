"""
CU (Central Unit) Log Analyzer for Telecom Anomaly Detection.
Analyzes text log files for CU-specific anomalies and patterns.
"""

import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
from collections import defaultdict, Counter
import logging

class CULogAnalyzer:
    """
    Analyzes CU (Central Unit) log files for telecom anomalies.
    Detects patterns in log messages, error frequencies, and timing anomalies.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # CU-specific log patterns to detect
        self.error_patterns = {
            'connection_failure': [
                r'connection.*failed',
                r'connect.*timeout',
                r'connection.*refused',
                r'link.*down',
                r'interface.*down'
            ],
            'handover_failure': [
                r'handover.*failed',
                r'ho.*failure',
                r'handoff.*error',
                r'mobility.*failed'
            ],
            'resource_exhaustion': [
                r'memory.*full',
                r'cpu.*overload',
                r'resource.*unavailable',
                r'capacity.*exceeded',
                r'buffer.*overflow'
            ],
            'protocol_error': [
                r'protocol.*error',
                r'invalid.*message',
                r'decode.*failed',
                r'parse.*error',
                r'malformed.*packet'
            ],
            'authentication_failure': [
                r'auth.*failed',
                r'authentication.*error',
                r'certificate.*invalid',
                r'security.*violation'
            ],
            'synchronization_loss': [
                r'sync.*lost',
                r'clock.*drift',
                r'timing.*error',
                r'synchronization.*failed'
            ]
        }
        
        # Log level patterns
        self.log_levels = {
            'CRITICAL': r'\b(CRITICAL|FATAL|CRIT)\b',
            'ERROR': r'\b(ERROR|ERR)\b',
            'WARNING': r'\b(WARNING|WARN)\b',
            'INFO': r'\b(INFO)\b',
            'DEBUG': r'\b(DEBUG|DBG)\b'
        }
        
        # Timestamp patterns
        self.timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # YYYY-MM-DD HH:MM:SS
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # MM/DD/YYYY HH:MM:SS
            r'\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}',  # DD-MM-YYYY HH:MM:SS
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',        # Mon DD HH:MM:SS
            r'\d{10}\.\d{3}',                        # Unix timestamp with milliseconds
        ]
    
    def analyze_cu_log_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a CU log file for anomalies.
        
        Args:
            file_path: Path to the CU log file
            
        Returns:
            Analysis results dictionary
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            # Extract basic statistics
            lines = log_content.split('\n')
            total_lines = len(lines)
            
            # Analyze log patterns
            error_analysis = self._analyze_error_patterns(log_content)
            log_level_analysis = self._analyze_log_levels(log_content)
            timestamp_analysis = self._analyze_timestamps(lines)
            frequency_analysis = self._analyze_message_frequency(lines)
            
            # Detect specific CU anomalies
            anomalies = self._detect_cu_anomalies(
                error_analysis, log_level_analysis, 
                timestamp_analysis, frequency_analysis
            )
            
            # Extract features for ML analysis
            features = self._extract_cu_log_features(
                error_analysis, log_level_analysis,
                timestamp_analysis, frequency_analysis, total_lines
            )
            
            return {
                'file': file_path,
                'type': 'CU_LOG',
                'total_lines': total_lines,
                'error_analysis': error_analysis,
                'log_level_analysis': log_level_analysis,
                'timestamp_analysis': timestamp_analysis,
                'frequency_analysis': frequency_analysis,
                'anomalies': anomalies,
                'features': features,
                'sample_errors': self._get_sample_errors(log_content)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing CU log file {file_path}: {str(e)}")
            return {
                'file': file_path,
                'type': 'CU_LOG',
                'error': f"Failed to analyze: {str(e)}"
            }
    
    def _analyze_error_patterns(self, log_content: str) -> Dict[str, int]:
        """Analyze error patterns in log content."""
        error_counts = {}
        
        for error_type, patterns in self.error_patterns.items():
            count = 0
            for pattern in patterns:
                matches = re.findall(pattern, log_content, re.IGNORECASE)
                count += len(matches)
            error_counts[error_type] = count
        
        return error_counts
    
    def _analyze_log_levels(self, log_content: str) -> Dict[str, int]:
        """Analyze distribution of log levels."""
        level_counts = {}
        
        for level, pattern in self.log_levels.items():
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            level_counts[level] = len(matches)
        
        return level_counts
    
    def _analyze_timestamps(self, lines: List[str]) -> Dict[str, Any]:
        """Analyze timestamp patterns and gaps."""
        timestamps = []
        timestamp_gaps = []
        
        for line in lines:
            for pattern in self.timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    timestamp_str = match.group()
                    try:
                        # Try to parse different timestamp formats
                        if re.match(r'\d{4}-\d{2}-\d{2}', timestamp_str):
                            ts = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        elif re.match(r'\d{2}/\d{2}/\d{4}', timestamp_str):
                            ts = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
                        elif re.match(r'\d{2}-\d{2}-\d{4}', timestamp_str):
                            ts = datetime.strptime(timestamp_str, '%d-%m-%Y %H:%M:%S')
                        elif re.match(r'\d{10}\.\d{3}', timestamp_str):
                            ts = datetime.fromtimestamp(float(timestamp_str))
                        else:
                            continue
                        
                        timestamps.append(ts)
                        break
                    except ValueError:
                        continue
        
        # Calculate gaps between timestamps
        if len(timestamps) > 1:
            timestamps.sort()
            for i in range(1, len(timestamps)):
                gap = (timestamps[i] - timestamps[i-1]).total_seconds()
                timestamp_gaps.append(gap)
        
        return {
            'total_timestamps': len(timestamps),
            'timestamp_gaps': timestamp_gaps,
            'average_gap': sum(timestamp_gaps) / len(timestamp_gaps) if timestamp_gaps else 0,
            'max_gap': max(timestamp_gaps) if timestamp_gaps else 0,
            'min_gap': min(timestamp_gaps) if timestamp_gaps else 0
        }
    
    def _analyze_message_frequency(self, lines: List[str]) -> Dict[str, Any]:
        """Analyze message frequency patterns."""
        # Extract message types (simplified)
        message_patterns = []
        
        for line in lines:
            # Extract potential message identifiers
            # Look for patterns like [MSG_TYPE], MSG_ID:, or similar
            msg_match = re.search(r'\[([A-Z_]+)\]|([A-Z_]+):|([A-Z]+_[A-Z]+)', line)
            if msg_match:
                msg_type = msg_match.group(1) or msg_match.group(2) or msg_match.group(3)
                if msg_type:
                    message_patterns.append(msg_type.rstrip(':'))
        
        message_freq = Counter(message_patterns)
        
        return {
            'unique_messages': len(message_freq),
            'total_messages': len(message_patterns),
            'top_messages': dict(message_freq.most_common(10)),
            'message_distribution': dict(message_freq)
        }
    
    def _detect_cu_anomalies(self, error_analysis: Dict, log_level_analysis: Dict,
                           timestamp_analysis: Dict, frequency_analysis: Dict) -> List[Dict]:
        """Detect CU-specific anomalies based on analysis results."""
        anomalies = []
        
        # High error rate anomaly
        total_errors = sum(error_analysis.values())
        if total_errors > 50:  # Threshold for high error count
            anomalies.append({
                'type': 'high_error_rate',
                'severity': 'HIGH',
                'description': f'High error rate detected: {total_errors} errors',
                'total_errors': total_errors,
                'error_breakdown': error_analysis
            })
        
        # Critical/Fatal log level anomaly
        critical_count = log_level_analysis.get('CRITICAL', 0)
        if critical_count > 0:
            anomalies.append({
                'type': 'critical_events',
                'severity': 'CRITICAL',
                'description': f'Critical events detected: {critical_count} critical messages',
                'critical_count': critical_count
            })
        
        # Connection failure spike
        connection_failures = error_analysis.get('connection_failure', 0)
        if connection_failures > 10:
            anomalies.append({
                'type': 'connection_failure_spike',
                'severity': 'HIGH',
                'description': f'Connection failure spike: {connection_failures} failures',
                'failure_count': connection_failures
            })
        
        # Timestamp gap anomaly (missing logs)
        max_gap = timestamp_analysis.get('max_gap', 0)
        if max_gap > 300:  # Gap longer than 5 minutes
            anomalies.append({
                'type': 'log_gap',
                'severity': 'MEDIUM',
                'description': f'Large gap in logging: {max_gap:.1f} seconds',
                'max_gap_seconds': max_gap
            })
        
        # Resource exhaustion
        resource_errors = error_analysis.get('resource_exhaustion', 0)
        if resource_errors > 5:
            anomalies.append({
                'type': 'resource_exhaustion',
                'severity': 'HIGH',
                'description': f'Resource exhaustion detected: {resource_errors} incidents',
                'resource_error_count': resource_errors
            })
        
        # Authentication failures
        auth_failures = error_analysis.get('authentication_failure', 0)
        if auth_failures > 3:
            anomalies.append({
                'type': 'authentication_failures',
                'severity': 'HIGH',
                'description': f'Multiple authentication failures: {auth_failures} failures',
                'auth_failure_count': auth_failures
            })
        
        return anomalies
    
    def _extract_cu_log_features(self, error_analysis: Dict, log_level_analysis: Dict,
                               timestamp_analysis: Dict, frequency_analysis: Dict,
                               total_lines: int) -> List[float]:
        """Extract numerical features for ML analysis."""
        features = []
        
        # Error pattern features (6 features)
        for error_type in ['connection_failure', 'handover_failure', 'resource_exhaustion',
                          'protocol_error', 'authentication_failure', 'synchronization_loss']:
            features.append(float(error_analysis.get(error_type, 0)))
        
        # Log level features (5 features)
        for level in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
            features.append(float(log_level_analysis.get(level, 0)))
        
        # Timestamp features (4 features)
        features.append(float(timestamp_analysis.get('total_timestamps', 0)))
        features.append(float(timestamp_analysis.get('average_gap', 0)))
        features.append(float(timestamp_analysis.get('max_gap', 0)))
        features.append(float(timestamp_analysis.get('min_gap', 0)))
        
        # Frequency features (3 features)
        features.append(float(frequency_analysis.get('unique_messages', 0)))
        features.append(float(frequency_analysis.get('total_messages', 0)))
        features.append(float(total_lines))
        
        # Derived features (4 features)
        total_errors = sum(error_analysis.values())
        features.append(float(total_errors))
        features.append(float(total_errors / max(total_lines, 1)))  # Error rate
        
        critical_errors = log_level_analysis.get('CRITICAL', 0) + log_level_analysis.get('ERROR', 0)
        features.append(float(critical_errors))
        features.append(float(critical_errors / max(total_lines, 1)))  # Critical error rate
        
        # Ensure we have exactly 26 features to match expected feature count
        while len(features) < 28:
            features.append(0.0)
        
        return features[:28]  # Ensure exactly 28 features
    
    def _get_sample_errors(self, log_content: str) -> List[Dict]:
        """Extract sample error messages for detailed analysis."""
        sample_errors = []
        lines = log_content.split('\n')
        
        for i, line in enumerate(lines):
            # Look for error patterns
            for error_type, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        sample_errors.append({
                            'line_number': i + 1,
                            'error_type': error_type,
                            'message': line.strip(),
                            'pattern_matched': pattern
                        })
                        break
                if len(sample_errors) >= 10:  # Limit to first 10 samples
                    break
            if len(sample_errors) >= 10:
                break
        
        return sample_errors