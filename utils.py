"""
Utility functions for Telecom Anomaly Detection System.
Contains helper functions for logging, feature extraction, and file processing.
"""

import logging
import os
import h5py
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

def setup_logging(log_level: str = "INFO", log_file: str = "./telecom_anomaly_detection.log") -> logging.Logger:
    """
    Set up logging configuration.
    
    Args:
        log_level: Logging level
        log_file: Path to log file
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else "./", exist_ok=True)
    
    # Configure logging - file only for silent operation
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file)
        ]
    )
    
    logger = logging.getLogger('TelecomAnomalyDetector')
    return logger

def extract_telecom_features(protocol_stats: Dict, flow_stats: Dict, 
                           ru_du_communications: Dict, plane_separation: Dict) -> List[float]:
    """
    Extract features from telecom protocol analysis for anomaly detection.
    
    Args:
        protocol_stats: Protocol distribution statistics
        flow_stats: Network flow statistics
        ru_du_communications: RU-DU communication patterns
        plane_separation: Control/User plane separation stats
        
    Returns:
        List of numerical features for machine learning
    """
    features = []
    
    # Protocol distribution features
    total_packets = sum(protocol_stats.values()) if protocol_stats else 0
    
    # Core telecom protocol ratios
    telecom_protocols = ['CPRI', 'eCPRI', 'F1_C', 'F1_U', 'NGAP', 'S1_MME', 'S1_U', 'X2']
    for protocol in telecom_protocols:
        count = protocol_stats.get(protocol, 0)
        ratio = count / total_packets if total_packets > 0 else 0
        features.append(ratio)
    
    # Unknown protocol ratio
    unknown_count = protocol_stats.get('unknown', 0)
    unknown_ratio = unknown_count / total_packets if total_packets > 0 else 0
    features.append(unknown_ratio)
    
    # Total protocol diversity (number of different protocols)
    features.append(len(protocol_stats))
    
    # Flow statistics features
    if flow_stats:
        flow_packets = [stats['packets'] for stats in flow_stats.values()]
        flow_bytes = [stats['bytes'] for stats in flow_stats.values()]
        
        # Flow packet statistics
        features.extend([
            len(flow_stats),  # Number of flows
            np.mean(flow_packets) if flow_packets else 0,  # Average packets per flow
            np.std(flow_packets) if flow_packets else 0,   # Packet count variance
            np.max(flow_packets) if flow_packets else 0,   # Max packets in a flow
            np.min(flow_packets) if flow_packets else 0,   # Min packets in a flow
        ])
        
        # Flow byte statistics
        features.extend([
            np.mean(flow_bytes) if flow_bytes else 0,  # Average bytes per flow
            np.std(flow_bytes) if flow_bytes else 0,   # Byte count variance
            np.max(flow_bytes) if flow_bytes else 0,   # Max bytes in a flow
        ])
        
        # Bidirectional flow ratio
        bidirectional_flows = sum(1 for stats in flow_stats.values() if len(stats['directions']) > 1)
        bidirectional_ratio = bidirectional_flows / len(flow_stats) if flow_stats else 0
        features.append(bidirectional_ratio)
        
    else:
        # No flow data - add zeros
        features.extend([0] * 9)
    
    # RU-DU communication features
    if ru_du_communications:
        du_to_ru_counts = [stats['du_to_ru'] for stats in ru_du_communications.values()]
        ru_to_du_counts = [stats['ru_to_du'] for stats in ru_du_communications.values()]
        
        features.extend([
            len(ru_du_communications),  # Number of RU-DU pairs
            np.sum(du_to_ru_counts),    # Total DU->RU packets
            np.sum(ru_to_du_counts),    # Total RU->DU packets
            np.mean(du_to_ru_counts) if du_to_ru_counts else 0,  # Average DU->RU per pair
            np.mean(ru_to_du_counts) if ru_to_du_counts else 0,  # Average RU->DU per pair
        ])
        
        # Unidirectional communication ratio
        unidirectional_pairs = sum(1 for stats in ru_du_communications.values() 
                                 if (stats['du_to_ru'] > 0) != (stats['ru_to_du'] > 0))
        unidirectional_ratio = unidirectional_pairs / len(ru_du_communications)
        features.append(unidirectional_ratio)
        
    else:
        # No RU-DU communication data
        features.extend([0] * 6)
    
    # Plane separation features
    c_plane_count = plane_separation.get('c_plane', 0)
    u_plane_count = plane_separation.get('u_plane', 0)
    other_count = plane_separation.get('other', 0)
    total_plane_packets = c_plane_count + u_plane_count + other_count
    
    if total_plane_packets > 0:
        features.extend([
            c_plane_count / total_plane_packets,  # Control plane ratio
            u_plane_count / total_plane_packets,  # User plane ratio
            other_count / total_plane_packets,    # Other traffic ratio
        ])
    else:
        features.extend([0, 0, 0])
    
    # Additional derived features
    features.extend([
        total_packets,  # Total packet count
        total_plane_packets,  # Total plane-classified packets
        len([p for p in protocol_stats.keys() if p != 'unknown']),  # Known protocol count
    ])
    
    return features

def process_hdf_file(hdf_path: str) -> Dict[str, Any]:
    """
    Process HDF file and extract UE events and other telecom data.
    Handles various HDF file formats and structures robustly.
    
    Args:
        hdf_path: Path to HDF file
        
    Returns:
        Dictionary containing extracted data and metadata
    """
    
    # Validate file exists and is readable
    if not os.path.exists(hdf_path):
        return {'error': f"HDF file not found: {hdf_path}", 'file_path': hdf_path}
    
    if os.path.getsize(hdf_path) == 0:
        return {'error': f"HDF file is empty: {hdf_path}", 'file_path': hdf_path}
    
    try:
        # Test if file can be opened as HDF5
        with h5py.File(hdf_path, 'r') as test_file:
            pass  # Just test opening
    except (OSError, IOError, ValueError) as e:
        return {'error': f"Invalid HDF5 file format: {str(e)}", 'file_path': hdf_path}
    except Exception as e:
        return {'error': f"Cannot open HDF file: {str(e)}", 'file_path': hdf_path}
    
    try:
        with h5py.File(hdf_path, 'r') as hdf_file:
            result = {
                'file_path': hdf_path,
                'file_size': os.path.getsize(hdf_path),
                'datasets': list(hdf_file.keys()),
                'ue_events': [],
                'metadata': {},
                'processing_log': []
            }
            
            # Extract metadata safely
            try:
                for attr_name in hdf_file.attrs:
                    try:
                        attr_value = hdf_file.attrs[attr_name]
                        # Convert numpy types to Python types
                        if hasattr(attr_value, 'item'):
                            attr_value = attr_value.item()
                        elif isinstance(attr_value, bytes):
                            attr_value = attr_value.decode('utf-8', errors='ignore')
                        result['metadata'][attr_name] = attr_value
                    except Exception:
                        continue  # Skip problematic attributes
            except Exception as e:
                result['processing_log'].append(f"Warning: Could not read file attributes: {str(e)}")
            
            # Process datasets with priority order
            ue_events = []
            
            # Primary datasets (most likely to contain UE events)
            primary_datasets = ['ue_events', 'UE_events', 'events']
            secondary_datasets = ['ue_data', 'UE_data', 'data', 'Data']
            tertiary_datasets = [
                'attach_events', 'detach_events', 'mobility_events',
                'log_data', 'telecom_events', 'ue_attach', 'ue_detach', 
                'attachment', 'detachment', 'session_events', 
                'connection_events', 'network_events'
            ]
            
            # Process in priority order
            all_datasets = primary_datasets + secondary_datasets + tertiary_datasets
            processed_datasets = set()
            
            for dataset_name in all_datasets:
                if dataset_name in hdf_file and dataset_name not in processed_datasets:
                    try:
                        dataset = hdf_file[dataset_name]
                        result['processing_log'].append(f"Processing dataset: {dataset_name}")
                        
                        if isinstance(dataset, h5py.Dataset):
                            # Direct dataset
                            data = dataset[:]
                            events = _parse_dataset_to_events(data, dataset_name)
                            ue_events.extend(events)
                            result['processing_log'].append(f"Extracted {len(events)} events from {dataset_name}")
                            processed_datasets.add(dataset_name)
                            
                        elif isinstance(dataset, h5py.Group):
                            # Group containing multiple datasets
                            for sub_dataset_name in dataset.keys():
                                try:
                                    sub_dataset = dataset[sub_dataset_name]
                                    if isinstance(sub_dataset, h5py.Dataset):
                                        data = sub_dataset[:]
                                        events = _parse_dataset_to_events(data, f"{dataset_name}/{sub_dataset_name}")
                                        ue_events.extend(events)
                                        result['processing_log'].append(f"Extracted {len(events)} events from {dataset_name}/{sub_dataset_name}")
                                except Exception as e:
                                    result['processing_log'].append(f"Error processing {dataset_name}/{sub_dataset_name}: {str(e)}")
                                    continue
                            processed_datasets.add(dataset_name)
                    except Exception as e:
                        result['processing_log'].append(f"Error processing {dataset_name}: {str(e)}")
                        continue
            
            # If no events found, try remaining datasets
            if not ue_events:
                result['processing_log'].append("No events found in primary datasets, trying all available datasets")
                for dataset_name in hdf_file.keys():
                    if dataset_name not in processed_datasets:
                        try:
                            dataset = hdf_file[dataset_name]
                            if isinstance(dataset, h5py.Dataset):
                                data = dataset[:]
                                events = _parse_dataset_to_events(data, dataset_name)
                                if events:  # Only add if events were successfully parsed
                                    ue_events.extend(events)
                                    result['processing_log'].append(f"Extracted {len(events)} events from fallback dataset: {dataset_name}")
                        except Exception as e:
                            result['processing_log'].append(f"Error processing fallback dataset {dataset_name}: {str(e)}")
                            continue
            
            result['ue_events'] = ue_events
            result['total_events'] = len(ue_events)
            
            if ue_events:
                result['processing_log'].append(f"Successfully processed {len(ue_events)} total events")
            else:
                result['processing_log'].append("Warning: No UE events could be extracted from any dataset")
            
            return result
            
    except Exception as e:
        return {
            'error': f"Unexpected error processing HDF file: {str(e)}", 
            'file_path': hdf_path,
            'error_type': type(e).__name__
        }

def _parse_dataset_to_events(data: np.ndarray, dataset_name: str) -> List[Dict]:
    """
    Parse dataset data into UE events with robust error handling.
    
    Args:
        data: Raw dataset data
        dataset_name: Name of the dataset
        
    Returns:
        List of parsed events
    """
    events = []
    
    try:
        # Validate data
        if data is None or data.size == 0:
            return events
        
        # Handle different data types
        if hasattr(data.dtype, 'names') and data.dtype.names:  # Structured array
            for i, record in enumerate(data):
                try:
                    event = {'source_dataset': dataset_name, 'record_index': i}
                    
                    for field_name in data.dtype.names:
                        try:
                            value = record[field_name]
                            
                            # Convert numpy types to Python types safely
                            if isinstance(value, np.ndarray):
                                if value.size == 1:
                                    value = value.item()
                                else:
                                    value = value.tolist()
                            elif isinstance(value, (np.integer, np.floating)):
                                value = value.item()
                            elif isinstance(value, np.bytes_):
                                try:
                                    value = value.decode('utf-8', errors='ignore')
                                except:
                                    value = str(value)  # Fallback to string representation
                            elif isinstance(value, bytes):
                                try:
                                    value = value.decode('utf-8', errors='ignore')
                                except:
                                    value = str(value)
                            
                            event[field_name] = value
                        except Exception as field_error:
                            # Skip problematic fields but continue with record
                            event[f'error_field_{field_name}'] = f"Field parsing error: {str(field_error)}"
                            continue
                    
                    # Only add event if it has some valid data
                    if len([k for k in event.keys() if not k.startswith('error_')]) > 2:  # More than just metadata
                        # Determine event type based on field names and values
                        try:
                            event_type = _determine_event_type(event, dataset_name)
                            event['event_type'] = event_type
                        except:
                            event['event_type'] = 'generic'
                        
                        # Extract UE ID if available
                        try:
                            ue_id = _extract_ue_id(event)
                            if ue_id:
                                event['ue_id'] = ue_id
                        except:
                            pass  # UE ID is optional
                        
                        # Extract timestamp if available
                        try:
                            timestamp = _extract_timestamp(event)
                            if timestamp:
                                event['timestamp'] = timestamp
                        except:
                            pass  # Timestamp is optional
                        
                        events.append(event)
                        
                except Exception as record_error:
                    # Skip problematic records but continue processing
                    continue
                
        else:  # Simple array or unstructured data
            # For simple arrays, create basic events
            try:
                for i, value in enumerate(data):
                    try:
                        # Convert value safely
                        if hasattr(value, 'item'):
                            clean_value = value.item()
                        elif isinstance(value, (bytes, np.bytes_)):
                            clean_value = value.decode('utf-8', errors='ignore')
                        else:
                            clean_value = value
                        
                        event = {
                            'source_dataset': dataset_name,
                            'record_index': i,
                            'value': clean_value,
                            'event_type': 'generic'
                        }
                        events.append(event)
                    except:
                        continue  # Skip problematic values
            except Exception:
                # If all else fails, create a summary event
                events.append({
                    'source_dataset': dataset_name,
                    'summary': f"Dataset with {len(data) if hasattr(data, '__len__') else 'unknown'} entries",
                    'event_type': 'summary',
                    'data_type': str(data.dtype) if hasattr(data, 'dtype') else 'unknown'
                })
    
    except Exception as e:
        # Create an error event as last resort
        events.append({
            'source_dataset': dataset_name,
            'error': f"Dataset parsing error: {str(e)}",
            'event_type': 'error',
            'error_type': type(e).__name__
        })
    
    return events

def _determine_event_type(event: Dict, dataset_name: str) -> str:
    """
    Determine the type of UE event based on available data.
    
    Args:
        event: Event dictionary with parsed fields
        dataset_name: Name of source dataset
        
    Returns:
        Event type string ('attach', 'detach', or 'generic')
    """
    # Check for explicit event_type field
    if 'event_type' in event:
        event_type_val = event['event_type']
        if event_type_val == 1 or str(event_type_val).lower() in ['attach', 'attachment']:
            return 'attach'
        elif event_type_val == 2 or str(event_type_val).lower() in ['detach', 'detachment']:
            return 'detach'
    
    # Check dataset name patterns
    dataset_lower = dataset_name.lower()
    if 'attach' in dataset_lower:
        return 'attach'
    elif 'detach' in dataset_lower:
        return 'detach'
    
    # Check for other field patterns
    for field_name, value in event.items():
        field_lower = str(field_name).lower()
        value_str = str(value).lower()
        
        if 'attach' in field_lower or 'attach' in value_str:
            return 'attach'
        elif 'detach' in field_lower or 'detach' in value_str:
            return 'detach'
    
    return 'generic'

def _extract_ue_id(event: Dict) -> Optional[str]:
    """Extract UE ID from event data."""
    # Look for common UE ID field names
    ue_id_fields = ['ue_id', 'UE_id', 'user_id', 'subscriber_id', 'imsi', 'tmsi']
    
    for field in ue_id_fields:
        if field in event:
            value = event[field]
            if isinstance(value, bytes):
                return value.decode('utf-8', errors='ignore')
            return str(value)
    
    return None

def _extract_timestamp(event: Dict) -> Optional[float]:
    """Extract timestamp from event data."""
    # Look for common timestamp field names
    timestamp_fields = ['timestamp', 'time', 'event_time', 'create_time']
    
    for field in timestamp_fields:
        if field in event:
            value = event[field]
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    continue
    
    return None

def extract_event_metadata(event: Dict, dataset_name: str) -> str:
    """Extract event metadata for classification."""
    # Check dataset name for hints
    dataset_lower = dataset_name.lower()
    if 'attach' in dataset_lower:
        return 'attach'
    elif 'detach' in dataset_lower:
        return 'detach'
    elif 'handover' in dataset_lower or 'mobility' in dataset_lower:
        return 'handover'
    
    # Check field names and values
    field_names = [str(k).lower() for k in event.keys()]
    field_values = [str(v).lower() for v in event.values() if isinstance(v, (str, int, float))]
    
    # Look for attach indicators
    attach_indicators = ['attach', 'connect', 'register', 'join', 'initial']
    if any(indicator in ' '.join(field_names + field_values) for indicator in attach_indicators):
        return 'attach'
    
    # Look for detach indicators
    detach_indicators = ['detach', 'disconnect', 'deregister', 'leave', 'release']
    if any(indicator in ' '.join(field_names + field_values) for indicator in detach_indicators):
        return 'detach'
    
    # Look for handover indicators
    handover_indicators = ['handover', 'handoff', 'mobility', 'move', 'transfer']
    if any(indicator in ' '.join(field_names + field_values) for indicator in handover_indicators):
        return 'handover'
    
    return 'generic'

def _extract_ue_id(event: Dict) -> Optional[str]:
    """
    Extract UE ID from event data.
    
    Args:
        event: Event dictionary
        
    Returns:
        UE ID string or None
    """
    # Common UE ID field names
    ue_id_fields = ['ue_id', 'ue_identifier', 'imsi', 'tmsi', 'guti', 'rnti', 'user_id', 'device_id']
    
    for field in ue_id_fields:
        if field in event:
            return str(event[field])
    
    # Look for fields containing 'ue' or 'id'
    for key, value in event.items():
        key_lower = str(key).lower()
        if ('ue' in key_lower and 'id' in key_lower) or key_lower.endswith('_id'):
            return str(value)
    
    return None

def _extract_timestamp(event: Dict) -> Optional[float]:
    """
    Extract timestamp from event data.
    
    Args:
        event: Event dictionary
        
    Returns:
        Timestamp as float or None
    """
    # Common timestamp field names
    timestamp_fields = ['timestamp', 'time', 'event_time', 'occurrence_time', 'created_at', 'recorded_at']
    
    for field in timestamp_fields:
        if field in event:
            value = event[field]
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                # Try to parse timestamp string
                try:
                    return float(value)
                except ValueError:
                    try:
                        # Try parsing as datetime string
                        from datetime import datetime
                        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                        return dt.timestamp()
                    except ValueError:
                        continue
    
    return None

def calculate_anomaly_score(features: List[float], historical_features: List[List[float]]) -> float:
    """
    Calculate a simple anomaly score based on feature deviation from historical data.
    
    Args:
        features: Current feature vector
        historical_features: List of historical feature vectors
        
    Returns:
        Anomaly score (higher = more anomalous)
    """
    if not historical_features or not features:
        return 0.5  # Neutral score when no data available
    
    try:
        # Convert to numpy arrays
        current = np.array(features)
        historical = np.array(historical_features)
        
        # Calculate mean and std of historical features
        historical_mean = np.mean(historical, axis=0)
        historical_std = np.std(historical, axis=0)
        
        # Avoid division by zero
        historical_std = np.where(historical_std == 0, 1, historical_std)
        
        # Calculate z-scores
        z_scores = np.abs((current - historical_mean) / historical_std)
        
        # Anomaly score is the mean of z-scores
        anomaly_score = np.mean(z_scores)
        
        # Normalize to 0-1 range
        return min(anomaly_score / 3.0, 1.0)  # Divide by 3 to normalize typical z-scores
        
    except Exception:
        return 0.5  # Return neutral score on error

def format_anomaly_output(anomalies: List[Dict], file_path: str) -> str:
    """
    Format anomaly detection results for console output.
    
    Args:
        anomalies: List of detected anomalies
        file_path: Path to analyzed file
        
    Returns:
        Formatted string for display
    """
    if not anomalies:
        return f"✅ No anomalies detected in {os.path.basename(file_path)}"
    
    output = [f"🚨 {len(anomalies)} anomalies detected in {os.path.basename(file_path)}:"]
    
    for i, anomaly in enumerate(anomalies, 1):
        severity = anomaly.get('severity', 'unknown')
        severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(severity, '🔵')
        
        output.append(f"  {i}. {severity_emoji} [{severity.upper()}] {anomaly.get('type', 'Unknown')}")
        output.append(f"     {anomaly.get('description', 'No description available')}")
    
    return '\n'.join(output)

def save_results_to_file(results: List[Dict], output_dir: str) -> None:
    """
    Save analysis results to file.
    
    Args:
        results: List of analysis results
        output_dir: Directory to save results
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"telecom_anomaly_results_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        import json
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"Results saved to: {filepath}")
        
    except Exception as e:
        print(f"Error saving results: {e}")
