#!/usr/bin/env python3
"""
Telecom Anomaly Detection Script
Standalone Python script for detecting anomalies in PCAP and HDF files
using Isolation Forest algorithm for unsupervised learning.
"""

# Import warning suppression first
try:
    from suppress_warnings import *
except ImportError:
    import warnings
    import os
    warnings.filterwarnings("ignore")
    os.environ['PYTHONWARNINGS'] = 'ignore'

import os
import glob
import logging
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

# Third-party imports
try:
    from scapy.all import rdpcap, IP, UDP, TCP, Ether
    from scapy.layers.l2 import ARP
except ImportError:
    print("[ERROR] Scapy not installed. Please install with: pip install scapy")
    exit(1)

try:
    import h5py
except ImportError:
    print("[ERROR] h5py not installed. Please install with: pip install h5py")
    exit(1)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("[ERROR] scikit-learn not installed. Please install with: pip install scikit-learn")
    exit(1)

from config import Config
from utils import setup_logging, extract_telecom_features, process_hdf_file
from severity_classifier import SeverityClassifier, SeverityLevel

class TelecomAnomalyDetector:
    """
    Main class for telecom anomaly detection using Isolation Forest algorithm.
    Processes PCAP files for protocol analysis and HDF files for UE events.
    """
    
    def __init__(self, input_folder=None):
        self.config = Config()
        self.logger = setup_logging()
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.model_trained = False
        self.feature_columns = []
        self.input_folder = input_folder  # Custom folder path for files
        
        # Initialize production protocol mapper for flexible protocol detection
        from production_protocol_mapper import ProductionProtocolMapper
        self.protocol_mapper = ProductionProtocolMapper()
        
        # Initialize adaptive contamination manager
        from adaptive_contamination_system import AdaptiveContaminationManager
        self.contamination_manager = AdaptiveContaminationManager(initial_contamination=0.1)
        
        # Initialize CU log analyzer
        from cu_log_analyzer import CULogAnalyzer
        self.cu_log_analyzer = CULogAnalyzer()
        
        # Legacy telecom protocol ports (kept for backward compatibility)
        self.telecom_ports = {
            'CPRI': [8080, 8081, 8082],
            'eCPRI': [3200, 3201, 3202],
            'F1_C': [38472],  # F1-C control plane
            'F1_U': [2152],   # F1-U user plane (GTP-U)
            'S1_MME': [36412],
            'S1_U': [2152],
            'X2': [36422],
            'NGAP': [38412],
            'HTTP': [80, 443]
        }
        
        # Communication pattern tracking
        self.communication_patterns = defaultdict(list)
        self.traffic_stats = defaultdict(dict)
        
        # Initialize severity classifier
        self.severity_classifier = SeverityClassifier()
        
    def load_or_create_model(self) -> None:
        """Load existing model or create new one."""
        model_path = os.path.join(self.config.MODEL_DIR, 'isolation_forest_model.pkl')
        scaler_path = os.path.join(self.config.MODEL_DIR, 'scaler.pkl')
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                with open(model_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.model_trained = True
                self.logger.info("Loaded existing model from disk")
            except Exception as e:
                self.logger.error(f"Error loading model: {e}")
                self._create_new_model()
        else:
            self._create_new_model()
    
    def _create_new_model(self, contamination: float = None) -> None:
        """Create new Isolation Forest model with adaptive contamination."""
        if contamination is None:
            contamination = self.contamination_manager.current_contamination
        
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        self.logger.info(f"Created new Isolation Forest model with contamination: {contamination:.1%}")
    
    def save_model(self) -> None:
        """Save trained model to disk."""
        os.makedirs(self.config.MODEL_DIR, exist_ok=True)
        
        model_path = os.path.join(self.config.MODEL_DIR, 'isolation_forest_model.pkl')
        scaler_path = os.path.join(self.config.MODEL_DIR, 'scaler.pkl')
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(self.isolation_forest, f)
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            self.logger.info("Model saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def analyze_pcap_file(self, pcap_path: str) -> Dict:
        """
        Analyze PCAP file for telecom protocol anomalies.
        
        Args:
            pcap_path: Path to PCAP file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            self.logger.info(f"Analyzing PCAP file: {pcap_path}")
            packets = rdpcap(pcap_path)
            
            # Initialize analysis containers
            protocol_stats = defaultdict(int)
            flow_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'directions': set()})
            ru_du_communications = defaultdict(lambda: {'du_to_ru': 0, 'ru_to_du': 0, 'du_packets': [], 'ru_packets': []})
            plane_separation = {'c_plane': 0, 'u_plane': 0, 'other': 0, 'c_plane_packets': [], 'u_plane_packets': []}
            packet_logs = []  # Store detailed packet information
            
            # Process each packet
            for i, packet in enumerate(packets):
                # Skip non-Ethernet packets
                if not packet.haslayer(Ether):
                    continue
                
                # Extract MAC addresses first
                src_mac = packet[Ether].src if packet.haslayer(Ether) else None
                dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None
                
                # Get IP info if available, but don't require it
                src_ip = None
                dst_ip = None
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    

                
                # Create detailed packet log
                packet_log = {
                    'packet_index': i,
                    'timestamp': packet.time if hasattr(packet, 'time') else None,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'size': len(packet),
                    'protocol': 'unknown',
                    'plane': 'other',
                    'src_port': None,
                    'dst_port': None,
                    'summary': packet.summary() if hasattr(packet, 'summary') else str(packet)
                }
                
                # Determine protocol and plane
                protocol_info = self._identify_protocol(packet)
                packet_log['protocol'] = protocol_info['protocol']
                packet_log['plane'] = protocol_info['plane']
                
                # Add port information
                if packet.haslayer(UDP):
                    packet_log['src_port'] = packet[UDP].sport
                    packet_log['dst_port'] = packet[UDP].dport
                elif packet.haslayer(TCP):
                    packet_log['src_port'] = packet[TCP].sport
                    packet_log['dst_port'] = packet[TCP].dport
                
                packet_logs.append(packet_log)
                protocol_stats[protocol_info['protocol']] += 1
                
                # Track plane separation with packet details
                if protocol_info['plane'] == 'control':
                    plane_separation['c_plane'] += 1
                    plane_separation['c_plane_packets'].append(packet_log)
                elif protocol_info['plane'] == 'user':
                    plane_separation['u_plane'] += 1
                    plane_separation['u_plane_packets'].append(packet_log)
                else:
                    plane_separation['other'] += 1
                
                # Track flow statistics (use IPs if available, otherwise MACs)
                if src_ip and dst_ip:
                    flow_key = f"{src_ip}:{dst_ip}"
                    flow_stats[flow_key]['packets'] += 1
                    flow_stats[flow_key]['bytes'] += len(packet)
                    flow_stats[flow_key]['directions'].add(f"{src_ip}->{dst_ip}")
                elif src_mac and dst_mac:
                    flow_key = f"{src_mac}:{dst_mac}"
                    flow_stats[flow_key]['packets'] += 1
                    flow_stats[flow_key]['bytes'] += len(packet)
                    flow_stats[flow_key]['directions'].add(f"{src_mac}->{dst_mac}")
                
                # Track RU-DU communications with packet details based on MAC addresses
                if self._is_ru_du_communication(src_mac, dst_mac):
                    if self._is_du_mac(src_mac):
                        comm_key = f"{src_mac}-{dst_mac}"
                        ru_du_communications[comm_key]['du_to_ru'] += 1
                        ru_du_communications[comm_key]['du_packets'].append(packet_log)
                    elif self._is_ru_mac(src_mac):
                        comm_key = f"{dst_mac}-{src_mac}"
                        ru_du_communications[comm_key]['ru_to_du'] += 1
                        ru_du_communications[comm_key]['ru_packets'].append(packet_log)
                

            
            # Extract features for anomaly detection
            features = extract_telecom_features(
                protocol_stats, flow_stats, ru_du_communications, plane_separation
            )
            
            # Detect anomalies in communication patterns
            anomalies = self._detect_communication_anomalies(
                protocol_stats, flow_stats, ru_du_communications, plane_separation, packet_logs
            )
            
            return {
                'file': pcap_path,
                'packet_count': len(packets),
                'protocol_stats': dict(protocol_stats),
                'flow_stats': dict(flow_stats),
                'ru_du_communications': dict(ru_du_communications),
                'plane_separation': plane_separation,
                'features': features,
                'anomalies': anomalies,
                'packet_logs': packet_logs
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file {pcap_path}: {e}")
            return {'error': str(e), 'file': pcap_path}
    
    def _identify_protocol(self, packet) -> Dict:
        """Identify telecom protocol from packet using production-ready mapping."""
        # First try the flexible production protocol mapper
        try:
            # Extract packet payload for deep inspection
            packet_payload = None
            if hasattr(packet, 'load'):
                packet_payload = packet.load
            elif hasattr(packet, 'payload'):
                packet_payload = bytes(packet.payload)
            
            protocol_info = self.protocol_mapper.identify_protocol(packet, packet_payload)
            
            # If confidence is high enough, use the result
            if protocol_info.get('confidence', 0) > 0.5:
                return {
                    'protocol': protocol_info['protocol'],
                    'plane': protocol_info['plane']
                }
        except Exception as e:
            self.logger.debug(f"Production mapper failed, using fallback: {e}")
        
        # Fallback to legacy port-based identification
        protocol_info = {'protocol': 'unknown', 'plane': 'other'}
        
        if packet.haslayer(UDP):
            port = packet[UDP].dport
            sport = packet[UDP].sport
            
            # Check for specific telecom protocols
            for protocol, ports in self.telecom_ports.items():
                if port in ports or sport in ports:
                    protocol_info['protocol'] = protocol
                    # Determine plane
                    if protocol in ['F1_C', 'NGAP', 'S1_MME', 'X2']:
                        protocol_info['plane'] = 'control'
                    elif protocol in ['F1_U', 'S1_U']:
                        protocol_info['plane'] = 'user'
                    break
        
        elif packet.haslayer(TCP):
            port = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Check for TCP-based protocols
            for protocol, ports in self.telecom_ports.items():
                if port in ports or sport in ports:
                    protocol_info['protocol'] = protocol
                    break
        
        return protocol_info
    
    def _is_ru_du_communication(self, src_mac: str, dst_mac: str) -> bool:
        """Check if communication is between RU and DU based on MAC addresses."""
        if not src_mac or not dst_mac:
            return False
        
        # Check for DU sending to RU (including broadcast indicating no RU response)
        du_to_ru = self._is_du_mac(src_mac) and (self._is_ru_mac(dst_mac) or dst_mac.lower() == "ff:ff:ff:ff:ff:ff")
        # Check for RU sending to DU
        ru_to_du = self._is_ru_mac(src_mac) and self._is_du_mac(dst_mac)
        
        return du_to_ru or ru_to_du
    
    def _is_du_mac(self, mac: str) -> bool:
        """Check if MAC address belongs to DU using production-ready patterns."""
        if not mac:
            return False
        # Use production mapper first
        device_type = self.protocol_mapper.identify_device_type(mac)
        if device_type == 'DU':
            return True
        # Fallback to config-based detection
        return self.config.is_du_mac(mac)
    
    def _is_ru_mac(self, mac: str) -> bool:
        """Check if MAC address belongs to RU using production-ready patterns."""
        if not mac:
            return False
        # Use production mapper first
        device_type = self.protocol_mapper.identify_device_type(mac)
        if device_type == 'RU':
            return True
        # Fallback to config-based detection
        return self.config.is_ru_mac(mac)
    
    def _detect_communication_anomalies(self, protocol_stats, flow_stats, 
                                       ru_du_communications, plane_separation, packet_logs) -> List[Dict]:
        """Detect specific telecom communication anomalies."""
        anomalies = []
        
        # Check for unidirectional RU-DU communication (DU sending but RU not responding)
        for comm_pair, stats in ru_du_communications.items():
            if stats['du_to_ru'] > 0 and stats['ru_to_du'] == 0:
                # Get sample DU packets for logging
                sample_du_packets = stats['du_packets'][:5]  # Show first 5 packets
                # Create context for severity classification
                context = {
                    'affected_devices': 2,  # RU and DU pair
                    'packet_loss_rate': 1.0,  # Complete loss of response
                    'duration_minutes': 10,  # Assume ongoing issue
                    'is_business_hours': True,
                    'anomaly_score': -0.8  # High anomaly score
                }
                
                anomalies.append({
                    'type': 'unidirectional_communication',
                    'description': f"DU sending to RU but no response from RU: {comm_pair}",
                    'context': context,
                    'severity': 'high',
                    'details': stats,
                    'sample_packets': sample_du_packets,
                    'total_du_packets': len(stats['du_packets']),
                    'total_ru_packets': len(stats['ru_packets'])
                })
        
        # Check for missing plane data
        total_telecom_packets = plane_separation['c_plane'] + plane_separation['u_plane']
        if total_telecom_packets > 0:
            c_plane_ratio = plane_separation['c_plane'] / total_telecom_packets
            u_plane_ratio = plane_separation['u_plane'] / total_telecom_packets
            
            if c_plane_ratio < 0.1:  # Less than 10% control plane
                # Get sample user plane packets that are present
                sample_u_packets = plane_separation.get('u_plane_packets', [])[:3]
                context = {
                    'affected_devices': 1,
                    'packet_loss_rate': 1.0 - c_plane_ratio,
                    'duration_minutes': 15,
                    'is_business_hours': True,
                    'anomaly_score': -0.6
                }
                anomalies.append({
                    'type': 'missing_control_plane',
                    'description': f"Very low control plane traffic: {c_plane_ratio:.2%}",
                    'context': context,
                    'severity': 'medium',
                    'details': plane_separation,
                    'sample_packets': sample_u_packets,
                    'missing_plane': 'control',
                    'present_plane_count': len(plane_separation.get('u_plane_packets', []))
                })
            
            if u_plane_ratio < 0.1:  # Less than 10% user plane
                # Get sample control plane packets that are present
                sample_c_packets = plane_separation.get('c_plane_packets', [])[:3]
                context = {
                    'affected_devices': 1,
                    'packet_loss_rate': 1.0 - u_plane_ratio,
                    'duration_minutes': 15,
                    'is_business_hours': True,
                    'anomaly_score': -0.5
                }
                anomalies.append({
                    'type': 'missing_user_plane',
                    'description': f"Very low user plane traffic: {u_plane_ratio:.2%}",
                    'context': context,
                    'severity': 'medium',
                    'details': plane_separation,
                    'sample_packets': sample_c_packets,
                    'missing_plane': 'user',
                    'present_plane_count': len(plane_separation.get('c_plane_packets', []))
                })
        
        # Check for unusual protocol distributions
        total_packets = sum(protocol_stats.values())
        if total_packets > 0:
            for protocol, count in protocol_stats.items():
                ratio = count / total_packets
                if protocol == 'unknown' and ratio > 0.5:
                    anomalies.append({
                        'type': 'high_unknown_protocol',
                        'description': f"High ratio of unknown protocol packets: {ratio:.2%}",
                        'severity': 'medium',
                        'details': {'protocol': protocol, 'count': count, 'ratio': ratio}
                    })
        
        return self._apply_severity_classification(anomalies)
    
    def analyze_hdf_file(self, hdf_path: str) -> Dict:
        """
        Analyze HDF file for UE Attach/Detach events.
        
        Args:
            hdf_path: Path to HDF file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            self.logger.info(f"Analyzing HDF file: {hdf_path}")
            hdf_data = process_hdf_file(hdf_path)
            
            if 'error' in hdf_data:
                return hdf_data
            
            # Extract UE events
            ue_events = hdf_data.get('ue_events', [])
            attach_events = [e for e in ue_events if e.get('event_type') == 'attach']
            detach_events = [e for e in ue_events if e.get('event_type') == 'detach']
            
            # Analyze event patterns
            event_anomalies = self._detect_ue_event_anomalies(attach_events, detach_events)
            
            # Extract features for anomaly detection
            features = self._extract_hdf_features(hdf_data, attach_events, detach_events)
            
            return {
                'file': hdf_path,
                'total_events': len(ue_events),
                'attach_events': len(attach_events),
                'detach_events': len(detach_events),
                'features': features,
                'anomalies': event_anomalies,
                'raw_data': hdf_data
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing HDF file {hdf_path}: {e}")
            return {'error': str(e), 'file': hdf_path}
    
    def _detect_ue_event_anomalies(self, attach_events: List, detach_events: List) -> List[Dict]:
        """Detect anomalies in UE attach/detach events."""
        anomalies = []
        
        # Check for unbalanced attach/detach ratio
        if len(attach_events) > 0 or len(detach_events) > 0:
            total_events = len(attach_events) + len(detach_events)
            attach_ratio = len(attach_events) / total_events
            detach_ratio = len(detach_events) / total_events
            
            # Expect roughly balanced attach/detach events
            if abs(attach_ratio - detach_ratio) > 0.3:  # More than 30% difference
                # Get sample events for logging
                sample_attach_events = attach_events[:3] if attach_events else []
                sample_detach_events = detach_events[:3] if detach_events else []
                context = {
                    'affected_devices': len(set([e.get('ue_id') for e in attach_events + detach_events])),
                    'packet_loss_rate': abs(attach_ratio - detach_ratio),
                    'duration_minutes': 20,
                    'is_business_hours': True,
                    'anomaly_score': -0.3
                }
                anomalies.append({
                    'type': 'unbalanced_attach_detach',
                    'description': f"Unbalanced attach/detach ratio: {attach_ratio:.2%} attach, {detach_ratio:.2%} detach",
                    'context': context,
                    'severity': 'medium',
                    'details': {'attach_count': len(attach_events), 'detach_count': len(detach_events)},
                    'sample_attach_events': sample_attach_events,
                    'sample_detach_events': sample_detach_events,
                    'total_attach_events': len(attach_events),
                    'total_detach_events': len(detach_events)
                })
        
        # Check for rapid attach/detach cycles (same UE)
        ue_event_counts = defaultdict(lambda: {'attach': 0, 'detach': 0})
        
        for event in attach_events:
            ue_id = event.get('ue_id', 'unknown')
            ue_event_counts[ue_id]['attach'] += 1
        
        for event in detach_events:
            ue_id = event.get('ue_id', 'unknown')
            ue_event_counts[ue_id]['detach'] += 1
        
        for ue_id, counts in ue_event_counts.items():
            if counts['attach'] > 5 or counts['detach'] > 5:  # Threshold for rapid cycling
                # Get sample events for this UE
                ue_attach_events = [e for e in attach_events if e.get('ue_id') == ue_id][:3]
                ue_detach_events = [e for e in detach_events if e.get('ue_id') == ue_id][:3]
                anomalies.append({
                    'type': 'rapid_attach_detach_cycle',
                    'description': f"UE {ue_id} has rapid attach/detach cycles",
                    'severity': 'high',
                    'details': {'ue_id': ue_id, 'counts': counts},
                    'sample_ue_attach_events': ue_attach_events,
                    'sample_ue_detach_events': ue_detach_events,
                    'total_ue_attach_events': len([e for e in attach_events if e.get('ue_id') == ue_id]),
                    'total_ue_detach_events': len([e for e in detach_events if e.get('ue_id') == ue_id])
                })
        
        return self._apply_severity_classification(anomalies)
    
    def _apply_severity_classification(self, anomalies: List[Dict]) -> List[Dict]:
        """Apply severity classification to detected anomalies."""
        classified_anomalies = []
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            context = anomaly.get('context', {})
            
            # Apply severity classification
            classification = self.severity_classifier.classify_anomaly(anomaly_type, context)
            
            # Add classification information to anomaly
            anomaly['severity_classification'] = classification
            anomaly['severity_level'] = classification.severity.value
            anomaly['priority_score'] = classification.priority_score
            anomaly['impact_description'] = classification.impact_description
            anomaly['recommended_action'] = classification.recommended_action
            anomaly['response_time'] = classification.response_time
            anomaly['escalation_required'] = classification.escalation_required
            
            classified_anomalies.append(anomaly)
        
        # Sort by priority score (highest first)
        classified_anomalies.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        
        return classified_anomalies
    
    def _extract_hdf_features(self, hdf_data: Dict, attach_events: List, detach_events: List) -> List[float]:
        """Extract features from HDF data for anomaly detection."""
        features = []
        
        # Basic event counts
        features.append(len(attach_events))
        features.append(len(detach_events))
        
        # Event ratios
        total_events = len(attach_events) + len(detach_events)
        if total_events > 0:
            features.append(len(attach_events) / total_events)
            features.append(len(detach_events) / total_events)
        else:
            features.extend([0.0, 0.0])
        
        # Time-based features (if timestamp available)
        if attach_events:
            timestamps = [e.get('timestamp', 0) for e in attach_events if 'timestamp' in e]
            if timestamps:
                features.append(np.std(timestamps))  # Timestamp variance
                features.append(max(timestamps) - min(timestamps))  # Time span
            else:
                features.extend([0.0, 0.0])
        else:
            features.extend([0.0, 0.0])
        
        # Additional HDF-specific features
        features.append(len(hdf_data.get('datasets', [])))
        features.append(hdf_data.get('file_size', 0))
        
        return features
    
    def train_model(self, all_features: List[List[float]]) -> None:
        """Train the Isolation Forest model on extracted features."""
        if not all_features:
            self.logger.warning("No features available for training")
            return
        
        try:
            # Ensure all feature vectors have the same length
            max_length = max(len(features) for features in all_features)
            normalized_features = []
            
            for features in all_features:
                # Pad shorter feature vectors with zeros
                if len(features) < max_length:
                    padded_features = features + [0.0] * (max_length - len(features))
                else:
                    padded_features = features[:max_length]  # Truncate if longer
                normalized_features.append(padded_features)
            
            # Convert to numpy array and handle any missing values
            X = np.array(normalized_features)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            self.logger.info(f"Training data shape: {X.shape}")
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest.fit(X_scaled)
            self.model_trained = True
            
            self.logger.info(f"Model trained successfully on {len(all_features)} samples with {X.shape[1]} features")
            
            # Save the trained model
            self.save_model()
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            import traceback
            traceback.print_exc()
            self.model_trained = False
    
    def predict_anomalies(self, features: List[float]) -> Tuple[int, float]:
        """
        Predict if features represent an anomaly.
        
        Args:
            features: Feature vector
            
        Returns:
            Tuple of (prediction, anomaly_score)
            prediction: -1 for anomaly, 1 for normal
            anomaly_score: Anomaly score (lower is more anomalous)
        """
        if not self.model_trained:
            return 0, 0.0
        
        try:
            # Convert to numpy array and scale
            X = np.array(features).reshape(1, -1)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.isolation_forest.predict(X_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_scaled)[0]
            
            return prediction, anomaly_score
            
        except Exception as e:
            self.logger.error(f"Error predicting anomaly: {e}")
            return 0, 0.0
    
    def analyze_cu_log_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze CU log file for anomalies.
        
        Args:
            file_path: Path to the CU log file
            
        Returns:
            Analysis results dictionary
        """
        self.logger.info(f"Analyzing CU log file: {file_path}")
        
        try:
            # Use CU log analyzer for detailed analysis
            result = self.cu_log_analyzer.analyze_cu_log_file(file_path)
            
            # Apply severity classification to detected anomalies
            if 'anomalies' in result and result['anomalies']:
                for anomaly in result['anomalies']:
                    # Create context for severity classification
                    context = {
                        'file_type': 'CU_LOG',
                        'total_lines': result.get('total_lines', 0),
                        'error_count': anomaly.get('total_errors', 0),
                        'duration': 'unknown'
                    }
                    
                    # Classify severity
                    classification = self.severity_classifier.classify_anomaly(
                        anomaly['type'], context
                    )
                    
                    # Add classification to anomaly
                    anomaly['severity_level'] = classification.severity.value
                    anomaly['priority_score'] = classification.priority_score
                    anomaly['impact_description'] = classification.impact_description
                    anomaly['response_time'] = classification.response_time
                    anomaly['escalation_required'] = classification.escalation_required
                    anomaly['recommended_action'] = classification.recommended_action
            
            self.logger.info(f"CU log analysis completed for {file_path}")
            return result
            
        except Exception as e:
            error_msg = f"Error analyzing CU log file {file_path}: {str(e)}"
            self.logger.error(error_msg)
            return {
                'file': file_path,
                'type': 'CU_LOG',
                'error': error_msg
            }
    
    def process_all_files(self) -> None:
        """Process all PCAP and HDF files from configured directories."""
        self.logger.info("Starting telecom anomaly detection...")
        
        # Load or create model
        self.load_or_create_model()
        
        # Find all files to process
        pcap_files = []
        hdf_files = []
        txt_files = []
        
        if self.input_folder:
            # Check if input is a single file or directory
            if os.path.isfile(self.input_folder):
                # Single file specified
                if self.input_folder.endswith(('.pcap', '.cap')):
                    pcap_files.append(self.input_folder)
                elif self.input_folder.endswith(('.h5', '.hdf5')):
                    hdf_files.append(self.input_folder)
                elif self.input_folder.endswith(('.txt', '.log')):
                    txt_files.append(self.input_folder)
                self.logger.info(f"Using single file: {self.input_folder}")
            elif os.path.exists(self.input_folder):
                # Directory specified
                pcap_files.extend(glob.glob(os.path.join(self.input_folder, "*.pcap")))
                pcap_files.extend(glob.glob(os.path.join(self.input_folder, "*.cap")))
                hdf_files.extend(glob.glob(os.path.join(self.input_folder, "*.h5")))
                hdf_files.extend(glob.glob(os.path.join(self.input_folder, "*.hdf5")))
                txt_files.extend(glob.glob(os.path.join(self.input_folder, "*.txt")))
                txt_files.extend(glob.glob(os.path.join(self.input_folder, "*.log")))
                self.logger.info(f"Using custom input folder: {self.input_folder}")
            else:
                self.logger.error(f"Custom input path not found: {self.input_folder}")
                return
        else:
            # Use default configured directories
            for data_dir in self.config.DATA_DIRS:
                if os.path.exists(data_dir):
                    pcap_files.extend(glob.glob(os.path.join(data_dir, "*.pcap")))
                    pcap_files.extend(glob.glob(os.path.join(data_dir, "*.cap")))
                    hdf_files.extend(glob.glob(os.path.join(data_dir, "*.h5")))
                    hdf_files.extend(glob.glob(os.path.join(data_dir, "*.hdf5")))
                    txt_files.extend(glob.glob(os.path.join(data_dir, "*.txt")))
                    txt_files.extend(glob.glob(os.path.join(data_dir, "*.log")))
                else:
                    self.logger.warning(f"Data directory not found: {data_dir}")
        
        self.logger.info(f"Found {len(pcap_files)} PCAP files, {len(hdf_files)} HDF files, and {len(txt_files)} CU log files")
        
        # Process files and collect features
        all_features = []
        all_results = []
        
        # Process PCAP files
        for pcap_file in pcap_files:
            result = self.analyze_pcap_file(pcap_file)
            if 'error' not in result:
                all_features.append(result['features'])
                all_results.append(result)
        
        # Process HDF files
        for hdf_file in hdf_files:
            result = self.analyze_hdf_file(hdf_file)
            if 'error' not in result:
                all_features.append(result['features'])
                all_results.append(result)
        
        # Process CU log files
        for txt_file in txt_files:
            result = self.analyze_cu_log_file(txt_file)
            if 'error' not in result:
                all_features.append(result['features'])
                all_results.append(result)
        
        # Train model if not already trained or retrain with new data
        if not self.model_trained or len(all_features) > 0:
            self.train_model(all_features)
        
        # Detect anomalies and adapt contamination factor
        total_anomalies = 0
        any_anomalies_found = False
        detected_anomalies = []
        network_conditions = {}
        
        # First pass: count anomalies and assess network conditions
        for result in all_results:
            if 'features' in result:
                prediction, anomaly_score = self.predict_anomalies(result['features'])
                
                # Count anomalies based on comprehensive detection
                has_specific_anomalies = 'anomalies' in result and len(result['anomalies']) > 0
                ml_anomaly_detected = prediction == -1
                low_anomaly_score = anomaly_score < -0.1
                
                # Always flag as anomaly if specific telecom anomalies are detected
                is_anomaly = has_specific_anomalies or ml_anomaly_detected or low_anomaly_score
                
                if is_anomaly:
                    detected_anomalies.append(result)
                    
                # Collect network condition indicators
                if 'anomalies' in result:
                    for anomaly in result['anomalies']:
                        anomaly_type = anomaly.get('type', '')
                        if 'unknown_protocol' in anomaly_type:
                            network_conditions['unknown_protocol_ratio'] = network_conditions.get('unknown_protocol_ratio', 0) + 0.1
                        elif 'unidirectional' in anomaly_type:
                            network_conditions['unidirectional_communications'] = network_conditions.get('unidirectional_communications', 0) + 1
                        elif 'missing_plane' in anomaly_type:
                            network_conditions['missing_plane_events'] = network_conditions.get('missing_plane_events', 0) + 1
                        elif 'rapid_cycle' in anomaly_type:
                            network_conditions['rapid_ue_cycling'] = network_conditions.get('rapid_ue_cycling', 0) + 1
        
        # Calculate current anomaly rate
        current_anomaly_rate = len(detected_anomalies) / max(len(all_results), 1)
        
        # Adapt contamination factor based on observed conditions
        if len(all_results) >= 5:  # Need sufficient data for adaptation
            new_contamination = self.contamination_manager.calculate_adaptive_contamination(
                current_anomaly_rate,
                network_conditions
            )
            
            # Retrain model if contamination changed significantly
            if abs(new_contamination - self.contamination_manager.current_contamination) > 0.05:
                self.logger.info(f"Retraining model with new contamination: {new_contamination:.1%}")
                self._create_new_model(new_contamination)
                if all_features:
                    self.train_model(all_features)
                
                # Re-analyze with updated model
                detected_anomalies = []
                for result in all_results:
                    if 'features' in result:
                        prediction, anomaly_score = self.predict_anomalies(result['features'])
                        has_specific_anomalies = 'anomalies' in result and len(result['anomalies']) > 0
                        ml_anomaly_detected = prediction == -1
                        low_anomaly_score = anomaly_score < -0.1
                        is_anomaly = ml_anomaly_detected or has_specific_anomalies or low_anomaly_score
                        if is_anomaly:
                            detected_anomalies.append(result)
        
        # Display results for detected anomalies
        if detected_anomalies:
            print("\n" + "="*80)
            print("TELECOM ANOMALY DETECTION RESULTS") 
            print("="*80)
            any_anomalies_found = True
            
            for result in detected_anomalies:
                # Get prediction for this result
                prediction, anomaly_score = self.predict_anomalies(result['features']) if 'features' in result else (-1, -0.5)
                
                # Display results for anomalous files
                self._display_file_results(result, prediction, anomaly_score)
                total_anomalies += 1
        
        # Display summary based on whether anomalies were found
        if any_anomalies_found:
            print(f"\n" + "="*80)
            print(f"SUMMARY:")
            print(f"Total files processed: {len(all_results)}")
            print(f"Anomalies detected: {total_anomalies}")
            print(f"Anomaly rate: {total_anomalies/len(all_results)*100:.2f}%")
            
            # Display severity distribution
            self._display_severity_summary(all_results)
            
            # Display comprehensive anomaly summary
            self._display_comprehensive_anomaly_summary(detected_anomalies)
            print("="*80)
        else:
            # Only print if files were actually processed
            if all_results:
                print("no anomalies found")
    
    def _display_severity_summary(self, all_results: List[Dict]) -> None:
        """Display severity distribution summary."""
        all_classifications = []
        
        # Collect all severity classifications
        for result in all_results:
            if 'anomalies' in result:
                for anomaly in result['anomalies']:
                    if 'severity_classification' in anomaly:
                        all_classifications.append(anomaly['severity_classification'])
        
        if not all_classifications:
            return
        
        # Get severity statistics
        stats = self.severity_classifier.get_severity_statistics(all_classifications)
        
        print(f"\nSEVERITY DISTRIBUTION:")
        print(f"  CRITICAL: {stats['counts'][SeverityLevel.CRITICAL]} ({stats['percentages'][SeverityLevel.CRITICAL]:.1f}%)")
        print(f"  HIGH:     {stats['counts'][SeverityLevel.HIGH]} ({stats['percentages'][SeverityLevel.HIGH]:.1f}%)")
        print(f"  MEDIUM:   {stats['counts'][SeverityLevel.MEDIUM]} ({stats['percentages'][SeverityLevel.MEDIUM]:.1f}%)")
        print(f"  LOW:      {stats['counts'][SeverityLevel.LOW]} ({stats['percentages'][SeverityLevel.LOW]:.1f}%)")
        print(f"  INFO:     {stats['counts'][SeverityLevel.INFO]} ({stats['percentages'][SeverityLevel.INFO]:.1f}%)")
    
    def _display_comprehensive_anomaly_summary(self, detected_anomalies: List[Dict]) -> None:
        """Display comprehensive summary of all anomalies with descriptions."""
        if not detected_anomalies:
            return
        
        print(f"\nALL DETECTED ANOMALIES:")
        print(f"-" * 50)
        
        anomaly_counter = 1
        for result in detected_anomalies:
            if 'anomalies' in result and result['anomalies']:
                filename = os.path.basename(result['file'])
                print(f"\nFile: {filename}")
                
                for anomaly in result['anomalies']:
                    severity = anomaly.get('severity_level', anomaly.get('severity', 'UNKNOWN'))
                    anomaly_type = anomaly.get('type', 'unknown')
                    description = anomaly.get('description', 'No description available')
                    
                    print(f"  {anomaly_counter}. [{severity}] {anomaly_type}")
                    print(f"     Description: {description}")
                    
                    # Add additional context if available
                    if 'impact_description' in anomaly:
                        print(f"     Impact: {anomaly['impact_description']}")
                    if 'recommended_action' in anomaly:
                        print(f"     Action: {anomaly['recommended_action']}")
                    
                    anomaly_counter += 1
        
        print(f"\nTotal anomalies found: {anomaly_counter - 1}")

    def _display_file_results(self, result: Dict, prediction: int, anomaly_score: float) -> None:
        """Display analysis results for a single file."""
        filename = os.path.basename(result['file'])
        
        # Determine anomaly status based on multiple factors
        has_specific_anomalies = 'anomalies' in result and len(result['anomalies']) > 0
        ml_anomaly_detected = prediction == -1
        low_anomaly_score = anomaly_score < -0.1  # Lower scores indicate anomalies
        
        # Consider it an anomaly if either ML detected it OR specific anomalies found
        is_anomaly = ml_anomaly_detected or has_specific_anomalies or low_anomaly_score
        
        # Only display output if anomalies are detected
        if not is_anomaly:
            return
        
        print(f"\n{'='*60}")
        print(f"FILE: {filename}")
        print(f"{'='*60}")
        print(f"Type: {'PCAP' if 'packet_count' in result else 'HDF'}")
        print(f"Anomaly Status: ANOMALY DETECTED")
        print(f"Anomaly Score: {anomaly_score:.4f} (lower = more anomalous)")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Additional anomaly indicators
        if has_specific_anomalies:
            print(f"Pattern-based Anomalies: {len(result['anomalies'])} detected")
        if ml_anomaly_detected:
            print(f"ML-based Detection: Isolation Forest flagged as anomaly")
        
        # Display specific anomalies found during analysis
        if 'anomalies' in result and result['anomalies']:
            print(f"\nDetected Issues ({len(result['anomalies'])}):")
            for i, anomaly in enumerate(result['anomalies'], 1):
                severity_level = anomaly.get('severity_level', 'UNKNOWN')
                priority_score = anomaly.get('priority_score', 0.0)
                
                print(f"  {i}. [{severity_level}] {anomaly.get('type', 'unknown')}")
                print(f"     Priority Score: {priority_score:.3f}")
                print(f"     Description: {anomaly.get('description', 'No description')}")
                
                # Display severity classification details
                if 'impact_description' in anomaly:
                    print(f"     Impact: {anomaly['impact_description']}")
                if 'response_time' in anomaly:
                    print(f"     Response Time: {anomaly['response_time']}")
                if 'recommended_action' in anomaly:
                    print(f"     Action: {anomaly['recommended_action']}")
                
                # Display specific packet/event logs for this anomaly
                self._display_anomaly_logs(anomaly, result.get('file', 'Unknown'))
        
        # Display summary statistics
        if 'packet_count' in result:  # PCAP file
            print(f"\nPCAP Statistics:")
            print(f"  Total Packets: {result['packet_count']}")
            print(f"  Protocols: {len(result.get('protocol_stats', {}))}")
            print(f"  Flows: {len(result.get('flow_stats', {}))}")
            print(f"  RU-DU Communications: {len(result.get('ru_du_communications', {}))}")
            
            # Display plane separation
            plane_sep = result.get('plane_separation', {})
            total_plane_packets = plane_sep.get('c_plane', 0) + plane_sep.get('u_plane', 0)
            if total_plane_packets > 0:
                print(f"  Control Plane: {plane_sep.get('c_plane', 0)} ({plane_sep.get('c_plane', 0)/total_plane_packets*100:.1f}%)")
                print(f"  User Plane: {plane_sep.get('u_plane', 0)} ({plane_sep.get('u_plane', 0)/total_plane_packets*100:.1f}%)")
        
        elif 'total_events' in result:  # HDF file
            print(f"\nHDF Statistics:")
            print(f"  Total Events: {result['total_events']}")
            print(f"  Attach Events: {result['attach_events']}")
            print(f"  Detach Events: {result['detach_events']}")
            
            if result['total_events'] > 0:
                attach_ratio = result['attach_events'] / result['total_events']
                detach_ratio = result['detach_events'] / result['total_events']
                print(f"  Attach Ratio: {attach_ratio*100:.1f}%")
                print(f"  Detach Ratio: {detach_ratio*100:.1f}%")
        
        elif 'total_lines' in result:  # CU Log file
            print(f"\nCU Log Statistics:")
            print(f"  Total Lines: {result['total_lines']}")
            
            # Display error analysis
            if 'error_analysis' in result:
                error_analysis = result['error_analysis']
                total_errors = sum(error_analysis.values())
                print(f"  Total Errors: {total_errors}")
                if total_errors > 0:
                    print(f"  Error Types:")
                    for error_type, count in error_analysis.items():
                        if count > 0:
                            print(f"    {error_type.replace('_', ' ').title()}: {count}")
            
            # Display log level distribution
            if 'log_level_analysis' in result:
                log_levels = result['log_level_analysis']
                print(f"  Log Levels:")
                for level, count in log_levels.items():
                    if count > 0:
                        print(f"    {level}: {count}")
            
            # Display timestamp analysis
            if 'timestamp_analysis' in result:
                ts_analysis = result['timestamp_analysis']
                if ts_analysis.get('total_timestamps', 0) > 0:
                    print(f"  Timestamp Analysis:")
                    print(f"    Total Timestamps: {ts_analysis['total_timestamps']}")
                    if ts_analysis.get('max_gap', 0) > 0:
                        print(f"    Max Gap: {ts_analysis['max_gap']:.1f} seconds")
                        print(f"    Average Gap: {ts_analysis['average_gap']:.1f} seconds")
    
    def _display_anomaly_logs(self, anomaly: Dict, filename: str) -> None:
        """Display specific log details for an anomaly."""
        anomaly_type = anomaly.get('type', 'unknown')
        
        print(f"\n     ANOMALY LOG DETAILS:")
        
        if anomaly_type == 'unidirectional_communication':
            # Display specific DU packets that have no RU response
            sample_packets = anomaly.get('sample_packets', [])
            total_du_packets = anomaly.get('total_du_packets', 0)
            total_ru_packets = anomaly.get('total_ru_packets', 0)
            
            print(f"     → Total DU→RU packets: {total_du_packets}, RU→DU responses: {total_ru_packets}")
            print(f"     → Sample DU packets with no RU response:")
            
            for j, packet in enumerate(sample_packets[:3], 1):
                timestamp = packet.get('timestamp', 'N/A')
                if timestamp != 'N/A' and timestamp:
                    from datetime import datetime
                    timestamp = datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S.%f')[:-3]
                
                print(f"        {j}. Packet #{packet.get('packet_index', 'N/A')} at {timestamp}")
                print(f"           {packet.get('src_ip', 'N/A')}:{packet.get('src_port', 'N/A')} → {packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', 'N/A')}")
                print(f"           Protocol: {packet.get('protocol', 'unknown')}, Size: {packet.get('size', 0)} bytes")
                print(f"           Summary: {packet.get('summary', 'N/A')[:80]}...")
        
        elif anomaly_type in ['missing_user_plane', 'missing_control_plane']:
            # Display sample packets from the present plane
            sample_packets = anomaly.get('sample_packets', [])
            missing_plane = anomaly.get('missing_plane', 'unknown')
            present_count = anomaly.get('present_plane_count', 0)
            
            print(f"     → Missing: {missing_plane} plane data")
            print(f"     → Present plane has {present_count} packets")
            print(f"     → Sample packets from present plane:")
            
            for j, packet in enumerate(sample_packets[:3], 1):
                timestamp = packet.get('timestamp', 'N/A')
                if timestamp != 'N/A' and timestamp:
                    from datetime import datetime
                    timestamp = datetime.fromtimestamp(float(timestamp)).strftime('%H:%M:%S.%f')[:-3]
                
                print(f"        {j}. Packet #{packet.get('packet_index', 'N/A')} at {timestamp}")
                print(f"           {packet.get('src_ip', 'N/A')}:{packet.get('src_port', 'N/A')} → {packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', 'N/A')}")
                print(f"           Protocol: {packet.get('protocol', 'unknown')}, Plane: {packet.get('plane', 'unknown')}")
        
        elif anomaly_type == 'unbalanced_attach_detach':
            # Display sample UE events
            sample_attach = anomaly.get('sample_attach_events', [])
            sample_detach = anomaly.get('sample_detach_events', [])
            total_attach = anomaly.get('total_attach_events', 0)
            total_detach = anomaly.get('total_detach_events', 0)
            
            print(f"     → Total attach events: {total_attach}, detach events: {total_detach}")
            
            if sample_attach:
                print(f"     → Sample attach events:")
                for j, event in enumerate(sample_attach[:3], 1):
                    ue_id = event.get('ue_id', 'unknown')
                    timestamp = event.get('timestamp', 'N/A')
                    cell_id = event.get('cell_id', 'unknown')
                    print(f"        {j}. UE {ue_id} attached to {cell_id} at {timestamp}")
            
            if sample_detach:
                print(f"     → Sample detach events:")
                for j, event in enumerate(sample_detach[:3], 1):
                    ue_id = event.get('ue_id', 'unknown')
                    timestamp = event.get('timestamp', 'N/A')
                    cell_id = event.get('cell_id', 'unknown')
                    print(f"        {j}. UE {ue_id} detached from {cell_id} at {timestamp}")
        
        elif anomaly_type == 'rapid_attach_detach_cycle':
            # Display rapid cycling UE events
            ue_id = anomaly.get('details', {}).get('ue_id', 'unknown')
            sample_attach = anomaly.get('sample_ue_attach_events', [])
            sample_detach = anomaly.get('sample_ue_detach_events', [])
            total_ue_attach = anomaly.get('total_ue_attach_events', 0)
            total_ue_detach = anomaly.get('total_ue_detach_events', 0)
            
            print(f"     → UE {ue_id} rapid cycling: {total_ue_attach} attaches, {total_ue_detach} detaches")
            print(f"     → Sample rapid attach events:")
            
            for j, event in enumerate(sample_attach[:3], 1):
                timestamp = event.get('timestamp', 'N/A')
                cell_id = event.get('cell_id', 'unknown')
                print(f"        {j}. UE {ue_id} attached to {cell_id} at {timestamp}")
            
            if sample_detach:
                print(f"     → Sample rapid detach events:")
                for j, event in enumerate(sample_detach[:3], 1):
                    timestamp = event.get('timestamp', 'N/A')
                    cell_id = event.get('cell_id', 'unknown')
                    print(f"        {j}. UE {ue_id} detached from {cell_id} at {timestamp}")
        
        print(f"     Log file: {filename}")
        print()


def main():
    """Main function to run the telecom anomaly detector."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Telecom Anomaly Detection System')
    parser.add_argument('--folder', '-f', type=str, help='Input folder path containing PCAP and HDF files')
    parser.add_argument('--input-dir', '-i', type=str, help='Input directory path (alternative to --folder)')
    
    args = parser.parse_args()
    
    # Use folder parameter (either --folder or --input-dir)
    input_folder = args.folder or args.input_dir
    
    try:
        if input_folder:
            print(f"Processing files from folder: {input_folder}")
            detector = TelecomAnomalyDetector(input_folder=input_folder)
        else:
            print("Using default configured directories")
            detector = TelecomAnomalyDetector()
            
        detector.process_all_files()
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
