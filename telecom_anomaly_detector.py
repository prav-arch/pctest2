#!/usr/bin/env python3
"""
Telecom Anomaly Detection Script
Standalone Python script for detecting anomalies in PCAP and HDF files
using Isolation Forest algorithm for unsupervised learning.
"""

import os
import glob
import logging
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple, Optional
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

class TelecomAnomalyDetector:
    """
    Main class for telecom anomaly detection using Isolation Forest algorithm.
    Processes PCAP files for protocol analysis and HDF files for UE events.
    """
    
    def __init__(self):
        self.config = Config()
        self.logger = setup_logging()
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.model_trained = False
        self.feature_columns = []
        
        # Telecom protocol ports and identifiers
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
    
    def _create_new_model(self) -> None:
        """Create new Isolation Forest model."""
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        self.logger.info("Created new Isolation Forest model")
    
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
                if not packet.haslayer(IP):
                    continue
                    
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Create detailed packet log
                packet_log = {
                    'packet_index': i,
                    'timestamp': packet.time if hasattr(packet, 'time') else None,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
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
                
                # Track flow statistics
                flow_key = f"{src_ip}:{dst_ip}"
                flow_stats[flow_key]['packets'] += 1
                flow_stats[flow_key]['bytes'] += len(packet)
                flow_stats[flow_key]['directions'].add(f"{src_ip}->{dst_ip}")
                
                # Track RU-DU communications with packet details
                if self._is_ru_du_communication(src_ip, dst_ip):
                    if self._is_du_ip(src_ip):
                        comm_key = f"{src_ip}-{dst_ip}"
                        ru_du_communications[comm_key]['du_to_ru'] += 1
                        ru_du_communications[comm_key]['du_packets'].append(packet_log)
                    elif self._is_ru_ip(src_ip):
                        comm_key = f"{dst_ip}-{src_ip}"
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
        """Identify telecom protocol from packet."""
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
    
    def _is_ru_du_communication(self, src_ip: str, dst_ip: str) -> bool:
        """Check if communication is between RU and DU."""
        # Simple heuristic: assume RU IPs start with 192.168.1.x and DU with 192.168.2.x
        ru_pattern = src_ip.startswith('192.168.1.') or dst_ip.startswith('192.168.1.')
        du_pattern = src_ip.startswith('192.168.2.') or dst_ip.startswith('192.168.2.')
        return ru_pattern and du_pattern
    
    def _is_du_ip(self, ip: str) -> bool:
        """Check if IP belongs to DU."""
        return ip.startswith('192.168.2.')
    
    def _is_ru_ip(self, ip: str) -> bool:
        """Check if IP belongs to RU."""
        return ip.startswith('192.168.1.')
    
    def _detect_communication_anomalies(self, protocol_stats, flow_stats, 
                                       ru_du_communications, plane_separation, packet_logs) -> List[Dict]:
        """Detect specific telecom communication anomalies."""
        anomalies = []
        
        # Check for unidirectional RU-DU communication
        for comm_pair, stats in ru_du_communications.items():
            if stats['du_to_ru'] > 0 and stats['ru_to_du'] == 0:
                # Get sample DU packets for logging
                sample_du_packets = stats['du_packets'][:5]  # Show first 5 packets
                anomalies.append({
                    'type': 'unidirectional_communication',
                    'description': f"DU sending to RU but no response from RU: {comm_pair}",
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
                anomalies.append({
                    'type': 'missing_control_plane',
                    'description': f"Very low control plane traffic: {c_plane_ratio:.2%}",
                    'severity': 'medium',
                    'details': plane_separation,
                    'sample_packets': sample_u_packets,
                    'missing_plane': 'control',
                    'present_plane_count': len(plane_separation.get('u_plane_packets', []))
                })
            
            if u_plane_ratio < 0.1:  # Less than 10% user plane
                # Get sample control plane packets that are present
                sample_c_packets = plane_separation.get('c_plane_packets', [])[:3]
                anomalies.append({
                    'type': 'missing_user_plane',
                    'description': f"Very low user plane traffic: {u_plane_ratio:.2%}",
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
        
        return anomalies
    
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
                anomalies.append({
                    'type': 'unbalanced_attach_detach',
                    'description': f"Unbalanced attach/detach ratio: {attach_ratio:.2%} attach, {detach_ratio:.2%} detach",
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
        
        return anomalies
    
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
            # Convert to numpy array and handle any missing values
            X = np.array(all_features)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest.fit(X_scaled)
            self.model_trained = True
            
            self.logger.info(f"Model trained on {len(all_features)} samples with {X.shape[1]} features")
            
            # Save the trained model
            self.save_model()
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
    
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
    
    def process_all_files(self) -> None:
        """Process all PCAP and HDF files from configured directories."""
        self.logger.info("Starting telecom anomaly detection...")
        
        # Load or create model
        self.load_or_create_model()
        
        # Find all files to process
        pcap_files = []
        hdf_files = []
        
        for pcap_dir in self.config.PCAP_DIRS:
            if os.path.exists(pcap_dir):
                pcap_files.extend(glob.glob(os.path.join(pcap_dir, "*.pcap")))
                pcap_files.extend(glob.glob(os.path.join(pcap_dir, "*.cap")))
            else:
                self.logger.warning(f"PCAP directory not found: {pcap_dir}")
        
        for hdf_dir in self.config.HDF_DIRS:
            if os.path.exists(hdf_dir):
                hdf_files.extend(glob.glob(os.path.join(hdf_dir, "*.h5")))
                hdf_files.extend(glob.glob(os.path.join(hdf_dir, "*.hdf5")))
            else:
                self.logger.warning(f"HDF directory not found: {hdf_dir}")
        
        self.logger.info(f"Found {len(pcap_files)} PCAP files and {len(hdf_files)} HDF files")
        
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
        
        # Train model if not already trained or retrain with new data
        if not self.model_trained or len(all_features) > 0:
            self.train_model(all_features)
        
        # Detect anomalies
        self.logger.info("\n" + "="*80)
        self.logger.info("ANOMALY DETECTION RESULTS")
        self.logger.info("="*80)
        
        total_anomalies = 0
        
        for result in all_results:
            if 'features' in result:
                prediction, anomaly_score = self.predict_anomalies(result['features'])
                
                # Display results
                self._display_file_results(result, prediction, anomaly_score)
                
                if prediction == -1:  # Anomaly detected
                    total_anomalies += 1
        
        self.logger.info(f"\nTotal files processed: {len(all_results)}")
        self.logger.info(f"Total anomalies detected: {total_anomalies}")
        self.logger.info(f"Anomaly rate: {total_anomalies/len(all_results)*100:.2f}%" if all_results else "N/A")
    
    def _display_file_results(self, result: Dict, prediction: int, anomaly_score: float) -> None:
        """Display analysis results for a single file."""
        filename = os.path.basename(result['file'])
        is_anomaly = prediction == -1
        
        print(f"\n{'='*60}")
        print(f"FILE: {filename}")
        print(f"{'='*60}")
        print(f"Type: {'PCAP' if 'packet_count' in result else 'HDF'}")
        print(f"Anomaly Status: {'🚨 ANOMALY DETECTED' if is_anomaly else '✅ NORMAL'}")
        print(f"Anomaly Score: {anomaly_score:.4f} (lower = more anomalous)")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Display specific anomalies found during analysis
        if 'anomalies' in result and result['anomalies']:
            print(f"\nDetected Issues ({len(result['anomalies'])}):")
            for i, anomaly in enumerate(result['anomalies'], 1):
                severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(anomaly.get('severity', 'low'), '🔵')
                print(f"  {i}. {severity_emoji} [{anomaly.get('severity', 'unknown').upper()}] {anomaly.get('type', 'unknown')}")
                print(f"     Description: {anomaly.get('description', 'No description')}")
                
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
    
    def _display_anomaly_logs(self, anomaly: Dict, filename: str) -> None:
        """Display specific log details for an anomaly."""
        anomaly_type = anomaly.get('type', 'unknown')
        
        print(f"\n     📋 ANOMALY LOG DETAILS:")
        
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
        
        print(f"     📁 Log file: {filename}")
        print()


def main():
    """Main function to run the telecom anomaly detector."""
    print("Telecom Anomaly Detection System")
    print("=" * 50)
    print("Using Isolation Forest for Unsupervised Learning")
    print("Analyzing PCAP and HDF files for telecom anomalies...")
    print()
    
    try:
        detector = TelecomAnomalyDetector()
        detector.process_all_files()
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
