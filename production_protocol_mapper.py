#!/usr/bin/env python3
"""
Production Protocol Mapper for Telecom Anomaly Detection.
Handles varying protocol names, port numbers, and packet structures in real PCAP files.
"""

import re
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ProtocolPattern:
    """Protocol identification pattern."""
    names: List[str]          # Possible protocol names
    ports: List[int]          # Port numbers
    keywords: List[str]       # Payload keywords
    plane: str               # 'control', 'user', or 'other'
    priority: int            # Detection priority (1=highest)

class ProductionProtocolMapper:
    """
    Maps varying protocol names and structures to standardized telecom protocols.
    Handles real-world PCAP file variations.
    """
    
    def __init__(self):
        """Initialize protocol mapping patterns."""
        self.protocol_patterns = self._initialize_protocol_patterns()
        self.mac_patterns = self._initialize_mac_patterns()
        self.port_fallbacks = self._initialize_port_fallbacks()
        
    def _initialize_protocol_patterns(self) -> Dict[str, ProtocolPattern]:
        """Initialize comprehensive protocol identification patterns."""
        return {
            'F1_C': ProtocolPattern(
                names=['F1-C', 'F1C', 'F1_Control', 'F1-Control', 'f1c', 'F1-AP'],
                ports=[38412, 38472, 9999, 36412],
                keywords=['F1AP', 'F1-C', 'gNB-DU', 'gNB-CU'],
                plane='control',
                priority=1
            ),
            'F1_U': ProtocolPattern(
                names=['F1-U', 'F1U', 'F1_User', 'F1-User', 'f1u', 'F1-UP'],
                ports=[2152, 2123, 4997],
                keywords=['GTP-U', 'F1-U', 'TEID'],
                plane='user',
                priority=1
            ),
            'CPRI': ProtocolPattern(
                names=['CPRI', 'eCPRI', 'C-RAN', 'CRAN', 'cpri'],
                ports=[4991, 4992, 2152],
                keywords=['CPRI', 'eCPRI', 'IQ', 'Radio'],
                plane='other',
                priority=2
            ),
            'NGAP': ProtocolPattern(
                names=['NGAP', 'NG-AP', 'ngap', '5G-NAS'],
                ports=[38412, 36412],
                keywords=['NGAP', 'AMF', '5G-NAS'],
                plane='control',
                priority=1
            ),
            'S1_MME': ProtocolPattern(
                names=['S1-MME', 'S1MME', 'S1AP', 's1ap', 'S1-AP'],
                ports=[36412, 2123],
                keywords=['S1AP', 'MME', 'eNB'],
                plane='control',
                priority=2
            ),
            'S1_U': ProtocolPattern(
                names=['S1-U', 'S1U', 'S1-User', 's1u'],
                ports=[2152],
                keywords=['GTP-U', 'S1-U'],
                plane='user',
                priority=2
            )
        }
    
    def _initialize_mac_patterns(self) -> Dict[str, List[str]]:
        """Initialize MAC address patterns for device identification."""
        return {
            'DU_PATTERNS': [
                '00:11:22:33:44:67',  # User-specific DU MACs
                '00:11:22:33:44:66',
                '00:1[0-9a-f]:22:33:44:[0-9a-f]{2}',  # DU MAC pattern
                '02:[0-9a-f]{2}:22:33:44:[0-9a-f]{2}',  # Alternative DU pattern
                '([0-9a-f]{2}:){5}[0-9a-f]{2}'  # Generic pattern fallback
            ],
            'RU_PATTERNS': [
                '00:1[0-9a-f]:11:22:33:[0-9a-f]{2}',  # RU MAC pattern
                '01:[0-9a-f]{2}:11:22:33:[0-9a-f]{2}',  # Alternative RU pattern
                '([0-9a-f]{2}:){5}[0-9a-f]{2}'  # Generic pattern fallback
            ]
        }
    
    def _initialize_port_fallbacks(self) -> Dict[str, List[int]]:
        """Initialize port number fallbacks for different vendors."""
        return {
            'CONTROL_PORTS': [36412, 38412, 38472, 2123, 9999, 8080, 443],
            'USER_PORTS': [2152, 4997, 8080, 9001, 9002],
            'CPRI_PORTS': [4991, 4992, 2152, 8001, 8002],
            'VENDOR_SPECIFIC': list(range(8000, 8100)) + list(range(9000, 9100))
        }
    
    def identify_protocol(self, packet, packet_payload: bytes = None) -> Dict:
        """
        Identify protocol from packet using multiple detection methods.
        
        Args:
            packet: Scapy packet object
            packet_payload: Raw packet payload bytes
            
        Returns:
            Protocol information dictionary
        """
        protocol_info = {'protocol': 'unknown', 'plane': 'other', 'confidence': 0.0}
        
        # Method 1: Port-based identification
        port_result = self._identify_by_port(packet)
        if port_result['confidence'] > protocol_info['confidence']:
            protocol_info = port_result
        
        # Method 2: Payload-based identification
        if packet_payload:
            payload_result = self._identify_by_payload(packet_payload)
            if payload_result['confidence'] > protocol_info['confidence']:
                protocol_info = payload_result
        
        # Method 3: Pattern-based identification
        pattern_result = self._identify_by_pattern(packet)
        if pattern_result['confidence'] > protocol_info['confidence']:
            protocol_info = pattern_result
        
        return protocol_info
    
    def _identify_by_port(self, packet) -> Dict:
        """Identify protocol by port numbers."""
        ports = []
        
        # Extract ports from different protocol layers
        if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
            ports = [packet.sport, packet.dport]
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            ports = [udp_layer.sport, udp_layer.dport]
        elif packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            ports = [tcp_layer.sport, tcp_layer.dport]
        
        best_match = {'protocol': 'unknown', 'plane': 'other', 'confidence': 0.0}
        
        for protocol, pattern in self.protocol_patterns.items():
            for port in ports:
                if port in pattern.ports:
                    confidence = 0.8 / pattern.priority  # Higher priority = higher confidence
                    if confidence > best_match['confidence']:
                        best_match = {
                            'protocol': protocol,
                            'plane': pattern.plane,
                            'confidence': confidence
                        }
        
        return best_match
    
    def _identify_by_payload(self, payload: bytes) -> Dict:
        """Identify protocol by payload content."""
        payload_str = payload.hex() if isinstance(payload, bytes) else str(payload)
        payload_ascii = payload.decode('ascii', errors='ignore') if isinstance(payload, bytes) else payload
        
        best_match = {'protocol': 'unknown', 'plane': 'other', 'confidence': 0.0}
        
        for protocol, pattern in self.protocol_patterns.items():
            matches = 0
            for keyword in pattern.keywords:
                if keyword.lower() in payload_ascii.lower() or keyword.lower() in payload_str.lower():
                    matches += 1
            
            if matches > 0:
                confidence = (matches / len(pattern.keywords)) * 0.9
                if confidence > best_match['confidence']:
                    best_match = {
                        'protocol': protocol,
                        'plane': pattern.plane,
                        'confidence': confidence
                    }
        
        return best_match
    
    def _identify_by_pattern(self, packet) -> Dict:
        """Identify protocol by packet structure patterns."""
        # Check for specific packet sizes, timing, or other characteristics
        packet_size = len(packet) if hasattr(packet, '__len__') else 0
        
        # CPRI typically has specific packet sizes
        if 64 <= packet_size <= 1518:
            if packet_size % 4 == 0:  # CPRI packets often align to 4-byte boundaries
                return {'protocol': 'CPRI', 'plane': 'other', 'confidence': 0.3}
        
        # Large packets often indicate user plane data
        if packet_size > 1000:
            return {'protocol': 'F1_U', 'plane': 'user', 'confidence': 0.2}
        
        # Small packets often indicate control plane
        if packet_size < 200:
            return {'protocol': 'F1_C', 'plane': 'control', 'confidence': 0.2}
        
        return {'protocol': 'unknown', 'plane': 'other', 'confidence': 0.0}
    
    def identify_device_type(self, mac_address: str) -> str:
        """
        Identify device type (DU/RU) from MAC address using flexible patterns.
        
        Args:
            mac_address: MAC address string
            
        Returns:
            Device type: 'DU', 'RU', or 'unknown'
        """
        if not mac_address:
            return 'unknown'
        
        mac_clean = mac_address.lower().replace('-', ':')
        
        # Check DU patterns first (more specific)
        for pattern in self.mac_patterns['DU_PATTERNS']:
            if re.match(pattern.lower(), mac_clean):
                return 'DU'
        
        # Check RU patterns
        for pattern in self.mac_patterns['RU_PATTERNS']:
            if re.match(pattern.lower(), mac_clean):
                return 'RU'
        
        return 'unknown'
    
    def get_protocol_mapping_stats(self, detected_protocols: Dict) -> Dict:
        """Get statistics about protocol detection success."""
        total_packets = sum(detected_protocols.values())
        unknown_count = detected_protocols.get('unknown', 0)
        
        return {
            'total_packets': total_packets,
            'unknown_packets': unknown_count,
            'unknown_ratio': unknown_count / total_packets if total_packets > 0 else 0,
            'protocol_diversity': len(detected_protocols),
            'detection_success_rate': (total_packets - unknown_count) / total_packets if total_packets > 0 else 0
        }
    
    def suggest_protocol_improvements(self, stats: Dict) -> List[str]:
        """Suggest improvements based on detection statistics."""
        suggestions = []
        
        if stats['unknown_ratio'] > 0.3:
            suggestions.append("High unknown protocol ratio - consider adding vendor-specific patterns")
        
        if stats['protocol_diversity'] < 3:
            suggestions.append("Low protocol diversity - verify PCAP contains telecom traffic")
        
        if stats['detection_success_rate'] < 0.7:
            suggestions.append("Low detection rate - review port mappings for your network")
        
        return suggestions

def main():
    """Demonstrate production protocol mapping capabilities."""
    mapper = ProductionProtocolMapper()
    
    print("PRODUCTION PROTOCOL MAPPER DEMO")
    print("=" * 40)
    print("Handles varying protocol names and packet structures in real PCAP files")
    print()
    
    # Demo various protocol identification scenarios
    test_scenarios = [
        {"description": "Standard F1-C packet", "ports": [38412, 9001], "payload": b"F1AP"},
        {"description": "Vendor-specific port", "ports": [8080, 8081], "payload": b"gNB-DU"},
        {"description": "Unknown protocol", "ports": [12345, 54321], "payload": b"CUSTOM"},
    ]
    
    for scenario in test_scenarios:
        print(f"Testing: {scenario['description']}")
        # This would work with actual packet objects
        print(f"  Ports: {scenario['ports']}")
        print(f"  Would identify based on multiple detection methods")
        print()

if __name__ == "__main__":
    main()