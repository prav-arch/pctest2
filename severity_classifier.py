#!/usr/bin/env python3
"""
Anomaly Severity Classification System for Telecom Network Monitoring.
Classifies anomalies based on impact, urgency, and operational criticality.
"""

from enum import Enum
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import logging

class SeverityLevel(Enum):
    """Anomaly severity levels with operational impact."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class SeverityMetrics:
    """Metrics used for severity classification."""
    network_impact: float  # 0.0-1.0 (network disruption level)
    service_impact: float  # 0.0-1.0 (service availability impact)
    urgency: float         # 0.0-1.0 (response time requirement)
    frequency: float       # 0.0-1.0 (occurrence frequency)
    duration: float        # 0.0-1.0 (persistence duration)

@dataclass
class AnomalyClassification:
    """Complete anomaly classification result."""
    severity: SeverityLevel
    priority_score: float
    impact_description: str
    recommended_action: str
    response_time: str
    escalation_required: bool

class SeverityClassifier:
    """
    Classifies telecom anomalies by severity based on multiple factors.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Severity thresholds for priority scoring
        self.severity_thresholds = {
            SeverityLevel.CRITICAL: 0.85,
            SeverityLevel.HIGH: 0.70,
            SeverityLevel.MEDIUM: 0.50,
            SeverityLevel.LOW: 0.30,
            SeverityLevel.INFO: 0.0
        }
        
        # Anomaly type base metrics
        self.anomaly_base_metrics = {
            "unidirectional_communication": SeverityMetrics(0.9, 0.8, 0.9, 0.7, 0.8),
            "missing_control_plane": SeverityMetrics(0.95, 0.9, 0.95, 0.6, 0.9),
            "missing_user_plane": SeverityMetrics(0.8, 0.7, 0.8, 0.6, 0.7),
            "protocol_deviation": SeverityMetrics(0.7, 0.6, 0.7, 0.8, 0.6),
            "excessive_retransmissions": SeverityMetrics(0.6, 0.5, 0.6, 0.9, 0.5),
            "unbalanced_attach_detach": SeverityMetrics(0.5, 0.4, 0.5, 0.7, 0.6),
            "rapid_ue_cycling": SeverityMetrics(0.7, 0.6, 0.7, 0.8, 0.4),
            "bandwidth_anomaly": SeverityMetrics(0.6, 0.5, 0.6, 0.7, 0.5),
            "latency_spike": SeverityMetrics(0.8, 0.7, 0.8, 0.6, 0.3),
            "connection_drops": SeverityMetrics(0.9, 0.8, 0.9, 0.8, 0.7),
        }
        
        # Response time requirements
        self.response_times = {
            SeverityLevel.CRITICAL: "Immediate (< 15 minutes)",
            SeverityLevel.HIGH: "Urgent (< 1 hour)",
            SeverityLevel.MEDIUM: "High (< 4 hours)",
            SeverityLevel.LOW: "Normal (< 24 hours)",
            SeverityLevel.INFO: "Low (< 72 hours)"
        }
        
        # Recommended actions
        self.recommended_actions = {
            SeverityLevel.CRITICAL: "Emergency response: Isolate affected components, activate backup systems",
            SeverityLevel.HIGH: "Immediate investigation: Check system logs, verify configurations",
            SeverityLevel.MEDIUM: "Scheduled investigation: Monitor trends, plan maintenance",
            SeverityLevel.LOW: "Routine monitoring: Log for analysis, trend monitoring",
            SeverityLevel.INFO: "Informational: Archive for future reference"
        }

    def classify_anomaly(self, anomaly_type: str, context: Dict) -> AnomalyClassification:
        """
        Classify an anomaly and determine its severity level.
        
        Args:
            anomaly_type: Type of anomaly detected
            context: Additional context about the anomaly
            
        Returns:
            Complete anomaly classification
        """
        # Get base metrics for anomaly type
        base_metrics = self.anomaly_base_metrics.get(
            anomaly_type, 
            SeverityMetrics(0.5, 0.5, 0.5, 0.5, 0.5)
        )
        
        # Adjust metrics based on context
        adjusted_metrics = self._adjust_metrics_for_context(base_metrics, context)
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(adjusted_metrics)
        
        # Determine severity level
        severity = self._determine_severity_level(priority_score)
        
        # Generate impact description
        impact_description = self._generate_impact_description(
            anomaly_type, severity, context
        )
        
        return AnomalyClassification(
            severity=severity,
            priority_score=priority_score,
            impact_description=impact_description,
            recommended_action=self.recommended_actions[severity],
            response_time=self.response_times[severity],
            escalation_required=severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        )

    def _adjust_metrics_for_context(self, base_metrics: SeverityMetrics, context: Dict) -> SeverityMetrics:
        """Adjust base metrics based on anomaly context."""
        network_impact = base_metrics.network_impact
        service_impact = base_metrics.service_impact
        urgency = base_metrics.urgency
        frequency = base_metrics.frequency
        duration = base_metrics.duration
        
        # Adjust based on affected device count
        affected_devices = context.get('affected_devices', 1)
        if affected_devices > 10:
            network_impact = min(1.0, network_impact * 1.3)
            service_impact = min(1.0, service_impact * 1.3)
        elif affected_devices > 5:
            network_impact = min(1.0, network_impact * 1.2)
            service_impact = min(1.0, service_impact * 1.2)
        
        # Adjust based on packet loss
        packet_loss = context.get('packet_loss_rate', 0.0)
        if packet_loss > 0.1:  # > 10% loss
            network_impact = min(1.0, network_impact * 1.4)
            urgency = min(1.0, urgency * 1.3)
        elif packet_loss > 0.05:  # > 5% loss
            network_impact = min(1.0, network_impact * 1.2)
            urgency = min(1.0, urgency * 1.2)
        
        # Adjust based on duration
        duration_minutes = context.get('duration_minutes', 0)
        if duration_minutes > 60:  # > 1 hour
            duration = min(1.0, duration * 1.5)
            service_impact = min(1.0, service_impact * 1.3)
        elif duration_minutes > 30:  # > 30 minutes
            duration = min(1.0, duration * 1.3)
            service_impact = min(1.0, service_impact * 1.2)
        
        # Adjust based on business hours
        is_business_hours = context.get('is_business_hours', True)
        if is_business_hours:
            service_impact = min(1.0, service_impact * 1.2)
            urgency = min(1.0, urgency * 1.2)
        
        # Adjust based on anomaly score
        anomaly_score = context.get('anomaly_score', 0.0)
        if anomaly_score < -0.5:  # Very anomalous
            network_impact = min(1.0, network_impact * 1.3)
            urgency = min(1.0, urgency * 1.3)
        elif anomaly_score < -0.2:  # Moderately anomalous
            network_impact = min(1.0, network_impact * 1.1)
            urgency = min(1.0, urgency * 1.1)
        
        return SeverityMetrics(
            network_impact=network_impact,
            service_impact=service_impact,
            urgency=urgency,
            frequency=frequency,
            duration=duration
        )

    def _calculate_priority_score(self, metrics: SeverityMetrics) -> float:
        """Calculate overall priority score from metrics."""
        # Weighted scoring - network and service impact are most important
        weights = {
            'network_impact': 0.35,
            'service_impact': 0.30,
            'urgency': 0.20,
            'frequency': 0.10,
            'duration': 0.05
        }
        
        score = (
            metrics.network_impact * weights['network_impact'] +
            metrics.service_impact * weights['service_impact'] +
            metrics.urgency * weights['urgency'] +
            metrics.frequency * weights['frequency'] +
            metrics.duration * weights['duration']
        )
        
        return min(1.0, max(0.0, score))

    def _determine_severity_level(self, priority_score: float) -> SeverityLevel:
        """Determine severity level from priority score."""
        for severity, threshold in self.severity_thresholds.items():
            if priority_score >= threshold:
                return severity
        return SeverityLevel.INFO

    def _generate_impact_description(self, anomaly_type: str, severity: SeverityLevel, context: Dict) -> str:
        """Generate human-readable impact description."""
        base_descriptions = {
            "unidirectional_communication": "RU-DU communication failure affects network reliability",
            "missing_control_plane": "Control plane failure disrupts network management",
            "missing_user_plane": "User plane failure impacts data transmission",
            "protocol_deviation": "Protocol violations may cause compatibility issues",
            "excessive_retransmissions": "High retransmission rate indicates network congestion",
            "unbalanced_attach_detach": "UE attachment imbalance suggests mobility issues",
            "rapid_ue_cycling": "Rapid UE state changes indicate network instability",
            "bandwidth_anomaly": "Bandwidth usage anomaly affects service quality",
            "latency_spike": "High latency impacts user experience",
            "connection_drops": "Connection failures disrupt service availability"
        }
        
        base_description = base_descriptions.get(
            anomaly_type, 
            "Network anomaly detected"
        )
        
        # Add severity-specific context
        if severity == SeverityLevel.CRITICAL:
            impact_modifier = "CRITICAL: Service outage imminent or in progress"
        elif severity == SeverityLevel.HIGH:
            impact_modifier = "HIGH: Significant service degradation likely"
        elif severity == SeverityLevel.MEDIUM:
            impact_modifier = "MEDIUM: Moderate impact on service quality"
        elif severity == SeverityLevel.LOW:
            impact_modifier = "LOW: Minor impact, monitor for trends"
        else:
            impact_modifier = "INFO: No immediate impact expected"
        
        # Add contextual details
        details = []
        if context.get('affected_devices', 0) > 1:
            details.append(f"{context['affected_devices']} devices affected")
        
        if context.get('packet_loss_rate', 0) > 0:
            details.append(f"{context['packet_loss_rate']*100:.1f}% packet loss")
        
        if context.get('duration_minutes', 0) > 0:
            details.append(f"Duration: {context['duration_minutes']} minutes")
        
        detail_string = f" ({', '.join(details)})" if details else ""
        
        return f"{impact_modifier}. {base_description}{detail_string}"

    def classify_multiple_anomalies(self, anomalies: List[Dict]) -> List[Tuple[Dict, AnomalyClassification]]:
        """
        Classify multiple anomalies and sort by priority.
        
        Args:
            anomalies: List of anomaly dictionaries
            
        Returns:
            List of (anomaly, classification) tuples sorted by priority
        """
        classified_anomalies = []
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            context = anomaly.get('context', {})
            
            classification = self.classify_anomaly(anomaly_type, context)
            classified_anomalies.append((anomaly, classification))
        
        # Sort by priority score (highest first)
        classified_anomalies.sort(key=lambda x: x[1].priority_score, reverse=True)
        
        return classified_anomalies

    def get_severity_statistics(self, classifications: List[AnomalyClassification]) -> Dict:
        """Generate severity distribution statistics."""
        stats = {level: 0 for level in SeverityLevel}
        
        for classification in classifications:
            stats[classification.severity] += 1
        
        total = len(classifications)
        percentages = {
            level: (count / total * 100) if total > 0 else 0 
            for level, count in stats.items()
        }
        
        return {
            'counts': stats,
            'percentages': percentages,
            'total': total,
            'critical_high_count': stats[SeverityLevel.CRITICAL] + stats[SeverityLevel.HIGH],
            'escalation_required': stats[SeverityLevel.CRITICAL] + stats[SeverityLevel.HIGH]
        }