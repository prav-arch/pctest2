#!/usr/bin/env python3
"""
Adaptive Contamination System for Isolation Forest
Dynamically adjusts contamination factor based on real-time anomaly patterns
and network conditions to handle varying anomaly rates.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional
from collections import deque
from datetime import datetime, timedelta
import logging

class AdaptiveContaminationManager:
    """
    Manages dynamic contamination factor adjustment for Isolation Forest
    based on real-time network conditions and historical anomaly patterns.
    """
    
    def __init__(self, initial_contamination: float = 0.1):
        """
        Initialize adaptive contamination manager.
        
        Args:
            initial_contamination: Starting contamination factor (default 10%)
        """
        self.current_contamination = initial_contamination
        self.min_contamination = 0.05  # 5% minimum
        self.max_contamination = 0.5   # 50% maximum for extreme scenarios
        
        # Historical tracking
        self.anomaly_history = deque(maxlen=100)  # Last 100 analysis windows
        self.contamination_history = deque(maxlen=50)
        
        # Network state tracking
        self.network_stress_indicators = {
            'high_unknown_protocols': 0,
            'unidirectional_communications': 0,
            'missing_plane_events': 0,
            'rapid_ue_cycling': 0
        }
        
        # Adaptive parameters
        self.adaptation_threshold = 0.15  # Trigger adaptation if anomaly rate > 15%
        self.stability_window = 10  # Require 10 stable readings before major changes
        self.max_adjustment_step = 0.05  # Maximum single adjustment
        
        self.logger = logging.getLogger('AdaptiveContamination')
    
    def calculate_adaptive_contamination(self, 
                                       recent_anomaly_rate: float,
                                       network_conditions: Dict,
                                       time_of_day: Optional[datetime] = None) -> float:
        """
        Calculate optimal contamination factor based on current conditions.
        
        Args:
            recent_anomaly_rate: Observed anomaly rate in recent analysis
            network_conditions: Current network stress indicators
            time_of_day: Current time for business hours consideration
            
        Returns:
            Optimal contamination factor
        """
        # Record current anomaly rate
        self.anomaly_history.append({
            'timestamp': datetime.now(),
            'anomaly_rate': recent_anomaly_rate,
            'network_conditions': network_conditions.copy()
        })
        
        # Calculate base contamination adjustment
        base_adjustment = self._calculate_base_adjustment(recent_anomaly_rate)
        
        # Apply network condition modifiers
        network_modifier = self._calculate_network_modifier(network_conditions)
        
        # Apply time-based modifiers
        time_modifier = self._calculate_time_modifier(time_of_day)
        
        # Calculate new contamination factor
        proposed_contamination = self.current_contamination + base_adjustment + network_modifier + time_modifier
        
        # Apply constraints and stability checks
        final_contamination = self._apply_constraints_and_stability(proposed_contamination)
        
        # Update tracking
        self.contamination_history.append({
            'timestamp': datetime.now(),
            'old_contamination': self.current_contamination,
            'new_contamination': final_contamination,
            'anomaly_rate': recent_anomaly_rate,
            'adjustment_reason': self._get_adjustment_reason(base_adjustment, network_modifier, time_modifier)
        })
        
        self.current_contamination = final_contamination
        
        self.logger.info(f"Contamination adapted: {self.current_contamination:.3f} "
                        f"(anomaly rate: {recent_anomaly_rate:.2%})")
        
        return self.current_contamination
    
    def _calculate_base_adjustment(self, recent_anomaly_rate: float) -> float:
        """Calculate base contamination adjustment from anomaly rate."""
        if len(self.anomaly_history) < 3:
            return 0.0  # Need sufficient history
        
        # Get recent anomaly rates
        recent_rates = [h['anomaly_rate'] for h in list(self.anomaly_history)[-5:]]
        avg_recent_rate = np.mean(recent_rates)
        
        # Calculate adjustment based on difference from current contamination
        rate_difference = avg_recent_rate - self.current_contamination
        
        if abs(rate_difference) < 0.02:  # Within 2% tolerance
            return 0.0
        
        # Gradual adjustment proportional to difference
        adjustment = rate_difference * 0.3  # 30% of the difference
        
        # Limit adjustment step
        return max(-self.max_adjustment_step, min(self.max_adjustment_step, adjustment))
    
    def _calculate_network_modifier(self, network_conditions: Dict) -> float:
        """Calculate contamination modifier based on network stress."""
        stress_score = 0.0
        
        # High unknown protocol ratio indicates potential attacks
        unknown_ratio = network_conditions.get('unknown_protocol_ratio', 0)
        if unknown_ratio > 0.3:
            stress_score += 0.1  # Increase contamination for security threats
        
        # Multiple unidirectional communications indicate infrastructure issues
        unidirectional_count = network_conditions.get('unidirectional_communications', 0)
        if unidirectional_count > 2:
            stress_score += 0.05
        
        # Missing plane events indicate service degradation
        missing_plane_events = network_conditions.get('missing_plane_events', 0)
        if missing_plane_events > 0:
            stress_score += 0.03
        
        # Rapid UE cycling indicates mobility issues
        rapid_cycling = network_conditions.get('rapid_ue_cycling', 0)
        if rapid_cycling > 3:
            stress_score += 0.02
        
        return min(stress_score, 0.15)  # Cap network modifier at 15%
    
    def _calculate_time_modifier(self, time_of_day: Optional[datetime]) -> float:
        """Calculate contamination modifier based on time patterns."""
        if not time_of_day:
            return 0.0
        
        hour = time_of_day.hour
        
        # Higher contamination during business hours (more activity = more potential issues)
        if 8 <= hour <= 18:  # Business hours
            return 0.01
        elif 22 <= hour or hour <= 6:  # Night hours (maintenance window)
            return 0.02  # Expect more anomalies during maintenance
        else:
            return 0.0
    
    def _apply_constraints_and_stability(self, proposed_contamination: float) -> float:
        """Apply constraints and stability checks to proposed contamination."""
        # Apply min/max constraints
        constrained = max(self.min_contamination, 
                         min(self.max_contamination, proposed_contamination))
        
        # Stability check: avoid oscillation
        if len(self.contamination_history) >= 3:
            recent_changes = [h['new_contamination'] for h in list(self.contamination_history)[-3:]]
            if self._is_oscillating(recent_changes):
                # Return to moving average to stabilize
                return np.mean(recent_changes)
        
        return constrained
    
    def _is_oscillating(self, recent_values: List[float]) -> bool:
        """Check if contamination values are oscillating."""
        if len(recent_values) < 3:
            return False
        
        # Check for alternating up/down pattern
        diffs = [recent_values[i+1] - recent_values[i] for i in range(len(recent_values)-1)]
        
        # Oscillation detected if signs alternate and changes are significant
        sign_changes = sum(1 for i in range(len(diffs)-1) 
                          if (diffs[i] > 0) != (diffs[i+1] > 0) and abs(diffs[i]) > 0.02)
        
        return sign_changes >= 1
    
    def _get_adjustment_reason(self, base_adj: float, network_mod: float, time_mod: float) -> str:
        """Get human-readable reason for contamination adjustment."""
        reasons = []
        
        if abs(base_adj) > 0.01:
            if base_adj > 0:
                reasons.append("high_anomaly_rate")
            else:
                reasons.append("low_anomaly_rate")
        
        if network_mod > 0.02:
            reasons.append("network_stress")
        
        if time_mod > 0:
            reasons.append("time_based")
        
        return ",".join(reasons) if reasons else "stability"
    
    def get_contamination_for_severity(self, severity_distribution: Dict) -> float:
        """
        Suggest contamination based on severity distribution of recent anomalies.
        
        Args:
            severity_distribution: Count of anomalies by severity level
            
        Returns:
            Recommended contamination factor
        """
        total_anomalies = sum(severity_distribution.values())
        if total_anomalies == 0:
            return max(0.05, self.current_contamination * 0.9)  # Reduce if no anomalies
        
        # Weight by severity impact
        severity_weights = {
            'CRITICAL': 5.0,
            'HIGH': 3.0,
            'MEDIUM': 1.5,
            'LOW': 1.0,
            'INFO': 0.5
        }
        
        weighted_score = sum(count * severity_weights.get(severity, 1.0) 
                           for severity, count in severity_distribution.items())
        
        # Convert to contamination factor
        base_rate = total_anomalies / 100  # Assume 100 samples analyzed
        severity_multiplier = weighted_score / max(total_anomalies, 1)
        
        recommended = base_rate * severity_multiplier
        
        return max(self.min_contamination, 
                  min(self.max_contamination, recommended))
    
    def get_adaptation_statistics(self) -> Dict:
        """Get statistics about contamination adaptation performance."""
        if not self.contamination_history:
            return {'status': 'no_data'}
        
        recent_history = list(self.contamination_history)[-20:]  # Last 20 adaptations
        
        return {
            'current_contamination': self.current_contamination,
            'adaptations_count': len(self.contamination_history),
            'avg_contamination': np.mean([h['new_contamination'] for h in recent_history]),
            'contamination_stability': np.std([h['new_contamination'] for h in recent_history]),
            'recent_anomaly_rates': [h['anomaly_rate'] for h in list(self.anomaly_history)[-10:]],
            'adaptation_triggers': [h['adjustment_reason'] for h in recent_history],
            'min_used': min(h['new_contamination'] for h in recent_history),
            'max_used': max(h['new_contamination'] for h in recent_history)
        }

def demonstrate_adaptive_contamination():
    """Demonstrate adaptive contamination in different scenarios."""
    print("ADAPTIVE CONTAMINATION SYSTEM DEMO")
    print("=" * 50)
    
    manager = AdaptiveContaminationManager(initial_contamination=0.1)
    
    # Simulate different network scenarios
    scenarios = [
        {
            'name': 'Normal Operations',
            'anomaly_rate': 0.08,
            'conditions': {'unknown_protocol_ratio': 0.02, 'unidirectional_communications': 0}
        },
        {
            'name': 'Security Attack',
            'anomaly_rate': 0.35,
            'conditions': {'unknown_protocol_ratio': 0.45, 'unidirectional_communications': 1}
        },
        {
            'name': 'Infrastructure Failure',
            'anomaly_rate': 0.25,
            'conditions': {'unknown_protocol_ratio': 0.05, 'unidirectional_communications': 5, 'missing_plane_events': 3}
        },
        {
            'name': 'Maintenance Window',
            'anomaly_rate': 0.15,
            'conditions': {'unknown_protocol_ratio': 0.08, 'rapid_ue_cycling': 4}
        },
        {
            'name': 'Return to Normal',
            'anomaly_rate': 0.07,
            'conditions': {'unknown_protocol_ratio': 0.01, 'unidirectional_communications': 0}
        }
    ]
    
    print("Scenario Analysis:")
    print("-" * 30)
    
    for scenario in scenarios:
        contamination = manager.calculate_adaptive_contamination(
            scenario['anomaly_rate'],
            scenario['conditions']
        )
        
        print(f"{scenario['name']:20} | Rate: {scenario['anomaly_rate']:5.1%} | "
              f"Contamination: {contamination:5.1%}")
    
    print()
    print("Adaptation Statistics:")
    stats = manager.get_adaptation_statistics()
    print(f"  Adaptations made: {stats['adaptations_count']}")
    print(f"  Average contamination: {stats['avg_contamination']:.1%}")
    print(f"  Range used: {stats['min_used']:.1%} - {stats['max_used']:.1%}")

if __name__ == "__main__":
    demonstrate_adaptive_contamination()