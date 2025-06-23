#!/usr/bin/env python3
"""
Check current adaptive contamination configuration
"""

from adaptive_contamination_system import AdaptiveContaminationManager

def check_config():
    manager = AdaptiveContaminationManager()
    
    print("Current Adaptive Contamination Configuration:")
    print("=" * 50)
    print(f"Current Rate: {manager.current_contamination:.1%}")
    print(f"Min Rate: {manager.min_contamination:.1%}")
    print(f"Max Rate: {manager.max_contamination:.1%}")
    print(f"Adaptation Threshold: {manager.adaptation_threshold:.1%}")
    print(f"Max Single Adjustment: {manager.max_adjustment_step:.1%}")
    print(f"Stability Window: {manager.stability_window} readings")
    
    # Show recent statistics
    stats = manager.get_adaptation_statistics()
    print(f"\nAdaptation Statistics:")
    for key, value in stats.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    check_config()