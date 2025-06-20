#!/usr/bin/env python3
"""
Create simple test data for telecom anomaly detection.
"""

import os
import numpy as np
import h5py

def create_simple_hdf():
    """Create simple HDF files for testing."""
    os.makedirs("./hdf_files", exist_ok=True)
    
    # Normal HDF file
    with h5py.File("./hdf_files/normal_ue_events.hdf5", "w") as f:
        # Simple attach events
        attach_data = np.array([
            (b"UE_001", 1734700000, b"attach", b"cell_1", 1),
            (b"UE_002", 1734700010, b"attach", b"cell_2", 1),
            (b"UE_003", 1734700020, b"attach", b"cell_1", 1),
        ], dtype=[('ue_id', 'S10'), ('timestamp', 'i8'), ('event_type', 'S10'), ('cell_id', 'S10'), ('status', 'i4')])
        
        # Simple detach events
        detach_data = np.array([
            (b"UE_001", 1734700100, b"detach", b"cell_1", 0),
            (b"UE_002", 1734700110, b"detach", b"cell_2", 0),
            (b"UE_003", 1734700120, b"detach", b"cell_1", 0),
        ], dtype=[('ue_id', 'S10'), ('timestamp', 'i8'), ('event_type', 'S10'), ('cell_id', 'S10'), ('status', 'i4')])
        
        f.create_dataset("attach_events", data=attach_data)
        f.create_dataset("detach_events", data=detach_data)
        f.attrs['file_type'] = 'Normal_UE_Events'
    
    # Anomalous HDF file
    with h5py.File("./hdf_files/anomalous_ue_events.hdf5", "w") as f:
        # Many attach events, few detach events (unbalanced)
        attach_data = np.array([
            (b"UE_001", 1734700000, b"attach", b"cell_1", 1),
            (b"UE_002", 1734700010, b"attach", b"cell_2", 1),
            (b"UE_003", 1734700020, b"attach", b"cell_1", 1),
            (b"UE_004", 1734700030, b"attach", b"cell_3", 1),
            (b"UE_005", 1734700040, b"attach", b"cell_2", 1),
            (b"UE_RAPID", 1734700050, b"attach", b"cell_1", 1),
            (b"UE_RAPID", 1734700055, b"attach", b"cell_1", 1),
            (b"UE_RAPID", 1734700060, b"attach", b"cell_1", 1),
            (b"UE_RAPID", 1734700065, b"attach", b"cell_1", 1),
            (b"UE_RAPID", 1734700070, b"attach", b"cell_1", 1),
        ], dtype=[('ue_id', 'S10'), ('timestamp', 'i8'), ('event_type', 'S10'), ('cell_id', 'S10'), ('status', 'i4')])
        
        # Only one detach event (unbalanced)
        detach_data = np.array([
            (b"UE_001", 1734700200, b"detach", b"cell_1", 0),
        ], dtype=[('ue_id', 'S10'), ('timestamp', 'i8'), ('event_type', 'S10'), ('cell_id', 'S10'), ('status', 'i4')])
        
        f.create_dataset("attach_events", data=attach_data)
        f.create_dataset("detach_events", data=detach_data)
        f.attrs['file_type'] = 'Anomalous_UE_Events'
    
    print("Created HDF test files:")
    print("  - ./hdf_files/normal_ue_events.hdf5")
    print("  - ./hdf_files/anomalous_ue_events.hdf5")

if __name__ == "__main__":
    create_simple_hdf()