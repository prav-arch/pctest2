#!/usr/bin/env python3
"""
Comprehensive warning suppression for cryptography deprecation warnings.
This should be imported before any other modules that use cryptography.
"""

import warnings
import sys
import os

# Comprehensive warning suppression
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# Specific cryptography warnings
warnings.filterwarnings("ignore", message=".*deprecated.*")
warnings.filterwarnings("ignore", message=".*CryptographyDeprecationWarning.*")
warnings.filterwarnings("ignore", message=".*TripleDES.*")
warnings.filterwarnings("ignore", message=".*algorithm.*deprecated.*")
warnings.filterwarnings("ignore", message=".*will be removed.*")

# Scapy-specific warnings
warnings.filterwarnings("ignore", module="scapy.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

# sklearn warnings
warnings.filterwarnings("ignore", message=".*model_persistence.*")
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Set environment variable to suppress warnings at system level
os.environ['PYTHONWARNINGS'] = 'ignore::DeprecationWarning,ignore::UserWarning'

print("Warning suppression activated")