#!/bin/bash
# Production installation with ClickHouse integration

echo "Telecom Anomaly Detection - ClickHouse Integration"
echo "=================================================="

# Install Python dependencies
pip install scapy h5py scikit-learn numpy pandas streamlit clickhouse-driver

# Create directories
mkdir -p logs models data

# Set permissions
chmod +x run_system.py pcap_analyzer.py

echo ""
echo "CLICKHOUSE INTEGRATION FEATURES:"
echo "  ✓ Automatic anomaly storage in ClickHouse database"
echo "  ✓ Complete table structure with 14 fields"
echo "  ✓ Categorization: NETWORK, UE_EVENTS, SYSTEM, OTHER"
echo "  ✓ Severity mapping and affected systems identification"
echo "  ✓ JSON metadata with full anomaly context"
echo "  ✓ Connection testing with graceful fallback"
echo ""
echo "DATABASE CONFIGURATION:"
echo "  Host: localhost:9000"
echo "  Database: l1_app_db"
echo "  User: default (no password)"
echo ""
echo "SETUP CLICKHOUSE:"
echo "  1. Install ClickHouse server"
echo "  2. Create database: CREATE DATABASE l1_app_db;"
echo "  3. Create table using CLICKHOUSE_SETUP.md instructions"
echo ""
echo "USAGE:"
echo "  python3 run_system.py /production/data"
echo ""
echo "All detected anomalies will be automatically stored in ClickHouse!"
