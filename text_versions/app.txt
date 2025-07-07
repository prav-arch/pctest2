import warnings
# Suppress cryptography deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", message=".*CryptographyDeprecationWarning.*")
warnings.filterwarnings("ignore", message=".*deprecated.*", category=UserWarning)

import streamlit as st
import os
import json
import pickle
from datetime import datetime
import pandas as pd
import io
import zipfile
from telecom_anomaly_detector import TelecomAnomalyDetector
from config import Config

# Configure Streamlit page
st.set_page_config(
    page_title="Telecom Anomaly Detection System",
    page_icon="📡",
    layout="wide"
)

def create_downloadable_report(results, analysis_summary):
    """Create a downloadable analysis report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": analysis_summary,
        "detailed_results": results,
        "system_info": {
            "total_files": len(results),
            "anomalies_detected": sum(1 for r in results if r.get('anomalies')),
            "file_types_processed": list(set(r.get('file_type', 'unknown') for r in results))
        }
    }
    return json.dumps(report, indent=2)

def create_results_dataframe(results):
    """Convert results to DataFrame for display."""
    data = []
    for result in results:
        filename = os.path.basename(result.get('file', 'unknown'))
        file_type = result.get('file_type', 'unknown')
        anomaly_count = len(result.get('anomalies', []))
        
        # Get severity breakdown
        severities = {}
        for anomaly in result.get('anomalies', []):
            severity = anomaly.get('severity_level', 'UNKNOWN')
            severities[severity] = severities.get(severity, 0) + 1
        
        data.append({
            'File': filename,
            'Type': file_type,
            'Anomalies': anomaly_count,
            'Critical': severities.get('CRITICAL', 0),
            'High': severities.get('HIGH', 0),
            'Medium': severities.get('MEDIUM', 0),
            'Low': severities.get('LOW', 0),
            'Status': 'Anomalous' if anomaly_count > 0 else 'Normal'
        })
    
    return pd.DataFrame(data)

def main():
    st.title("Telecom Anomaly Detection System")
    st.markdown("Detect anomalies in PCAP, HDF, and CU log files using machine learning")
    
    # Sidebar for configuration
    st.sidebar.header("Configuration")
    
    # Data folder selection
    available_folders = ['mixed_data_folder', 'pcap_files', 'hdf_files']
    available_folders = [f for f in available_folders if os.path.exists(f)]
    
    selected_folder = st.sidebar.selectbox(
        "Select data folder:",
        available_folders,
        index=0 if available_folders else None
    )
    
    # Custom folder path
    custom_folder = st.sidebar.text_input(
        "Or enter custom folder path:",
        placeholder="/path/to/your/data"
    )
    
    # Use custom folder if provided
    data_folder = custom_folder if custom_folder and os.path.exists(custom_folder) else selected_folder
    
    if not data_folder or not os.path.exists(data_folder):
        st.error("Please select a valid data folder")
        return
    
    # Display folder contents
    st.sidebar.markdown(f"**Folder:** `{data_folder}`")
    files = os.listdir(data_folder)
    pcap_files = [f for f in files if f.endswith(('.pcap', '.pcapng'))]
    hdf_files = [f for f in files if f.endswith(('.hdf5', '.h5'))]
    log_files = [f for f in files if f.endswith(('.txt', '.log'))]
    
    st.sidebar.markdown(f"📁 PCAP files: {len(pcap_files)}")
    st.sidebar.markdown(f"📁 HDF files: {len(hdf_files)}")
    st.sidebar.markdown(f"📁 Log files: {len(log_files)}")
    
    # Main analysis section
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.header("Analysis Results")
        
        if st.button("Run Analysis", type="primary"):
            with st.spinner("Analyzing files..."):
                try:
                    # Initialize detector
                    detector = TelecomAnomalyDetector(input_folder=data_folder)
                    
                    # Store results in session state
                    results = []
                    total_anomalies = 0
                    
                    # Process PCAP files
                    for pcap_file in pcap_files:
                        file_path = os.path.join(data_folder, pcap_file)
                        result = detector.analyze_pcap_file(file_path)
                        result['file'] = file_path
                        result['file_type'] = 'PCAP'
                        results.append(result)
                        total_anomalies += len(result.get('anomalies', []))
                    
                    # Process HDF files
                    for hdf_file in hdf_files:
                        file_path = os.path.join(data_folder, hdf_file)
                        result = detector.analyze_hdf_file(file_path)
                        result['file'] = file_path
                        result['file_type'] = 'HDF'
                        results.append(result)
                        total_anomalies += len(result.get('anomalies', []))
                    
                    # Process log files
                    for log_file in log_files:
                        file_path = os.path.join(data_folder, log_file)
                        result = detector.analyze_cu_log_file(file_path)
                        result['file'] = file_path
                        result['file_type'] = 'CU_LOG'
                        results.append(result)
                        total_anomalies += len(result.get('anomalies', []))
                    
                    # Store in session state
                    st.session_state.results = results
                    st.session_state.total_anomalies = total_anomalies
                    st.session_state.analysis_timestamp = datetime.now()
                    
                    st.success(f"Analysis complete! Found {total_anomalies} anomalies in {len(results)} files")
                    
                except Exception as e:
                    st.error(f"Analysis failed: {str(e)}")
    
    with col2:
        st.header("Downloads")
        
        if hasattr(st.session_state, 'results'):
            # Analysis summary
            analysis_summary = {
                "timestamp": st.session_state.analysis_timestamp.isoformat(),
                "total_files": len(st.session_state.results),
                "total_anomalies": st.session_state.total_anomalies,
                "folder_analyzed": data_folder
            }
            
            # Download analysis report
            report_json = create_downloadable_report(st.session_state.results, analysis_summary)
            st.download_button(
                label="Download Analysis Report",
                data=report_json,
                file_name=f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
            
            # Download results as CSV
            df = create_results_dataframe(st.session_state.results)
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Results CSV",
                data=csv,
                file_name=f"anomaly_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            
            # Download trained model
            if os.path.exists('models/isolation_forest_model.pkl'):
                with open('models/isolation_forest_model.pkl', 'rb') as f:
                    model_data = f.read()
                st.download_button(
                    label="Download Trained Model",
                    data=model_data,
                    file_name="isolation_forest_model.pkl",
                    mime="application/octet-stream"
                )
            
            # Create and download complete package
            if st.button("Create Download Package"):
                with st.spinner("Creating package..."):
                    # Create ZIP file in memory
                    zip_buffer = io.BytesIO()
                    
                    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        # Add analysis report
                        zip_file.writestr("anomaly_report.json", report_json)
                        
                        # Add CSV results
                        zip_file.writestr("results.csv", csv)
                        
                        # Add model files if they exist
                        if os.path.exists('models/isolation_forest_model.pkl'):
                            zip_file.write('models/isolation_forest_model.pkl', 'isolation_forest_model.pkl')
                        if os.path.exists('models/scaler.pkl'):
                            zip_file.write('models/scaler.pkl', 'scaler.pkl')
                    
                    zip_buffer.seek(0)
                    
                    st.download_button(
                        label="Download Complete Package",
                        data=zip_buffer.getvalue(),
                        file_name=f"telecom_analysis_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        mime="application/zip"
                    )
    
    # Display results if available
    if hasattr(st.session_state, 'results'):
        st.header("Analysis Overview")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Files", len(st.session_state.results))
        with col2:
            st.metric("Total Anomalies", st.session_state.total_anomalies)
        with col3:
            anomaly_rate = (st.session_state.total_anomalies / len(st.session_state.results)) * 100 if st.session_state.results else 0
            st.metric("Anomaly Rate", f"{anomaly_rate:.1f}%")
        with col4:
            st.metric("Analysis Time", st.session_state.analysis_timestamp.strftime("%H:%M:%S"))
        
        # Results table
        st.subheader("File Analysis Results")
        df = create_results_dataframe(st.session_state.results)
        st.dataframe(df, use_container_width=True)
        
        # Detailed anomaly view
        st.subheader("Anomaly Details")
        
        anomalous_files = [r for r in st.session_state.results if r.get('anomalies')]
        
        if anomalous_files:
            for result in anomalous_files:
                filename = os.path.basename(result.get('file', 'unknown'))
                with st.expander(f"📄 {filename} ({len(result.get('anomalies', []))} anomalies)"):
                    for i, anomaly in enumerate(result.get('anomalies', []), 1):
                        severity = anomaly.get('severity_level', 'UNKNOWN')
                        anomaly_type = anomaly.get('type', 'unknown')
                        description = anomaly.get('description', 'No description')
                        
                        # Color code by severity
                        if severity == 'CRITICAL':
                            st.error(f"**{i}. [{severity}] {anomaly_type}**")
                        elif severity == 'HIGH':
                            st.warning(f"**{i}. [{severity}] {anomaly_type}**")
                        else:
                            st.info(f"**{i}. [{severity}] {anomaly_type}**")
                        
                        st.write(f"Description: {description}")
                        
                        if 'impact_description' in anomaly:
                            st.write(f"Impact: {anomaly['impact_description']}")
                        if 'recommended_action' in anomaly:
                            st.write(f"Action: {anomaly['recommended_action']}")
                        
                        st.divider()
        else:
            st.success("No anomalies detected in any files!")

if __name__ == "__main__":
    main()