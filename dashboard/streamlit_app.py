"""
Enhanced Streamlit web dashboard with website capture functionality
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import threading
from typing import Dict, Any

from core.system_manager import SystemManager
from dashboard.real_time_dashboard import RealTimeDashboard
from dashboard.website_capture_ui import WebsiteCaptureUI

class StreamlitDashboard:
    """Enhanced Streamlit web dashboard with website capture"""
    
    def __init__(self, system_manager: SystemManager):
        self.system_manager = system_manager
        self.real_time_dashboard = RealTimeDashboard(system_manager)
        self.website_capture_ui = WebsiteCaptureUI(system_manager)
        self.setup_page_config()
    
    def setup_page_config(self):
        """Configure Streamlit page"""
        st.set_page_config(
            page_title="QS-AI-IDS - Website Capture Dashboard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS for website capture
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .website-capture-indicator {
            background: linear-gradient(45deg, #059669, #10b981);
            color: white;
            padding: 0.5rem;
            border-radius: 5px;
            text-align: center;
            animation: pulse 2s infinite;
        }
        
        .capture-card {
            border: 2px solid #10b981;
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
            background: linear-gradient(45deg, #f0fdf4, #ecfdf5);
        }
        
        .threat-alert {
            background: #fef2f2;
            border-left: 4px solid #ef4444;
            padding: 1rem;
            border-radius: 8px;
            margin: 0.5rem 0;
            animation: slideIn 0.5s ease-in;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        @keyframes slideIn {
            from { transform: translateX(-100%); }
            to { transform: translateX(0); }
        }
        </style>
        """, unsafe_allow_html=True)
    
    def run(self, host: str = "localhost", port: int = 8501, debug: bool = False):
        """Run the Streamlit dashboard"""
        # Initialize session state
        if 'system_started' not in st.session_state:
            st.session_state.system_started = False
        
        # Setup real-time updates
        self.real_time_dashboard.setup_real_time_updates()
        
        # Main dashboard
        self.render_dashboard()
    
    def render_dashboard(self):
        """Render the main dashboard"""
        # Header with website capture indicator
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ QS-AI-IDS - Website Capture & Security Dashboard</h1>
            <div class="website-capture-indicator">
                🌐 LIVE - Website Capture & Real-Time Monitoring Active
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar
        self.render_sidebar()
        
        # Main content
        page = st.session_state.get('current_page', 'Real-Time Dashboard')
        
        if page == 'Real-Time Dashboard':
            self.render_real_time_dashboard()
        elif page == 'Website Capture':
            self.website_capture_ui.render_website_capture_page()
        elif page == 'Network Monitor':
            self.render_network_monitor()
        elif page == 'Website Analysis':
            self.render_website_analysis()
        elif page == 'Threat Intelligence':
            self.render_threat_intelligence()
        elif page == 'Quantum Analysis':
            self.render_quantum_analysis()
        elif page == 'Settings':
            self.render_settings()
        elif page == 'Reports':
            self.render_reports()
    
    def render_sidebar(self):
        """Render sidebar navigation"""
        with st.sidebar:
            st.title("🔧 Control Center")
            
            # System status with real-time updates
            status = self.system_manager.get_system_status()
            status_color = "🟢" if status['running'] else "🔴"
            st.markdown(f"**System Status:** {status_color} {'LIVE' if status['running'] else 'OFFLINE'}")
            
            # Website capture status
            if hasattr(self.system_manager, 'website_capture_manager'):
                active_captures = self.system_manager.website_capture_manager.get_all_captures()
                capture_count = len(active_captures)
                
                if capture_count > 0:
                    st.markdown(f"""
                    <div class="website-capture-indicator">
                        🌐 {capture_count} Website{'s' if capture_count != 1 else ''} Capturing
                    </div>
                    """, unsafe_allow_html=True)
            
            # Navigation
            pages = [
                'Real-Time Dashboard', 'Website Capture', 'Network Monitor', 
                'Website Analysis', 'Threat Intelligence', 'Quantum Analysis', 
                'Settings', 'Reports'
            ]
            
            selected_page = st.selectbox("Select Page", pages)
            st.session_state.current_page = selected_page
            
            st.markdown("---")
            
            # Quick website capture
            st.markdown("### 🌐 Quick Website Capture")
            
            quick_url = st.text_input("URL", placeholder="https://example.com", key="quick_capture")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🚀 Capture", type="primary", key="quick_start"):
                    if quick_url and hasattr(self.system_manager, 'website_capture_manager'):
                        result = self.system_manager.website_capture_manager.start_website_capture(quick_url, 300)
                        st.success("Started!")
                        st.rerun()
            
            with col2:
                if st.button("⚡ Scan", type="secondary", key="quick_scan"):
                    if quick_url:
                        with st.spinner("Scanning..."):
                            result = self.system_manager.verify_website(quick_url)
                            if result.get('threats_detected'):
                                st.error(f"⚠️ {len(result['threats_detected'])} threats!")
                            else:
                                st.success("✅ Clean!")
            
            st.markdown("---")
            
            # Real-time metrics
            self.real_time_dashboard.render_real_time_metrics()
            
            st.markdown("---")
            
            # System controls
            st.markdown("### ⚙️ System Controls")
            
            if not status['running']:
                if st.button("🚀 Start System", type="primary"):
                    self.system_manager.start()
                    st.success("System started!")
                    st.rerun()
            else:
                if st.button("🛑 Stop System", type="secondary"):
                    self.system_manager.shutdown()
                    st.warning("System stopped!")
                    st.rerun()
    
    def render_real_time_dashboard(self):
        """Render real-time dashboard page"""
        st.header("📊 Real-Time Security Overview")
        
        # Real-time metrics
        self.real_time_dashboard.render_real_time_metrics()
        
        st.markdown("---")
        
        # Website capture overview
        if hasattr(self.system_manager, 'website_capture_manager'):
            active_captures = self.system_manager.website_capture_manager.get_all_captures()
            
            if active_captures:
                st.subheader("🌐 Active Website Captures")
                
                # Create columns for active captures
                cols = st.columns(min(len(active_captures), 4))
                
                for i, (url, capture_data) in enumerate(active_captures.items()):
                    with cols[i % 4]:
                        # Mini capture card
                        captures_count = len(capture_data.get('captures', []))
                        threats_count = len(capture_data.get('threats_found', []))
                        changes_count = len(capture_data.get('changes_detected', []))
                        
                        st.markdown(f"""
                        <div class="capture-card">
                            <h5>🌐 {url[:25]}...</h5>
                            <p>📸 Captures: {captures_count}</p>
                            <p>🔄 Changes: {changes_count}</p>
                            <p>🚨 Threats: {threats_count}</p>
                        </div>
                        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Live threat feed and charts
        col1, col2 = st.columns([1, 1])
        
        with col1:
            self.real_time_dashboard.render_live_threat_feed()
        
        with col2:
            self.real_time_dashboard.render_real_time_charts()
        
        st.markdown("---")
        
        # Network activity monitoring
        self.real_time_dashboard.render_network_activity()
        
        st.markdown("---")
        
        # System health
        self.real_time_dashboard.render_system_health()
    
    def render_network_monitor(self):
        """Render network monitoring page with real-time updates"""
        st.header("📡 Real-Time Network Monitor")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("🔍 Live Traffic Analysis")
            
            # Interface selection
            interfaces = self.system_manager.settings.network.interfaces
            selected_interface = st.selectbox("Network Interface", interfaces)
            
            # Target domain filter
            target_domain = st.text_input("Target Domain (optional)", 
                                        placeholder="example.com")
            
            # Real-time filter
            capture_filter = st.text_input("Capture Filter", 
                                         value="tcp port 80 or tcp port 443",
                                         help="BPF filter expression")
            
            # Control buttons
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("🚀 Start Live Monitoring", type="primary"):
                    # Start real-time network monitoring
                    if hasattr(self.system_manager, 'real_time_monitor'):
                        self.system_manager.real_time_monitor.start()
                    
                    self.system_manager.start_network_monitoring(
                        interface=selected_interface,
                        target_domain=target_domain if target_domain else None
                    )
                    st.success("🔴 Live monitoring started!")
            
            with col_b:
                if st.button("🛑 Stop Monitoring"):
                    if hasattr(self.system_manager, 'real_time_monitor'):
                        self.system_manager.real_time_monitor.stop()
                    st.info("Monitoring stopped!")
            
            # Live packet display
            st.subheader("📦 Live Packet Stream")
            
            # Display recent packets (this would be updated in real-time)
            recent_threats = st.session_state.real_time_data.get('recent_threats', [])
            
            if recent_threats:
                st.write("**Recent Network Events:**")
                for threat in recent_threats[-5:]:  # Show last 5
                    timestamp = threat.get('timestamp', 'Unknown')
                    source_ip = threat.get('source_ip', '0.0.0.0')
                    threat_type = threat.get('threat_type', 'Unknown')
                    
                    st.write(f"🕒 {timestamp} - 🚨 {threat_type} from {source_ip}")
            else:
                st.info("🔴 Waiting for live network data... Start monitoring to see packets.")
        
        with col2:
            st.subheader("⚙️ Monitor Configuration")
            
            # Real-time settings
            st.write("**Real-Time Settings:**")
            buffer_size = st.slider("Buffer Size", 1000, 50000, 10000)
            update_interval = st.slider("Update Interval (ms)", 100, 5000, 1000)
            
            # Alert configuration
            st.write("**Alert Configuration:**")
            threat_threshold = st.slider("Threat Threshold", 0.1, 1.0, 0.7)
            auto_block = st.checkbox("Auto-block Threats", value=False)
    
    def render_website_analysis(self):
        """Render website analysis page"""
        st.header("🌐 Website Security Analysis")
        
        # Single website verification with real-time results
        st.subheader("🔍 Single Website Analysis")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            url_input = st.text_input("Website URL", placeholder="https://example.com")
        with col2:
            verify_button = st.button("🔍 Analyze", type="primary")
        
        if verify_button and url_input:
            with st.spinner("🔴 Performing analysis..."):
                result = self.system_manager.verify_website(url_input)
                self.display_verification_result(result)
        
        st.markdown("---")
        
        # Bulk analysis
        st.subheader("📊 Bulk Website Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            urls_text = st.text_area("URLs (one per line)", 
                                   placeholder="https://example1.com\nhttps://example2.com")
            
            depth = st.slider("Crawl Depth", 1, 5, 2)
            max_pages = st.slider("Max Pages per Site", 10, 100, 50)
        
        with col2:
            st.subheader("⚙️ Analysis Options")
            
            quantum_analysis = st.checkbox("🧬 Quantum Analysis", value=True)
            deep_scan = st.checkbox("🔬 Deep Security Scan", value=True)
            threat_intel = st.checkbox("🎯 Threat Intelligence", value=True)
            
            if st.button("🚀 Start Analysis", type="primary"):
                if urls_text:
                    urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
                    if urls:
                        self.system_manager.start_website_analysis(urls, depth, max_pages)
                        st.success(f"🔴 Started analysis of {len(urls)} websites!")
                    else:
                        st.error("Please enter at least one valid URL")
                else:
                    st.error("Please enter URLs to analyze")
    
    def render_threat_intelligence(self):
        """Render threat intelligence page with real-time updates"""
        st.header("🎯 Real-Time Threat Intelligence")
        
        # Real-time threat overview
        col1, col2, col3 = st.columns(3)
        
        # Get real-time data
        counters = st.session_state.real_time_data.get('counters', {})
        
        with col1:
            threats_detected = counters.get('threats_detected', 0)
            st.metric("🔴 Active Threats", threats_detected, delta="Live")
        with col2:
            blocked_ips = counters.get('blocked_ips_count', 0)
            st.metric("🛡️ Blocked IPs", blocked_ips, delta="Auto-blocked")
        with col3:
            quantum_analyses = counters.get('quantum_analyses', 0)
            st.metric("🧬 Quantum Analyses", quantum_analyses, delta="Enhanced")
        
        # Live threat feed
        self.real_time_dashboard.render_live_threat_feed()
        
        # Real-time threat analytics
        col1, col2 = st.columns(2)
        
        with col1:
            self.real_time_dashboard.render_real_time_charts()
        
        with col2:
            # Website-specific threats
            if hasattr(self.system_manager, 'website_capture_manager'):
                active_captures = self.system_manager.website_capture_manager.get_all_captures()
                
                st.subheader("🌐 Website Threats")
                
                website_threats = 0
                for url, data in active_captures.items():
                    threats = len(data.get('threats_found', []))
                    website_threats += threats
                    
                    if threats > 0:
                        st.write(f"⚠️ {url}: {threats} threats")
                
                if website_threats == 0:
                    st.success("✅ No website threats detected")
    
    def render_quantum_analysis(self):
        """Render quantum analysis page with real-time updates"""
        st.header("🧬 Real-Time Quantum Security Analysis")
        
        # Quantum status with real-time indicator
        quantum_enabled = self.system_manager.settings.quantum.enabled
        
        if quantum_enabled:
            st.markdown("""
            <div style="
                background: linear-gradient(45deg, #8b5cf6, #06b6d4);
                color: white;
                padding: 1rem;
                border-radius: 10px;
                text-align: center;
                margin-bottom: 1rem;
            ">
                <h3>🧬 Quantum Processing: LIVE</h3>
                <p>Real-time quantum-enhanced threat detection active</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.warning("⚠️ Quantum processing is disabled. Enable in settings for enhanced detection.")
        
        # Real-time quantum metrics
        self.real_time_dashboard.render_real_time_metrics()
        
        # Quantum analysis results
        self.real_time_dashboard.render_live_threat_feed()
    
    def render_settings(self):
        """Render settings page"""
        st.header("⚙️ System Settings")
        
        # Website capture settings
        st.subheader("🌐 Website Capture Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            default_duration = st.selectbox(
                "Default Capture Duration",
                [300, 600, 1800, 3600],
                format_func=lambda x: f"{x//60} minutes" if x < 3600 else f"{x//3600} hours"
            )
            
            capture_interval = st.slider("Capture Interval (seconds)", 10, 300, 30)
            
            max_concurrent = st.slider("Max Concurrent Captures", 1, 10, 5)
        
        with col2:
            enable_browser = st.checkbox("Enable Browser Capture", value=True)
            capture_screenshots = st.checkbox("Capture Screenshots", value=False)
            deep_analysis = st.checkbox("Enable Deep Analysis", value=True)
        
        # Other settings tabs
        tab1, tab2, tab3, tab4 = st.tabs(["🧬 Quantum", "🤖 AI/ML", "📡 Network", "🔒 Security"])
        
        with tab1:
            st.subheader("Quantum Configuration")
            quantum_enabled = st.checkbox("Enable Quantum Processing", 
                                        value=self.system_manager.settings.quantum.enabled)
        
        with tab2:
            st.subheader("AI/ML Configuration")
            confidence_threshold = st.slider("Confidence Threshold", 0.1, 1.0, 
                                           self.system_manager.settings.ai.confidence_threshold)
        
        with tab3:
            st.subheader("Network Configuration")
            interfaces = st.multiselect("Network Interfaces", 
                                      ["eth0", "eth1", "wlan0", "lo"],
                                      default=self.system_manager.settings.network.interfaces)
        
        with tab4:
            st.subheader("Security Configuration")
            encryption_enabled = st.checkbox("Enable Encryption", 
                                           value=self.system_manager.settings.security.encryption_enabled)
        
        # Save settings
        if st.button("💾 Save Settings", type="primary"):
            # Update settings
            self.system_manager.settings.quantum.enabled = quantum_enabled
            self.system_manager.settings.ai.confidence_threshold = confidence_threshold
            self.system_manager.settings.network.interfaces = interfaces
            self.system_manager.settings.security.encryption_enabled = encryption_enabled
            
            # Save to file
            self.system_manager.settings.save_config()
            st.success("✅ Settings saved successfully!")
    
    def render_reports(self):
        """Render reports page"""
        st.header("📊 Security Reports")
        
        # Website capture reports
        if hasattr(self.system_manager, 'website_capture_manager'):
            st.subheader("🌐 Website Capture Reports")
            
            active_captures = self.system_manager.website_capture_manager.get_all_captures()
            
            if active_captures:
                for url, data in active_captures.items():
                    with st.expander(f"📊 Report: {url}"):
                        # Generate report for this website
                        captures = len(data.get('captures', []))
                        changes = len(data.get('changes_detected', []))
                        threats = len(data.get('threats_found', []))
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Captures", captures)
                        with col2:
                            st.metric("Changes", changes)
                        with col3:
                            st.metric("Threats", threats)
                        
                        # Export button
                        if st.button(f"📥 Export Report", key=f"export_{url}"):
                            report_data = {
                                'url': url,
                                'generated_at': datetime.now().isoformat(),
                                'summary': {
                                    'captures': captures,
                                    'changes': changes,
                                    'threats': threats
                                },
                                'detailed_data': data
                            }
                            
                            report_json = json.dumps(report_data, indent=2, default=str)
                            st.download_button(
                                label="📥 Download JSON Report",
                                data=report_json,
                                file_name=f"website_report_{url.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
            else:
                st.info("No website capture data available for reports.")
        
        # System reports
        st.subheader("🛡️ System Reports")
        
        if st.button("📊 Generate System Report", type="primary"):
            report = self.system_manager.generate_report()
            
            st.success("✅ System report generated!")
            
            with st.expander("📄 Report Preview"):
                st.json(report)
            
            # Download button
            report_json = json.dumps(report, indent=2, default=str)
            st.download_button(
                label="📥 Download System Report",
                data=report_json,
                file_name=f"system_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    def display_verification_result(self, result: Dict[str, Any]):
        """Display website verification result"""
        if 'error' in result:
            st.error(f"❌ Error: {result['error']}")
            return
        
        # Basic info
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status = result.get('status', 'Unknown')
            status_color = "🟢" if status == "200" else "🔴"
            st.metric("🌐 Status", f"{status_color} {status}")
        with col2:
            https_status = "✅ Enabled" if result.get('https_enabled') else "❌ Disabled"
            st.metric("🔒 HTTPS", https_status)
        with col3:
            risk_score = result.get('risk_score', 0)
            risk_level = "LOW" if risk_score < 0.3 else "MEDIUM" if risk_score < 0.7 else "HIGH"
            risk_color = "🟢" if risk_level == "LOW" else "🟡" if risk_level == "MEDIUM" else "🔴"
            st.metric("⚠️ Risk Level", f"{risk_color} {risk_level}")
        
        # Threats detected
        if 'threats_detected' in result and result['threats_detected']:
            st.subheader("🚨 Threats Detected")
            for threat in result['threats_detected']:
                st.markdown(f"""
                <div class="threat-alert">
                    <strong>🎯 {threat['type']}</strong><br>
                    <small>{threat['description']}</small><br>
                    <small>🔴 Confidence: {threat['confidence']:.2f}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No threats detected")
