"""
Streamlit UI for website capture functionality
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
import html
from typing import Dict, Any, List

class WebsiteCaptureUI:
    """UI for website capture functionality"""
    
    def __init__(self, system_manager):
        self.system_manager = system_manager
        
        # Initialize website capture manager if not exists
        if not hasattr(system_manager, 'website_capture_manager'):
            from core.website_capture import WebsiteCaptureManager
            system_manager.website_capture_manager = WebsiteCaptureManager(system_manager)
    
    def render_website_capture_page(self):
        """Render main website capture page"""
        st.header("🌐 Real-Time Website Capture & Analysis")
        
        # Website capture form
        self.render_capture_form()
        
        st.markdown("---")
        
        # Active captures
        self.render_active_captures()
        
        st.markdown("---")
        
        # Capture results
        self.render_capture_results()
    
    def render_capture_form(self):
        """Render website capture form"""
        st.subheader("🎯 Target Website Capture")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Website URL input
            target_url = st.text_input(
                "🌐 Website URL to Capture",
                placeholder="https://example.com",
                help="Enter the complete URL of the website you want to monitor"
            )
            
            # Capture options
            col_a, col_b, col_c = st.columns(3)
            
            with col_a:
                capture_duration = st.selectbox(
                    "⏱️ Capture Duration",
                    [300, 600, 1800, 3600, 7200],
                    format_func=lambda x: f"{x//60} minutes" if x < 3600 else f"{x//3600} hours",
                    index=1
                )
            
            with col_b:
                capture_interval = st.selectbox(
                    "🔄 Capture Interval",
                    [30, 60, 120, 300],
                    format_func=lambda x: f"{x} seconds",
                    index=0
                )
            
            with col_c:
                deep_analysis = st.checkbox("🔬 Deep Analysis", value=True)
        
        with col2:
            st.markdown("### 🎛️ Capture Options")
            
            capture_content = st.checkbox("📄 Capture Content", value=True)
            capture_images = st.checkbox("🖼️ Capture Images", value=True)
            capture_js = st.checkbox("⚡ Capture JavaScript", value=True)
            capture_css = st.checkbox("🎨 Capture CSS", value=True)
            monitor_changes = st.checkbox("🔍 Monitor Changes", value=True)
            threat_detection = st.checkbox("🛡️ Threat Detection", value=True)
        
        # Start capture button
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            if st.button("🚀 Start Live Capture", type="primary", use_container_width=True):
                if target_url:
                    if target_url.startswith(('http://', 'https://')):
                        # Start website capture
                        result = self.system_manager.website_capture_manager.start_website_capture(
                            target_url, 
                            capture_duration
                        )
                        
                        st.success(f"✅ {result}")
                        st.balloons()
                        
                        # Store in session state
                        if 'active_captures' not in st.session_state:
                            st.session_state.active_captures = []
                        
                        capture_info = {
                            'url': target_url,
                            'start_time': datetime.now(),
                            'duration': capture_duration,
                            'status': 'active'
                        }
                        
                        st.session_state.active_captures.append(capture_info)
                        st.rerun()
                    else:
                        st.error("❌ Please enter a valid URL starting with http:// or https://")
                else:
                    st.error("❌ Please enter a website URL")
        
        with col2:
            if st.button("📊 Quick Scan", type="secondary", use_container_width=True):
                if target_url:
                    with st.spinner("🔍 Performing quick scan..."):
                        # Perform quick website verification
                        result = self.system_manager.verify_website(target_url)
                        self.display_quick_scan_result(result)
        
        with col3:
            if st.button("🛑 Stop All", type="secondary", use_container_width=True):
                # Stop all active captures
                if hasattr(st.session_state, 'active_captures'):
                    for capture in st.session_state.active_captures:
                        self.system_manager.website_capture_manager.stop_website_capture(capture['url'])
                    
                    st.session_state.active_captures = []
                    st.success("🛑 All captures stopped")
                    st.rerun()
    
    def render_active_captures(self):
        """Render active website captures"""
        st.subheader("📡 Active Website Captures")
        
        # Get active captures from system
        active_captures = self.system_manager.website_capture_manager.get_all_captures()
        
        if active_captures:
            # Create columns for each active capture
            cols = st.columns(min(len(active_captures), 3))
            
            for i, (url, capture_data) in enumerate(active_captures.items()):
                with cols[i % 3]:
                    # Capture status card
                    start_time = capture_data.get('start_time', datetime.now())
                    elapsed = datetime.now() - start_time
                    
                    st.markdown(f"""
                    <div style="
                        border: 1px solid #e2e8f0;
                        border-left: 4px solid #48bb78;
                        border-radius: 8px;
                        padding: 1rem;
                        margin: 0.5rem 0;
                        background: #ffffff;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                    ">
                        <h4>🌐 {url[:30]}...</h4>
                        <p><strong>Status:</strong> 🔴 LIVE</p>
                        <p><strong>Elapsed:</strong> {str(elapsed).split('.')[0]}</p>
                        <p><strong>Captures:</strong> {len(capture_data.get('captures', []))}</p>
                        <p><strong>Changes:</strong> {len(capture_data.get('changes_detected', []))}</p>
                        <p><strong>Threats:</strong> {len(capture_data.get('threats_found', []))}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Control buttons
                    col_a, col_b = st.columns(2)
                    with col_a:
                        if st.button(f"👁️ View", key=f"view_{i}"):
                            st.session_state.selected_capture = url
                    
                    with col_b:
                        if st.button(f"🛑 Stop", key=f"stop_{i}"):
                            self.system_manager.website_capture_manager.stop_website_capture(url)
                            st.success(f"Stopped capturing {url}")
                            st.rerun()
        else:
            st.info("📭 No active website captures. Start capturing a website above.")
    
    def render_capture_results(self):
        """Render capture results and analysis"""
        st.subheader("📊 Capture Results & Analysis")
        
        # Check if a specific capture is selected
        selected_url = st.session_state.get('selected_capture')
        
        if selected_url:
            # Get capture data
            capture_data = self.system_manager.website_capture_manager.get_capture_data(selected_url)
            
            if capture_data and capture_data.get('status') != 'not_found':
                self.display_detailed_capture_results(selected_url, capture_data)
            else:
                st.warning(f"No capture data found for {selected_url}")
        else:
            # Show summary of all captures
            self.display_capture_summary()
    
    def display_detailed_capture_results(self, url: str, capture_data: Dict[str, Any]):
        """Display detailed results for a specific capture"""
        st.markdown(f"### 🔍 Detailed Analysis: {url}")
        
        # Capture overview
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📸 Total Captures", len(capture_data.get('captures', [])))
        with col2:
            st.metric("🔄 Changes Detected", len(capture_data.get('changes_detected', [])))
        with col3:
            st.metric("🚨 Threats Found", len(capture_data.get('threats_found', [])))
        with col4:
            status = capture_data.get('status', 'unknown')
            status_icon = "🔴" if status == 'active' else "✅" if status == 'completed' else "⚠️"
            st.metric("📊 Status", f"{status_icon} {status.upper()}")
        
        # Tabs for different views
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📸 Captures", "🔄 Changes", "🚨 Threats", "📈 Performance", "🔧 Technical"
        ])
        
        with tab1:
            self.display_captures_timeline(capture_data.get('captures', []))
        
        with tab2:
            self.display_changes_detected(capture_data.get('changes_detected', []))
        
        with tab3:
            self.display_threats_found(capture_data.get('threats_found', []))
        
        with tab4:
            self.display_performance_metrics(capture_data.get('performance_metrics', []))
        
        with tab5:
            self.display_technical_details(capture_data.get('captures', []))
    
    def display_captures_timeline(self, captures: List[Dict[str, Any]]):
        """Display timeline of captures"""
        if not captures:
            st.info("No captures available yet.")
            return
        
        st.subheader("📸 Capture Timeline")
        
        # Create timeline data
        timeline_data = []
        for i, capture in enumerate(captures):
            timeline_data.append({
                'capture_number': i + 1,
                'timestamp': capture.get('timestamp', datetime.now()),
                'status_code': capture.get('status_code', 0),
                'response_time': capture.get('response_time', 0),
                'content_length': capture.get('content_length', 0)
            })
        
        df = pd.DataFrame(timeline_data)
        
        # Response time chart
        fig = px.line(
            df, 
            x='timestamp', 
            y='response_time',
            title="Response Time Over Time",
            labels={'response_time': 'Response Time (seconds)', 'timestamp': 'Time'}
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Content length chart
        fig2 = px.bar(
            df, 
            x='capture_number', 
            y='content_length',
            title="Content Length by Capture",
            labels={'content_length': 'Content Length (bytes)', 'capture_number': 'Capture #'}
        )
        st.plotly_chart(fig2, use_container_width=True)
        
        # Latest capture details
        if captures:
            latest = captures[-1]
            st.subheader("📄 Latest Capture Details")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Timestamp:** {latest.get('timestamp')}")
                st.write(f"**Status Code:** {latest.get('status_code')}")
                st.write(f"**Response Time:** {latest.get('response_time', 0):.2f}s")
                st.write(f"**Content Length:** {latest.get('content_length', 0):,} bytes")
            
            with col2:
                st.write(f"**Images Found:** {len(latest.get('images', []))}")
                st.write(f"**Links Found:** {len(latest.get('links', []))}")
                st.write(f"**Forms Found:** {len(latest.get('forms', []))}")
                st.write(f"**Technologies:** {', '.join(latest.get('technologies', []))}")
    
    def display_changes_detected(self, changes: List[Dict[str, Any]]):
        """Display detected changes"""
        if not changes:
            st.info("No changes detected yet.")
            return
        
        st.subheader("🔄 Changes Detected")
        
        for change in changes[-10:]:  # Show last 10 changes
            change_type = change.get('type', 'unknown')
            timestamp = change.get('timestamp', datetime.now())
            description = change.get('description', 'No description')
            
            # Color code by change type
            if change_type == 'content_change':
                color = "#fbbf24"  # Yellow
                icon = "📝"
            elif change_type == 'status_change':
                color = "#ef4444"  # Red
                icon = "🔄"
            elif change_type == 'headers_change':
                color = "#3b82f6"  # Blue
                icon = "📋"
            else:
                color = "#6b7280"  # Gray
                icon = "🔧"
            
            st.markdown(f"""
            <div style="
                border-left: 4px solid {color};
                padding: 1rem;
                margin: 0.5rem 0;
                background: #f9fafb;
                border-radius: 0 8px 8px 0;
            ">
                <h4>{icon} {change_type.replace('_', ' ').title()}</h4>
                <p>{description}</p>
                <small>🕒 {timestamp}</small>
            </div>
            """, unsafe_allow_html=True)
    
    def display_threats_found(self, threats: List[Dict[str, Any]]):
        """Display found threats"""
        if not threats:
            st.success("✅ No threats detected!")
            return
        
        st.subheader("🚨 Security Threats Detected")
        
        # Threat summary
        threat_counts = {}
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Threat distribution chart
        if threat_counts:
            df = pd.DataFrame(
                list(threat_counts.items()),
                columns=['Threat Type', 'Count']
            )
            
            fig = px.pie(
                df,
                values='Count',
                names='Threat Type',
                title="Threat Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Individual threats
        for threat in threats[-15:]:  # Show last 15 threats
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'low')
            description = threat.get('description', 'No description')
            timestamp = threat.get('timestamp', datetime.now())
            
            # Color code by severity
            if severity == 'high':
                color = "#dc2626"  # Red
                icon = "🔴"
            elif severity == 'medium':
                color = "#f59e0b"  # Orange
                icon = "🟡"
            else:
                color = "#10b981"  # Green
                icon = "🟢"
            
            # Properly escape HTML in the description to prevent rendering issues
            safe_description = html.escape(str(description))
            safe_threat_type = html.escape(str(threat_type))

            st.markdown(f"""
            <div style="
                border: 2px solid {color};
                padding: 1rem;
                margin: 0.5rem 0;
                background: #fefefe;
                border-radius: 8px;
            ">
                <h4>{icon} {safe_threat_type.replace('_', ' ').title()} - {severity.upper()}</h4>
                <p>{safe_description}</p>
                <small>🕒 {timestamp}</small>
            </div>
            """, unsafe_allow_html=True)
    
    def display_performance_metrics(self, metrics: List[Dict[str, Any]]):
        """Display performance metrics"""
        if not metrics:
            st.info("No performance data available yet.")
            return
        
        st.subheader("📈 Performance Metrics")
        
        # Create performance dataframe
        df = pd.DataFrame(metrics)
        
        if not df.empty:
            # Response time trend
            fig1 = px.line(
                df,
                x='timestamp',
                y='response_time',
                title="Response Time Trend",
                labels={'response_time': 'Response Time (seconds)'}
            )
            st.plotly_chart(fig1, use_container_width=True)
            
            # Content size trend
            fig2 = px.line(
                df,
                x='timestamp',
                y='content_length',
                title="Content Size Trend",
                labels={'content_length': 'Content Length (bytes)'}
            )
            st.plotly_chart(fig2, use_container_width=True)
            
            # Performance summary
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                avg_response = df['response_time'].mean()
                st.metric("⚡ Avg Response Time", f"{avg_response:.2f}s")
            
            with col2:
                avg_size = df['content_length'].mean()
                st.metric("📦 Avg Content Size", f"{avg_size:,.0f} bytes")
            
            with col3:
                total_images = df['images_count'].sum()
                st.metric("🖼️ Total Images", total_images)
            
            with col4:
                total_links = df['links_count'].sum()
                st.metric("🔗 Total Links", total_links)
    
    def display_technical_details(self, captures: List[Dict[str, Any]]):
        """Display technical details"""
        if not captures:
            st.info("No technical data available yet.")
            return
        
        st.subheader("🔧 Technical Details")
        
        latest_capture = captures[-1]
        
        # Security headers
        security_headers = latest_capture.get('security_headers', {})
        if security_headers:
            st.write("**🔒 Security Headers Analysis:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                score = security_headers.get('security_score', 0)
                st.metric("Security Score", f"{score}/100")
                
                st.write("**Headers Present:**")
                for header, value in security_headers.items():
                    if value and header != 'security_score':
                        st.write(f"✅ {header.replace('_', ' ').title()}")
            
            with col2:
                st.write("**Missing Headers:**")
                missing_headers = []
                if not security_headers.get('content_security_policy'):
                    missing_headers.append("Content Security Policy")
                if not security_headers.get('strict_transport_security'):
                    missing_headers.append("Strict Transport Security")
                if not security_headers.get('x_frame_options'):
                    missing_headers.append("X-Frame-Options")
                
                for header in missing_headers:
                    st.write(f"❌ {header}")
        
        # SSL/TLS Information
        ssl_info = latest_capture.get('ssl_info', {})
        if ssl_info and 'error' not in ssl_info:
            st.write("**🔐 SSL/TLS Certificate:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                subject = ssl_info.get('subject', {})
                st.write(f"**Subject:** {subject.get('commonName', 'N/A')}")
                st.write(f"**Issuer:** {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}")
                st.write(f"**Valid Until:** {ssl_info.get('not_after', 'N/A')}")
            
            with col2:
                st.write(f"**Protocol:** {ssl_info.get('protocol', 'N/A')}")
                cipher = ssl_info.get('cipher', [])
                if cipher:
                    st.write(f"**Cipher:** {cipher[0] if cipher else 'N/A'}")
        
        # Technologies detected
        technologies = latest_capture.get('technologies', [])
        if technologies:
            st.write("**🛠️ Technologies Detected:**")
            
            tech_cols = st.columns(min(len(technologies), 4))
            for i, tech in enumerate(technologies):
                with tech_cols[i % 4]:
                    st.write(f"🔧 {tech}")
    
    def display_capture_summary(self):
        """Display summary of all captures"""
        st.subheader("📊 Capture Summary")
        
        # Get all captures
        all_captures = self.system_manager.website_capture_manager.get_all_captures()
        
        if all_captures:
            # Summary metrics
            total_captures = sum(len(data.get('captures', [])) for data in all_captures.values())
            total_changes = sum(len(data.get('changes_detected', [])) for data in all_captures.values())
            total_threats = sum(len(data.get('threats_found', [])) for data in all_captures.values())
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("🌐 Active Websites", len(all_captures))
            with col2:
                st.metric("📸 Total Captures", total_captures)
            with col3:
                st.metric("🔄 Total Changes", total_changes)
            with col4:
                st.metric("🚨 Total Threats", total_threats)
            
            # Website list
            st.write("**Active Website Captures:**")
            
            for url, data in all_captures.items():
                with st.expander(f"🌐 {url}"):
                    col_a, col_b = st.columns(2)
                    
                    with col_a:
                        st.write(f"**Status:** {data.get('status', 'unknown')}")
                        st.write(f"**Start Time:** {data.get('start_time', 'N/A')}")
                        st.write(f"**Captures:** {len(data.get('captures', []))}")
                    
                    with col_b:
                        st.write(f"**Changes:** {len(data.get('changes_detected', []))}")
                        st.write(f"**Threats:** {len(data.get('threats_found', []))}")
                        
                        if st.button(f"View Details", key=f"summary_view_{url}"):
                            st.session_state.selected_capture = url
                            st.rerun()
        else:
            st.info("📭 No website captures active. Start capturing websites above.")
    
    def display_quick_scan_result(self, result: Dict[str, Any]):
        """Display quick scan result"""
        st.subheader("⚡ Quick Scan Results")
        
        if 'error' in result:
            st.error(f"❌ Scan Error: {result['error']}")
            return
        
        # Basic metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status = result.get('status', 'Unknown')
            status_color = "🟢" if status == "200" else "🔴"
            st.metric("Status", f"{status_color} {status}")
        
        with col2:
            https_enabled = result.get('https_enabled', False)
            https_status = "✅ Enabled" if https_enabled else "❌ Disabled"
            st.metric("HTTPS", https_status)
        
        with col3:
            risk_score = result.get('risk_score', 0)
            risk_level = "LOW" if risk_score < 0.3 else "MEDIUM" if risk_score < 0.7 else "HIGH"
            risk_color = "🟢" if risk_level == "LOW" else "🟡" if risk_level == "MEDIUM" else "🔴"
            st.metric("Risk Level", f"{risk_color} {risk_level}")
        
        # Threats detected
        threats = result.get('threats_detected', [])
        if threats:
            st.write("**🚨 Threats Detected:**")
            for threat in threats:
                st.warning(f"⚠️ {threat.get('type', 'Unknown')}: {threat.get('description', 'No description')}")
        else:
            st.success("✅ No immediate threats detected")
