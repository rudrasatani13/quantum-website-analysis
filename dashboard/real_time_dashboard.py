"""
Real-time dashboard components for Streamlit
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from typing import Dict, Any

class RealTimeDashboard:
    """Real-time dashboard components"""

    def __init__(self, system_manager):
        self.system_manager = system_manager

    def setup_real_time_updates(self):
        """Setup real-time updates for Streamlit"""
        # Initialize session state for real-time data
        if 'real_time_data' not in st.session_state:
            st.session_state.real_time_data = {
                'counters': {
                    'packets_processed': 0,
                    'threats_detected': 0,
                    'bytes_processed': 0,
                    'quantum_analyses': 0,
                    'blocked_ips_count': 0,
                    'active_connections': 0
                },
                'recent_threats': [],
                'threat_timeline': [],
                'attack_distribution': {},
                'network_rates': {}
            }

        # Auto-refresh every 2 seconds
        if 'last_update' not in st.session_state:
            st.session_state.last_update = time.time()

        current_time = time.time()
        if current_time - st.session_state.last_update > 2:
            self._update_real_time_data()
            st.session_state.last_update = current_time

    def _update_real_time_data(self):
        """Update real-time data from system manager"""
        try:
            status = self.system_manager.get_system_status()

            # Update counters
            if 'real_time_data' in status:
                real_time_data = status['real_time_data']
                st.session_state.real_time_data.update(real_time_data)

            # Update statistics
            if 'statistics' in status:
                stats = status['statistics']
                st.session_state.real_time_data['counters'].update({
                    'packets_processed': stats.get('packets_processed', 0),
                    'threats_detected': stats.get('threats_detected', 0),
                    'bytes_processed': stats.get('bytes_processed', 0),
                    'quantum_analyses': stats.get('quantum_analyses', 0)
                })

        except Exception as e:
            st.error(f"Error updating real-time data: {e}")

    def render_real_time_metrics(self):
        """Render real-time metrics"""
        st.subheader("📊 Live Metrics")

        counters = st.session_state.real_time_data.get('counters', {})

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "🔴 Threats",
                counters.get('threats_detected', 0),
                delta="Live"
            )

            st.metric(
                "📦 Packets",
                f"{counters.get('packets_processed', 0):,}",
                delta="+1.2K"
            )

        with col2:
            st.metric(
                "🧬 Quantum",
                counters.get('quantum_analyses', 0),
                delta="+12"
            )

            st.metric(
                "🛡️ Blocked",
                counters.get('blocked_ips_count', 0),
                delta="+2"
            )

    def render_live_threat_feed(self):
        """Render live threat feed"""
        st.subheader("🚨 Live Threat Feed")

        recent_threats = st.session_state.real_time_data.get('recent_threats', [])

        if recent_threats:
            # Create scrollable container
            with st.container():
                for threat in recent_threats[-10:]:  # Show last 10
                    severity = threat.get('severity', 0.5)

                    if severity >= 0.8:
                        level_icon = "🔴"
                        level_text = "CRITICAL"
                        bg_color = "#fef2f2"
                        border_color = "#ef4444"
                    elif severity >= 0.6:
                        level_icon = "🟠"
                        level_text = "HIGH"
                        bg_color = "#fff7ed"
                        border_color = "#f97316"
                    else:
                        level_icon = "🟡"
                        level_text = "MEDIUM"
                        bg_color = "#fefce8"
                        border_color = "#eab308"

                    st.markdown(f"""
                    <div style="
                        background: {bg_color};
                        border-left: 4px solid {border_color};
                        padding: 0.5rem;
                        border-radius: 4px;
                        margin: 0.25rem 0;
                        font-size: 0.9rem;
                    ">
                        <strong>{level_icon} {threat.get('threat_type', 'Unknown')}</strong> - {level_text}<br>
                        <small>📍 {threat.get('source_ip', 'Unknown')} | 🎯 {threat.get('confidence', 0):.2f}</small>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("🔴 Monitoring for threats... No active threats detected.")

    def render_real_time_charts(self):
        """Render real-time charts"""
        st.subheader("📈 Live Analytics")

        # Attack distribution pie chart
        attack_dist = st.session_state.real_time_data.get('attack_distribution', {})

        if attack_dist:
            df = pd.DataFrame(
                list(attack_dist.items()),
                columns=['Attack Type', 'Count']
            )

            fig = px.pie(
                df,
                values='Count',
                names='Attack Type',
                title="Attack Distribution (Live)"
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Building attack distribution data...")

    def render_network_activity(self):
        """Render network activity monitoring"""
        st.subheader("📡 Network Activity")

        col1, col2 = st.columns(2)

        with col1:
            # Network rates
            rates = st.session_state.real_time_data.get('network_rates', {})

            st.write("**Live Network Rates:**")
            st.write(f"📦 Packets/sec: {rates.get('packets_per_second', 0)}")
            st.write(f"💾 Bytes/sec: {rates.get('bytes_per_second', 0):,}")
            st.write(f"🔗 Connections: {rates.get('connections_active', 0)}")

        with col2:
            # Connection status
            counters = st.session_state.real_time_data.get('counters', {})

            st.write("**Connection Status:**")
            active_connections = counters.get('active_connections', 0)

            if active_connections > 0:
                st.success(f"🟢 {active_connections} active connections")
            else:
                st.info("🟡 No active connections")

    def render_system_health(self):
        """Render system health indicators"""
        st.subheader("💚 System Health")

        try:
            status = self.system_manager.get_system_status()

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Component Status:**")
                components = status.get('components_status', {})

                for name, running in components.items():
                    status_icon = "🟢" if running else "🔴"
                    status_text = "Running" if running else "Stopped"
                    st.write(f"{status_icon} {name}: {status_text}")

            with col2:
                st.write("**System Metrics:**")

                uptime = status.get('uptime_seconds', 0)
                if uptime > 0:
                    hours = int(uptime // 3600)
                    minutes = int((uptime % 3600) // 60)
                    st.write(f"⏱️ Uptime: {hours}h {minutes}m")

                st.write(f"🔄 System: {'🟢 Running' if status.get('running') else '🔴 Stopped'}")

        except Exception as e:
            st.error(f"Error getting system status: {e}")

    def render_real_time_controls(self):
        """Render real-time control buttons"""
        st.markdown("### 🎛️ Real-Time Controls")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("🔄 Refresh Data"):
                self._update_real_time_data()
                st.success("Data refreshed!")

        with col2:
            auto_refresh = st.checkbox("🔄 Auto-refresh", value=True)

            if auto_refresh:
                # Force refresh every 3 seconds when auto-refresh is enabled
                time.sleep(0.1)
                st.rerun()
