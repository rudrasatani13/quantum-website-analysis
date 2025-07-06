"""
Real-time monitoring system for QS-AI-IDS
Provides live data feeds and real-time updates
"""

import asyncio
import threading
import time
import queue
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, asdict
import websockets
import logging
from collections import deque, defaultdict

@dataclass
class ThreatEvent:
    """Real-time threat event"""
    timestamp: datetime
    threat_type: str
    source_ip: str
    destination_ip: str
    severity: float
    confidence: float
    payload: str
    quantum_analysis: Dict[str, Any]
    blocked: bool = False

@dataclass
class NetworkStats:
    """Real-time network statistics"""
    timestamp: datetime
    packets_per_second: int
    bytes_per_second: int
    connections_active: int
    threats_detected: int
    quantum_analyses: int

class RealTimeDataFeed:
    """Real-time data feed manager"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.threat_events = deque(maxlen=max_history)
        self.network_stats = deque(maxlen=max_history)
        self.subscribers = []
        self.running = False
        self.lock = threading.Lock()
        
        # Real-time counters
        self.counters = {
            'packets_processed': 0,
            'threats_detected': 0,
            'bytes_processed': 0,
            'quantum_analyses': 0,
            'blocked_ips': set(),
            'active_connections': 0
        }
        
        # Rate tracking
        self.rate_tracker = {
            'packets': deque(maxlen=60),  # Last 60 seconds
            'threats': deque(maxlen=60),
            'bytes': deque(maxlen=60)
        }
        
        self.logger = logging.getLogger(__name__)
    
    def add_threat_event(self, event: ThreatEvent):
        """Add new threat event"""
        with self.lock:
            self.threat_events.append(event)
            self.counters['threats_detected'] += 1
            
            if event.blocked:
                self.counters['blocked_ips'].add(event.source_ip)
        
        # Notify subscribers
        self._notify_subscribers('threat_event', asdict(event))
    
    def add_network_stats(self, stats: NetworkStats):
        """Add network statistics"""
        with self.lock:
            self.network_stats.append(stats)
            
            # Update rate tracking
            current_time = time.time()
            self.rate_tracker['packets'].append((current_time, stats.packets_per_second))
            self.rate_tracker['threats'].append((current_time, stats.threats_detected))
            self.rate_tracker['bytes'].append((current_time, stats.bytes_per_second))
        
        # Notify subscribers
        self._notify_subscribers('network_stats', asdict(stats))
    
    def update_counters(self, **kwargs):
        """Update real-time counters"""
        with self.lock:
            for key, value in kwargs.items():
                if key in self.counters:
                    if isinstance(self.counters[key], int):
                        self.counters[key] += value
                    else:
                        self.counters[key] = value
        
        # Notify subscribers
        self._notify_subscribers('counters_update', self.get_current_counters())
    
    def get_current_counters(self) -> Dict[str, Any]:
        """Get current counter values"""
        with self.lock:
            return {
                'packets_processed': self.counters['packets_processed'],
                'threats_detected': self.counters['threats_detected'],
                'bytes_processed': self.counters['bytes_processed'],
                'quantum_analyses': self.counters['quantum_analyses'],
                'blocked_ips_count': len(self.counters['blocked_ips']),
                'active_connections': self.counters['active_connections']
            }
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent threat events"""
        with self.lock:
            recent = list(self.threat_events)[-limit:]
            return [asdict(event) for event in recent]
    
    def get_threat_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get threat timeline for specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            timeline_data = []
            threat_counts = defaultdict(int)
            
            for event in self.threat_events:
                if event.timestamp >= cutoff_time:
                    hour_key = event.timestamp.strftime('%Y-%m-%d %H:00')
                    threat_counts[hour_key] += 1
            
            # Convert to timeline format
            for hour_key, count in sorted(threat_counts.items()):
                timeline_data.append({
                    'timestamp': hour_key,
                    'threat_count': count
                })
            
            return timeline_data
    
    def get_attack_distribution(self) -> Dict[str, int]:
        """Get attack type distribution"""
        with self.lock:
            distribution = defaultdict(int)
            
            for event in self.threat_events:
                distribution[event.threat_type] += 1
            
            return dict(distribution)
    
    def get_network_rates(self) -> Dict[str, float]:
        """Get current network rates"""
        current_time = time.time()
        cutoff_time = current_time - 60  # Last minute
        
        rates = {}
        
        for metric, data in self.rate_tracker.items():
            recent_data = [(t, v) for t, v in data if t >= cutoff_time]
            if recent_data:
                rates[f'{metric}_per_second'] = sum(v for _, v in recent_data) / len(recent_data)
            else:
                rates[f'{metric}_per_second'] = 0
        
        return rates
    
    def subscribe(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Subscribe to real-time updates"""
        self.subscribers.append(callback)
    
    def unsubscribe(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Unsubscribe from real-time updates"""
        if callback in self.subscribers:
            self.subscribers.remove(callback)
    
    def _notify_subscribers(self, event_type: str, data: Dict[str, Any]):
        """Notify all subscribers of new data"""
        for callback in self.subscribers:
            try:
                callback(event_type, data)
            except Exception as e:
                self.logger.error(f"Subscriber notification error: {e}")

class WebSocketServer:
    """WebSocket server for real-time updates"""
    
    def __init__(self, data_feed: RealTimeDataFeed, host: str = "localhost", port: int = 8765):
        self.data_feed = data_feed
        self.host = host
        self.port = port
        self.clients = set()
        self.server = None
        self.loop = None
        self.logger = logging.getLogger(__name__)
    
    async def register_client(self, websocket, path):
        """Register new WebSocket client"""
        self.clients.add(websocket)
        self.logger.info(f"Client connected: {websocket.remote_address}")
        
        # Send initial data
        await self.send_initial_data(websocket)
        
        try:
            await websocket.wait_closed()
        finally:
            self.clients.remove(websocket)
            self.logger.info(f"Client disconnected: {websocket.remote_address}")
    
    async def send_initial_data(self, websocket):
        """Send initial data to new client"""
        try:
            # Send current counters
            counters = self.data_feed.get_current_counters()
            await websocket.send(json.dumps({
                'type': 'initial_counters',
                'data': counters
            }))
            
            # Send recent threats
            recent_threats = self.data_feed.get_recent_threats(20)
            await websocket.send(json.dumps({
                'type': 'recent_threats',
                'data': recent_threats
            }))
            
            # Send attack distribution
            attack_dist = self.data_feed.get_attack_distribution()
            await websocket.send(json.dumps({
                'type': 'attack_distribution',
                'data': attack_dist
            }))
            
        except Exception as e:
            self.logger.error(f"Error sending initial data: {e}")
    
    async def broadcast_update(self, event_type: str, data: Dict[str, Any]):
        """Broadcast update to all connected clients"""
        if not self.clients:
            return
        
        message = json.dumps({
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
        
        # Send to all clients
        disconnected = set()
        for client in self.clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                self.logger.error(f"Error broadcasting to client: {e}")
                disconnected.add(client)
        
        # Remove disconnected clients
        self.clients -= disconnected
    
    def start_server(self):
        """Start WebSocket server"""
        async def run_server():
            self.server = await websockets.serve(
                self.register_client,
                self.host,
                self.port
            )
            self.logger.info(f"WebSocket server started on {self.host}:{self.port}")
            await self.server.wait_closed()
        
        # Run server in event loop
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(run_server())

    def stop_server(self):
        """Stop WebSocket server"""
        if self.server:
            self.server.close()

class RealTimeMonitor:
    """Main real-time monitoring coordinator"""
    
    def __init__(self, system_manager):
        self.system_manager = system_manager
        self.data_feed = RealTimeDataFeed()
        self.websocket_server = WebSocketServer(self.data_feed)
        self.running = False
        self.threads = []
        self.logger = logging.getLogger(__name__)
        
        # Subscribe to data feed updates
        self.data_feed.subscribe(self._handle_data_update)
    
    def start(self):
        """Start real-time monitoring"""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Starting real-time monitoring...")
        
        # Start WebSocket server
        websocket_thread = threading.Thread(
            target=self.websocket_server.start_server,
            daemon=True
        )
        websocket_thread.start()
        self.threads.append(websocket_thread)
        
        # Start statistics collector
        stats_thread = threading.Thread(
            target=self._collect_statistics,
            daemon=True
        )
        stats_thread.start()
        self.threads.append(stats_thread)
        
        # Start network monitor
        network_thread = threading.Thread(
            target=self._monitor_network,
            daemon=True
        )
        network_thread.start()
        self.threads.append(network_thread)
        
        self.logger.info("Real-time monitoring started")
    
    def stop(self):
        """Stop real-time monitoring"""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping real-time monitoring...")
        
        # Stop WebSocket server
        self.websocket_server.stop_server()
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        self.logger.info("Real-time monitoring stopped")
    
    def _handle_data_update(self, event_type: str, data: Dict[str, Any]):
        """Handle data feed updates"""
        # Broadcast to WebSocket clients
        asyncio.run_coroutine_threadsafe(
            self.websocket_server.broadcast_update(event_type, data),
            asyncio.get_event_loop()
        )
    
    def _collect_statistics(self):
        """Collect real-time statistics"""
        while self.running:
            try:
                # Get current system status
                status = self.system_manager.get_system_status()
                stats = status['statistics']
                
                # Create network stats
                network_stats = NetworkStats(
                    timestamp=datetime.now(),
                    packets_per_second=self._calculate_rate('packets_processed', stats),
                    bytes_per_second=self._calculate_rate('bytes_processed', stats),
                    connections_active=stats.get('active_connections', 0),
                    threats_detected=stats.get('threats_detected', 0),
                    quantum_analyses=stats.get('quantum_analyses', 0)
                )
                
                self.data_feed.add_network_stats(network_stats)
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                self.logger.error(f"Statistics collection error: {e}")
                time.sleep(5)
    
    def _monitor_network(self):
        """Monitor network for real-time threats"""
        while self.running:
            try:
                # This would integrate with actual network monitoring
                # For now, we'll simulate real network monitoring
                
                # Check for new threats from quantum detector
                if hasattr(self.system_manager, 'components'):
                    quantum_detector = self.system_manager.components.get('quantum_detector')
                    if quantum_detector and hasattr(quantum_detector, 'get_recent_detections'):
                        recent_detections = quantum_detector.get_recent_detections()
                        
                        for detection in recent_detections:
                            threat_event = ThreatEvent(
                                timestamp=datetime.now(),
                                threat_type=detection.get('threat_type', 'Unknown'),
                                source_ip=detection.get('source_ip', '0.0.0.0'),
                                destination_ip=detection.get('destination_ip', '0.0.0.0'),
                                severity=detection.get('severity', 0.5),
                                confidence=detection.get('confidence', 0.5),
                                payload=detection.get('payload', ''),
                                quantum_analysis=detection.get('quantum_analysis', {}),
                                blocked=detection.get('blocked', False)
                            )
                            
                            self.data_feed.add_threat_event(threat_event)
                
                time.sleep(0.1)  # Check every 100ms
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(1)
    
    def _calculate_rate(self, metric: str, stats: Dict[str, Any]) -> int:
        """Calculate rate for a metric"""
        # This would calculate actual rates based on historical data
        # For now, return current value or simulate rate
        return stats.get(metric, 0)
    
    def add_threat_detection(self, detection: Dict[str, Any]):
        """Add new threat detection"""
        threat_event = ThreatEvent(
            timestamp=datetime.now(),
            threat_type=detection.get('threat_type', 'Unknown'),
            source_ip=detection.get('source_ip', '0.0.0.0'),
            destination_ip=detection.get('destination_ip', '0.0.0.0'),
            severity=detection.get('severity', 0.5),
            confidence=detection.get('confidence', 0.5),
            payload=detection.get('payload', ''),
            quantum_analysis=detection.get('quantum_analysis', {}),
            blocked=detection.get('blocked', False)
        )
        
        self.data_feed.add_threat_event(threat_event)
    
    def get_real_time_data(self) -> Dict[str, Any]:
        """Get current real-time data"""
        return {
            'counters': self.data_feed.get_current_counters(),
            'recent_threats': self.data_feed.get_recent_threats(10),
            'threat_timeline': self.data_feed.get_threat_timeline(24),
            'attack_distribution': self.data_feed.get_attack_distribution(),
            'network_rates': self.data_feed.get_network_rates()
        }

    def _broadcast_data(self):
        """Broadcast data to all connected clients."""
        if self.websocket_server and self.websocket_server.is_running():
            data = self.get_real_time_data()

            # Ensure this is thread-safe
            asyncio.run_coroutine_threadsafe(
                self.websocket_server.broadcast_update(data),
                self.websocket_server.loop
            )
