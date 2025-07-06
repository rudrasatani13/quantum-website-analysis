#!/usr/bin/env python3
"""
QS-AI-IDS - Quantum-Safe AI Intrusion Detection System
Main Entry Point - Fixed Streamlit Integration
"""

import os
import sys
import argparse
import signal
import subprocess
import webbrowser
import time
import threading
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))


def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    print("\n🛑 Shutdown requested. Cleaning up...")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def print_banner():
    """Display system banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗       █████╗ ██╗    ██╗██████╗ ███████╗            ║
║ ██╔═══██╗██╔════╝      ██╔══██╗██║    ██║██╔══██╗██╔════╝            ║
║ ██║   ██║███████╗█████╗███████║██║    ██║██║  ██║███████╗            ║
║ ██║▄▄ ██║╚════██║╚════╝██╔══██║██║    ██║██║  ██║╚════██║            ║
║ ╚██████╔╝███████║      ██║  ██║██████╔╝███████║███████║            ║
║  ╚══▀▀═╝ ╚══════╝      ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝            ║
║                                                                      ║
║        🧬 Quantum-Safe AI Intrusion Detection System v2.0           ║
║        🛡️ Advanced Threat Detection & Response Platform             ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def setup_directories():
    """Create necessary directories"""
    directories = [
        'logs', 'reports', 'models', 'data', 'config',
        'temp', 'exports'
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def web_mode(args):
    """Run in web interface mode using proper Streamlit"""
    print_banner()
    print("🌐 Starting QS-AI-IDS Web Interface...")
    print(f"🚀 Dashboard will be available at: http://{args.host}:{args.port}")
    print("🛑 Press Ctrl+C to stop the system")

    # Setup directories
    setup_directories()

    # Open browser after delay
    def open_browser():
        time.sleep(3)
        try:
            webbrowser.open(f"http://{args.host}:{args.port}")
            print(f"🌐 Browser opened to http://{args.host}:{args.port}")
        except:
            print("🌐 Please manually open your browser and navigate to the URL above")

    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Run Streamlit properly
    try:
        cmd = [
            sys.executable, "-m", "streamlit", "run",
            "app.py",
            "--server.port", str(args.port),
            "--server.address", args.host,
            "--server.headless", "true",
            "--browser.gatherUsageStats", "false",
            "--theme.base", "light"
        ]

        print("🔄 Starting Streamlit server...")
        subprocess.run(cmd, check=True)

    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Streamlit error: {e}")
        print("💡 Try installing Streamlit: pip install streamlit")
    except Exception as e:
        print(f"❌ Error: {e}")


def cli_mode(args):
    """Run in CLI mode"""
    print_banner()
    print("💻 Starting QS-AI-IDS in CLI mode...")

    try:
        # Import after path setup
        from config.settings import Settings
        from core.system_manager import SystemManager

        # Initialize system
        settings = Settings()
        system_manager = SystemManager(settings)

        # Start system components
        system_manager.start()

        if args.mode == 'monitor':
            print("📡 Starting network monitoring...")
            print("🔍 Monitoring network traffic for threats...")
            print("🛑 Press Ctrl+C to stop")

            # Keep running until shutdown
            try:
                while True:
                    system_manager.print_status()
                    time.sleep(10)
            except KeyboardInterrupt:
                print("\n⚠️ Monitoring stopped by user")

        elif args.mode == 'verify':
            if not args.url:
                print("❌ Error: URL required for verification mode")
                return

            print(f"✅ Verifying website: {args.url}")
            result = system_manager.verify_website(args.url)

            # Print results
            print("\n📊 VERIFICATION RESULTS:")
            print("=" * 50)
            print(f"URL: {args.url}")
            print(f"Status: {result.get('status', 'Unknown')}")
            print(f"HTTPS: {'✅ Enabled' if result.get('https_enabled') else '❌ Disabled'}")

            threats = result.get('threats_detected', [])
            if threats:
                print(f"🚨 Threats Found: {len(threats)}")
                for threat in threats:
                    print(f"  - {threat.get('type', 'Unknown')}: {threat.get('description', 'No description')}")
            else:
                print("✅ No threats detected")

        else:
            print(f"💻 CLI mode: {args.mode}")
            print("🔄 System running... Press Ctrl+C to stop")

            try:
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                print("\n⚠️ Stopped by user")

        # Cleanup
        system_manager.shutdown()
        print("✅ QS-AI-IDS stopped")

    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("🔧 Running in basic mode...")

        # Basic mode
        if args.mode == 'verify' and args.url:
            print(f"🔍 Basic verification of: {args.url}")

            try:
                import requests
                response = requests.get(args.url, timeout=10)
                print(f"Status: {response.status_code}")
                print(f"HTTPS: {'✅' if args.url.startswith('https') else '❌'}")
                print("✅ Basic check completed")
            except Exception as e:
                print(f"❌ Error: {e}")
        else:
            print("💻 Basic CLI mode - limited functionality")

    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="QS-AI-IDS - Quantum-Safe AI Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🚀 Quick Start Examples:

  # Start Web Interface (Recommended)
  python main.py web

  # Start on different port
  python main.py web --port 8080

  # CLI Network Monitoring
  python main.py cli --mode monitor

  # Verify Single Website
  python main.py cli --mode verify --url https://example.com

📖 The web interface provides the full dashboard experience!
        """
    )

    # Main command
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Web interface command (default and recommended)
    web_parser = subparsers.add_parser('web', help='Launch web interface (Recommended)')
    web_parser.add_argument('--host', default='localhost', help='Host to bind to')
    web_parser.add_argument('--port', type=int, default=8501, help='Port to bind to')
    web_parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    # CLI command
    cli_parser = subparsers.add_parser('cli', help='Run in CLI mode')
    cli_parser.add_argument('--mode', choices=['monitor', 'verify'],
                            required=True, help='Operation mode')
    cli_parser.add_argument('--url', help='Single URL to verify')

    args = parser.parse_args()

    if not args.command:
        # Default to web mode if no command specified
        print("🌐 No command specified, starting web interface...")
        args.command = 'web'
        args.host = 'localhost'
        args.port = 8501
        args.debug = False

    # Route to appropriate mode
    if args.command == 'web':
        web_mode(args)
    elif args.command == 'cli':
        cli_mode(args)


if __name__ == "__main__":
    main()
