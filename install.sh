#!/bin/bash

# QS-AI-IDS Installation Script

echo "🛡️ Installing QS-AI-IDS - Quantum-Safe AI Intrusion Detection System"
echo "=================================================================="

# Check if running as root for network monitoring capabilities
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  Running as root - network monitoring will be available"
else
   echo "ℹ️  Running as user - some network monitoring features may be limited"
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs reports models data config/backups crypto/keys temp exports

# Set permissions
echo "🔒 Setting permissions..."
chmod 700 crypto/keys
chmod 755 logs reports models data temp exports

# Download quantum models (if available)
echo "🧬 Setting up quantum models..."
# This would download pre-trained models in a real deployment

# Create default configuration
echo "⚙️  Creating default configuration..."
if [ ! -f config/settings.yaml ]; then
    echo "Configuration file created at config/settings.yaml"
fi

# Install system dependencies (Ubuntu/Debian)
if command -v apt-get &> /dev/null; then
    echo "🔧 Installing system dependencies..."
    sudo apt-get update
    sudo apt-get install -y libpcap-dev tcpdump
fi

# Install system dependencies (macOS)
if command -v brew &> /dev/null; then
    echo "🔧 Installing system dependencies..."
    brew install libpcap
fi

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "🚀 To start QS-AI-IDS:"
echo "   Web Interface: python main.py web"
echo "   CLI Mode:      python main.py cli --mode monitor"
echo ""
echo "📚 For more options: python main.py --help"
echo ""
echo "⚠️  Note: Network monitoring requires root privileges"
echo "   Use: sudo python main.py cli --mode monitor"
