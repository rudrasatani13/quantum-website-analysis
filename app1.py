import streamlit as st
from core.quantum_detector import QuantumThreatDetector
from utils.false_positive_filter import is_false_positive
from utils.pattern_loader import load_attack_patterns
from ai.threat_scorer import compute_threat_score
from ai.entropy_detector import entropy

# Load centralized threat patterns
patterns = load_attack_patterns()
weights = patterns.get("weights", {})
legitimate_indicators = patterns.get("legitimate_indicators", [])

# Initialize detector
detector = QuantumThreatDetector(threat_patterns=patterns)

st.set_page_config(page_title="QS-AI-IDS Dashboard", layout="centered")
st.title("🛡️ Quantum-Safe AI Intrusion Detection System")

st.markdown("---")
st.subheader("🌐 Real-Time URL Threat Analysis")

url = st.text_input("🔗 Enter a URL to analyze", placeholder="http://example.com/login?user=admin' OR 1=1")

if url:
    # Step 1: False Positive Filter
    if is_false_positive(url, legitimate_indicators):
        st.warning("⚠️ This input appears to be a legitimate query (documentation, test, etc). Skipping detection.")
    else:
        # Step 2: Entropy Check
        ent = entropy(url)
        st.info(f"🔍 Entropy Score: `{ent:.2f}`")

        if ent > 4.5:
            st.error("🚨 High entropy detected! This may indicate obfuscation or encoded threats.")

        # Step 3: Run Detector
        result = detector.analyze_url(url)

        if result.get("threat_detected"):
            st.error(f"🚨 Threat Detected: **{result['threat_type']}**")
            st.write(f"🧠 Confidence: `{result['confidence']:.2f}`")

            # Step 4: Compute threat score
            context_score = len(url) / 100.0
            weight = weights.get(result['threat_type'], 1.0)
            score = compute_threat_score(result['confidence'], context_score, weight, multiplier=1.5)

            st.write(f"📊 Threat Score: `{score:.2f}`")
            st.json(result)

        else:
            st.success("✅ No significant threat detected.")

# Optional: Add packet analyzer interface
st.markdown("---")
st.subheader("📦 Packet Analysis (Manual Input)")

payload = st.text_area("📝 Paste packet payload to analyze")

if st.button("Analyze Packet"):
    if payload:
        if is_false_positive(payload, legitimate_indicators):
            st.warning("⚠️ Legitimate input detected. Skipping analysis.")
        else:
            entropy_score = entropy(payload)
            st.info(f"🔍 Entropy Score: `{entropy_score:.2f}`")

            if entropy_score > 4.5:
                st.error("🚨 High entropy: Payload may be obfuscated.")

            packet_data = {
                "load": payload.encode("utf-8"),
                "source_ip": "192.168.0.15"
            }

            result = detector.analyze_packet(packet_data)

            if result.get("threat_detected"):
                st.error(f"🚨 Threat Detected: **{result['threat_type']}**")
                st.write(f"🧠 Confidence: `{result['confidence']:.2f}`")

                context_score = len(payload) / 100.0
                weight = weights.get(result['threat_type'], 1.0)
                score = compute_threat_score(result['confidence'], context_score, weight, 1.5)

                st.write(f"📊 Threat Score: `{score:.2f}`")
                st.json(result)

            else:
                st.success("✅ No threat detected.")
    else:
        st.warning("⚠️ Please paste some payload text first.")
