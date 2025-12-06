# AEGIS-VoIP: Post-Quantum Secure Communication

A proof-of-concept secure VoIP solution demonstrating hybrid post-quantum cryptography, ZRTP-inspired authentication, and double-layer encryption.

## 🔐 Security Features

- **Hybrid PQC Key Exchange**: X25519 + Kyber (ML-KEM) for quantum-resistant security
- **Short Authentication String (SAS)**: ZRTP-inspired MITM detection
- **Double Encryption**: WebRTC DTLS-SRTP + Application-layer AES-GCM

## 🛠 Technology Stack

- Vanilla HTML/CSS/JavaScript (ES6)
- WebRTC APIs
- Pico.css for styling
- libsodium.js (X25519)
- Kyber WASM (Post-Quantum KEM)

## 🚀 How to Run

### Prerequisites
- Modern browser (Chrome 94+ or Edge 94+ recommended for Insertable Streams)
- Local web server (required for WebRTC)

### Quick Start

**Option 1: Python HTTP Server**
```bash
cd src
python -m http.server 8080
```

**Option 2: Node.js http-server**
```bash
npx http-server src -p 8080
```

**Option 3: VS Code Live Server Extension**
- Install "Live Server" extension
- Right-click `index.html` → "Open with Live Server"

### Demo Instructions

1. Open `http://localhost:8080` in **Browser Tab 1**
2. Open `http://localhost:8080` in **Browser Tab 2**
3. In **Tab 1**: Click "Create Call" → Copy the Offer token
4. In **Tab 2**: Click "Join Call" → Paste the Offer → Copy the Answer token
5. In **Tab 1**: Paste the Answer token → Click "Connect"
6. Both tabs should now show video from each other!

## 📅 Development Progress

- [x] Day 1: Foundational WebRTC Video Call
- [ ] Day 2: Hybrid Post-Quantum Key Exchange
- [ ] Day 3: MITM Detection via SAS
- [ ] Day 4: Double-Layer Encryption & Polish

## 📚 References

Based on academic research in post-quantum VoIP security. See `/papers` directory.
