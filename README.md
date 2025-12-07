# AEGIS-VoIP 🛡️
## Post-Quantum Secure Voice/Video Communication System

A proof-of-concept implementation of quantum-resistant, end-to-end encrypted video calling using WebRTC with hybrid post-quantum cryptography and double-layer encryption.

---

## 🚀 Features

### Security Features
- **Hybrid Post-Quantum Key Exchange**: X25519 (ECDH) + Kyber-1024 (NIST ML-KEM)
- **Double-Layer Encryption**: 
  - Layer 1: WebRTC's built-in DTLS-SRTP
  - Layer 2: Custom AES-256-GCM via Insertable Streams
- **MITM Detection**: ZRTP-inspired Short Authentication String (SAS)
- **Perfect Forward Secrecy**: Each call uses unique ephemeral keys
- **Manual Signaling**: No server can intercept call metadata

### Technical Features
- Pure browser-based (no plugins/extensions)
- Peer-to-peer communication via WebRTC
- Works locally without any server infrastructure
- Cross-platform (Desktop + Mobile)

---

## 🔒 Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AEGIS-VoIP Security Stack                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Application Layer:                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ AES-256-GCM Encryption (from PQC-derived key)            │  │
│  │ - Implemented via WebRTC Insertable Streams              │  │
│  │ - Frame-level encryption with VP8 header preservation    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Transport Layer:                                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ DTLS-SRTP (WebRTC built-in)                              │  │
│  │ - Standard WebRTC encryption                             │  │
│  │ - Provides first layer of protection                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Key Agreement:                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Hybrid PQC: X25519 + Kyber-1024                          │  │
│  │ - Quantum-resistant key exchange                         │  │
│  │ - 256-bit master secret derivation via HKDF              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ How to Run

### Prerequisites
- Modern browser (Edge, Firefox, or Chrome)
- Node.js and npm
- Camera and microphone access

### Installation

```bash
# Clone and install
git clone <repository-url>
cd aegis-voip
npm install

# Start development server
npm run dev
```

Open `http://localhost:5173` in your browser.

### Cross-Device Testing

```bash
# Terminal 1: Start Vite
npm run dev

# Terminal 2: Create tunnel
ngrok http [port-number-from-npm-run-dev]
```

Use the generated `*.ngrok.*` URL on **both** devices.
Make sure that ngrok has been previously already configured, if not, then configure it first.

---

## 📞 Making a Secure Call

### Step-by-Step

1. **Initiator (Peer A):**
   - Open the application
   - Click **"Create Call"**
   - Copy the Offer token
   - Send it to Peer B (via any messenger)

2. **Responder (Peer B):**
   - Open the application (same URL)
   - Click **"Join Call"**
   - Paste the Offer token → Click **"Process Offer"**
   - Copy the Answer token
   - Send it back to Peer A

3. **Initiator (Peer A):**
   - Paste the Answer token
   - Click **"Connect"**

4. **Both Peers:**
   - Compare the 4-character SAS code verbally
   - If codes match, click **"Accept"**
   - ✅ Call is now quantum-secure with double encryption!

---

## 🔐 Threat Model

### Protected Against
| Threat | Protection |
|--------|------------|
| Quantum Attacks | Hybrid PQC (X25519 + Kyber-1024) |
| Man-in-the-Middle | SAS verification detects active attackers |
| Passive Eavesdropping | Double encryption prevents wiretapping |
| Server Compromise | Manual signaling - no server has keys |
| DTLS Downgrade | Second encryption layer provides defense-in-depth |

### Out of Scope
- Endpoint compromise (malware on device)
- Browser/OS vulnerabilities
- Traffic analysis attacks
- Physical access to device

---

## 📊 Security Parameters

| Component | Specification |
|-----------|---------------|
| Classical Key Exchange | X25519 (128-bit security) |
| Post-Quantum KEM | Kyber-1024 (NIST Level 5) |
| Key Derivation | HKDF-SHA256 |
| Layer 1 Encryption | DTLS-SRTP (AES-128/256) |
| Layer 2 Encryption | AES-256-GCM |
| SAS Entropy | 20 bits (Base32) / 16 bits (PGP words) |

---

## 🌐 Browser Compatibility

| Browser | Windows | macOS/Linux | Android | iOS |
|---------|---------|-------------|---------|-----|
| **Edge** | ✅ Recommended | ✅ | ✅ | ❌* |
| Firefox | ✅ | ✅ | ✅ | ❌* |
| Chrome | ⚠️ ICE issues** | ✅ | ✅ | ❌* |
| Safari | ⚠️ Limited | ⚠️ Limited | N/A | ❌* |

*iOS browsers use WebKit, which lacks Insertable Streams API  
**Some Windows systems block WebRTC in Chrome; use Edge instead

### Recommended Combinations
- **Windows + Android**: Edge (PC) + Chrome (Mobile)
- **Mac/Linux + Android**: Firefox/Chrome + Chrome (Mobile)

---

## 📚 Technical Stack

| Component | Technology |
|-----------|------------|
| Frontend | Vanilla JavaScript (ES6+) |
| Styling | Pico.css |
| Build Tool | Vite |
| Classical Crypto | libsodium-wrappers (X25519) |
| Post-Quantum Crypto | kyber-crystals (Kyber-1024) |
| Symmetric Crypto | WebCrypto API (AES-GCM) |
| Real-time Comm | WebRTC APIs |

---

## 📁 Project Structure

```
aegis-voip/
├── index.html          # Main UI with modals
├── package.json        # Dependencies
├── vite.config.js      # Dev server config
├── src/
│   ├── app.js          # Main application logic
│   ├── crypto.js       # Hybrid PQC implementation
│   ├── worker.js       # Frame encryption worker
│   └── style.css       # UI styling
└── papers/             # Research references
```

---

## 📅 Development Progress

- [x] Day 1: Foundational WebRTC Video Call
- [x] Day 2: Hybrid Post-Quantum Key Exchange (X25519 + Kyber)
- [x] Day 3: MITM Detection via SAS Verification
- [x] Day 4: Double-Layer Encryption & Polish

---

## 📚 References

This project implements concepts from academic research in post-quantum VoIP security:

- ZRTP Protocol (RFC 6189) - SAS verification
- NIST PQC Standardization - Kyber/ML-KEM
- WebRTC Insertable Streams - Frame-level encryption
- Hybrid PQC schemes - Defense-in-depth

See `/papers` directory for full literature review.

---

## ⚖️ License

MIT License - See LICENSE file for details.

---

## ⚠️ Disclaimer

This is a proof-of-concept implementation for academic purposes. Not intended for production use without proper security audit.

---

*AEGIS-VoIP - Information Security Semester Project*