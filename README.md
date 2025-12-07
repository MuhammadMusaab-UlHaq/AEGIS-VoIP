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
- Progressive Web App (PWA) capable

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
│  │ - Frame-level encryption with authentication             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Transport Layer:                                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ DTLS-SRTP (WebRTC built-in)                              │  │
│  │ - Standard WebRTC encryption                             │  │
│  │ - Provides first layer of protection                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Key Agreement:                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Hybrid PQC: X25519 + Kyber-1024                          │  │
│  │ - Quantum-resistant key exchange                         │  │
│  │ - 256-bit master secret derivation                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ How to Run

### Prerequisites
- Modern browser (Chrome 90+, Firefox 117+, Edge 90+)
- Node.js and npm (for development server)
- Camera and microphone access

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd aegis-voip
```

2. **Install dependencies:**
```bash
npm install
```

3. **Start the development server:**
```bash
npm run dev
```

4. **Open in browser:**
```
http://localhost:5173
```

### Making a Secure Call

1. **Initiator (Peer A):**
   - Open the application in a browser tab
   - Click "Create Call"
   - Copy the Offer token
   - Send it to Peer B (via any messenger/email)

2. **Responder (Peer B):**
   - Open the application in another tab/device
   - Click "Join Call"
   - Paste the Offer token
   - Copy the generated Answer token
   - Send it back to Peer A

3. **Initiator (Peer A):**
   - Paste the Answer token
   - Click "Connect"

4. **Both Peers:**
   - Verbally compare the 4-character SAS code
   - If codes match, click "Accept"
   - Call is now quantum-secure with double encryption!

---

## 🔐 Threat Model

### Protected Against:
- **Quantum Attacks**: Hybrid PQC protects against future quantum computers
- **Man-in-the-Middle**: SAS verification detects active attackers
- **Passive Eavesdropping**: Double encryption prevents wiretapping
- **Server Compromise**: Manual signaling means no server has keys
- **DTLS Downgrade**: Second encryption layer provides defense-in-depth

### Limitations:
- Cannot protect against endpoint compromise (malware)
- Requires user vigilance for SAS comparison
- Browser/OS vulnerabilities out of scope
- No protection against traffic analysis

---

## 📊 Security Analysis

### Key Exchange Security
- **Classical Security**: 128-bit (X25519 ECDH)
- **Post-Quantum Security**: NIST Level 5 (Kyber-1024)
- **Combined Security**: Maximum of both

### Encryption Strength
- **Layer 1 (DTLS-SRTP)**: AES-128/256 depending on negotiation
- **Layer 2 (Custom E2EE)**: AES-256-GCM with 128-bit auth tag
- **Key Derivation**: HKDF-SHA256

### SAS Collision Resistance
- **Base32 Format**: 20 bits entropy (1 in 1,048,576)
- **PGP Words**: 16 bits entropy (1 in 65,536)
- Single guess probability for attacker

---

## 🌐 Browser Compatibility

| Browser | Desktop Windows | Desktop Mac/Linux | Android | iOS | Notes |
|---------|----------------|-------------------|---------|-----|-------|
| Chrome | ⚠️ Issues* | ✅ Full | ✅ Full | ❌ No E2EE** | *Some systems block WebRTC |
| **Edge** | ✅ Full | ✅ Full | ✅ Full | ❌ No E2EE** | **Recommended for Windows** |
| Firefox | ✅ Full | ✅ Full | ✅ Full | ❌ No E2EE** | Good alternative |
| Safari | ⚠️ Limited | ⚠️ Limited | N/A | ❌ No E2EE** | Basic WebRTC only |

*If Chrome shows 0 ICE candidates on Windows, use Microsoft Edge instead  
**iOS browsers use WebKit engine, lacking Insertable Streams API for double encryption

### Recommended Combinations:
- **Windows PC + Android**: Edge (PC) + Chrome (Android)
- **Mac + Android**: Chrome/Firefox (Mac) + Chrome (Android)
- **Linux + Android**: Chrome/Firefox (Linux) + Chrome (Android)
- **Cross-Platform**: Firefox on both devices

---

## 📚 Technical Stack

- **Frontend**: Vanilla JavaScript (ES6+)
- **Styling**: Pico.css framework
- **Crypto Libraries**: 
  - libsodium-wrappers (X25519)
  - kyber-crystals (Kyber KEM)
  - WebCrypto API (AES-GCM)
- **Build Tool**: Vite
- **WebRTC APIs**: RTCPeerConnection, RTCRtpScriptTransform

---

## 🔬 Implementation Details

### Double Encryption Flow

1. **Key Exchange Phase**:
   - Hybrid PQC key agreement establishes shared secret
   - HKDF derives 256-bit master secret
   - SAS generated for authentication

2. **SAS Verification**:
   - Users compare 4-character codes verbally
   - On acceptance, encryption worker is activated

3. **Media Encryption**:
   - Master secret sent to Web Worker
   - Worker derives AES-256-GCM key using HKDF
   - RTCRtpScriptTransform intercepts media frames
   - Each frame encrypted with unique IV (counter mode)
   - Magic bytes mark encrypted frames

4. **Frame Structure**:
   ```
   [Codec Header][Magic: 0xAE6153][IV: 12 bytes][Encrypted Payload + Tag]
   ```

---

## 🤝 Contributing

This is a proof-of-concept for educational purposes. Contributions welcome!

---

## ⚖️ License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- NIST for PQC standardization
- WebRTC community for Insertable Streams API
- Paper authors from literature review

---

## ⚠️ Disclaimer

This is a proof-of-concept implementation for academic purposes. Do not use for production without proper security audit.
2. Open `https://*.trycloudflare.com` in **Device 2**
3. In **Tab 1**: Click "Create Call" → Copy the Offer token
4. In **Tab 2**: Click "Join Call" → Paste the Offer → Copy the Answer token
5. In **Tab 1**: Paste the Answer token → Click "Connect"
6. Both tabs should now show video from each other!

## 📅 Development Progress

- [x] Day 1: Foundational WebRTC Video Call
- [x] Day 2: Hybrid Post-Quantum Key Exchange
- [x] Day 3: MITM Detection via SAS
- [x] Day 4: Double-Layer Encryption & Polish

## 📚 References

Based on academic research in post-quantum VoIP security. See `/papers` directory.
