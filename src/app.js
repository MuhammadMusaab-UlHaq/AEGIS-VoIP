/**
 * AEGIS-VoIP - Post-Quantum Secure Communication
 * Day 2: Hybrid Post-Quantum Key Exchange Integration
 * 
 * This module implements a peer-to-peer video call using WebRTC
 * with manual signaling and hybrid PQC key exchange (X25519 + Kyber512).
 */

// ============================================
// DAY 2: Import the Crypto Module
// ============================================
import { Crypto, CryptoUtils } from './crypto.js';

// ============================================
// Configuration
// ============================================

const CONFIG = {
    // ICE servers for NAT traversal
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        // Add a free TURN server for testing
        {
            urls: 'turn:openrelay.metered.ca:80',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        {
            urls: 'turn:openrelay.metered.ca:443',
            username: 'openrelayproject', 
            credential: 'openrelayproject'
        }
    ],
    // Media constraints
    mediaConstraints: {
        video: {
            width: { ideal: 1280 },
            height: { ideal: 720 },
            facingMode: 'user'
        },
        audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true
        }
    },
    // ICE gathering timeout (ms)
    iceGatheringTimeout: 5000
};

// ============================================
// State Management
// ============================================

const state = {
    peerConnection: null,
    localStream: null,
    remoteStream: null,
    isInitiator: false,
    connectionState: 'disconnected',
    iceCandidates: [],
    iceGatheringComplete: false,
    
    // DAY 2 & 3: Crypto state
    crypto: {
        myKeys: null,              // Our hybrid key pair
        theirEcdhPk: null,         // Peer's ECDH public key
        theirKyberPk: null,        // Peer's Kyber public key (responder only)
        myEcdhPk: null,            // Our ECDH public key (responder only)
        kyberCiphertext: null,     // Kyber ciphertext (shared)
        masterSecret: null,        // The derived master shared secret
        isKeyExchangeComplete: false,
        sas: null                  // Generated SAS codes
    }
};

// ============================================
// DOM Elements
// ============================================

const elements = {
    // Videos
    localVideo: document.getElementById('localVideo'),
    remoteVideo: document.getElementById('remoteVideo'),
    remotePlaceholder: document.getElementById('remote-placeholder'),
    
    // Buttons
    createCallBtn: document.getElementById('createCallBtn'),
    joinCallBtn: document.getElementById('joinCallBtn'),
    hangupBtn: document.getElementById('hangupBtn'),
    toggleVideoBtn: document.getElementById('toggleVideoBtn'),
    toggleAudioBtn: document.getElementById('toggleAudioBtn'),
    
    // Status
    securityIndicator: document.getElementById('security-indicator'),
    connectionState: document.getElementById('connection-state'),
    mediaControls: document.getElementById('media-controls'),
    
    // Offer Modal
    offerModal: document.getElementById('offer-modal'),
    offerDisplay: document.getElementById('offer-display'),
    answerInput: document.getElementById('answer-input'),
    copyOfferBtn: document.getElementById('copy-offer-btn'),
    cancelOfferBtn: document.getElementById('cancel-offer-btn'),
    connectBtn: document.getElementById('connect-btn'),
    
    // Join Modal
    joinModal: document.getElementById('join-modal'),
    offerInput: document.getElementById('offer-input'),
    processOfferBtn: document.getElementById('process-offer-btn'),
    
    // Answer Modal
    answerModal: document.getElementById('answer-modal'),
    answerDisplay: document.getElementById('answer-display'),
    copyAnswerBtn: document.getElementById('copy-answer-btn'),
    answerDoneBtn: document.getElementById('answer-done-btn'),
    
    // SAS Modal (for Day 3)
    sasModal: document.getElementById('sas-modal'),
    sasCode: document.getElementById('sas-code'),
    sasAccept: document.getElementById('sas-accept'),
    sasReject: document.getElementById('sas-reject'),
    
    // Debug
    debugLog: document.getElementById('debug-log'),
    clearLogBtn: document.getElementById('clearLogBtn')
};

// ============================================
// Logging Utility
// ============================================

const Logger = {
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[${timestamp}] [${type.toUpperCase()}] ${message}`);
        
        if (elements.debugLog) {
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `
                <span class="log-time">${timestamp}</span>
                <span class="log-${type}">${message}</span>
            `;
            elements.debugLog.appendChild(entry);
            elements.debugLog.scrollTop = elements.debugLog.scrollHeight;
        }
    },
    
    info(msg) { this.log(msg, 'info'); },
    success(msg) { this.log(msg, 'success'); },
    warning(msg) { this.log(msg, 'warning'); },
    error(msg) { this.log(msg, 'error'); },
    crypto(msg) { this.log(`🔐 ${msg}`, 'crypto'); }  // DAY 2: Special crypto logging
};

// ============================================
// UI State Management
// ============================================

function updateSecurityIndicator(status) {
    const indicator = elements.securityIndicator;
    const textSpan = indicator.querySelector('.indicator-text');
    
    // Remove all status classes
    indicator.classList.remove('disconnected', 'connecting', 'connected', 'unverified', 'verified');
    
    // Add new status class and update text
    indicator.classList.add(status);
    
    const statusTexts = {
        'disconnected': 'Disconnected',
        'connecting': 'Connecting...',
        'connected': 'Connected (Unverified)',
        'unverified': 'Connected - Verify Security',
        'verified': 'Connected - Verified ✓'
    };
    
    textSpan.textContent = statusTexts[status] || status;
    state.connectionState = status;
}

function updateConnectionStateDisplay(stateText) {
    elements.connectionState.textContent = stateText;
}

function setButtonStates(phase) {
    switch (phase) {
        case 'initial':
            elements.createCallBtn.disabled = false;
            elements.joinCallBtn.disabled = false;
            elements.hangupBtn.disabled = true;
            elements.mediaControls.classList.add('hidden');
            break;
        case 'calling':
            elements.createCallBtn.disabled = true;
            elements.joinCallBtn.disabled = true;
            elements.hangupBtn.disabled = false;
            break;
        case 'connected':
            elements.createCallBtn.disabled = true;
            elements.joinCallBtn.disabled = true;
            elements.hangupBtn.disabled = false;
            elements.mediaControls.classList.remove('hidden');
            break;
    }
}

// ============================================
// Modal Management
// ============================================

function openModal(modal) {
    modal.showModal();
}

function closeModal(modal) {
    modal.close();
}

function closeAllModals() {
    [elements.offerModal, elements.joinModal, elements.answerModal, elements.sasModal].forEach(modal => {
        if (modal && modal.open) modal.close();
    });
}

// ============================================
// Media Stream Management
// ============================================

async function initializeLocalMedia() {
    try {
        Logger.info('Requesting camera and microphone access...');
        
        state.localStream = await navigator.mediaDevices.getUserMedia(CONFIG.mediaConstraints);
        elements.localVideo.srcObject = state.localStream;
        
        Logger.success('Local media stream initialized');
        return true;
    } catch (error) {
        Logger.error(`Failed to access media devices: ${error.message}`);
        alert('Could not access camera/microphone. Please ensure permissions are granted.');
        return false;
    }
}

function stopLocalMedia() {
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => {
            track.stop();
            Logger.info(`Stopped ${track.kind} track`);
        });
        state.localStream = null;
        elements.localVideo.srcObject = null;
    }
}

// ============================================
// WebRTC Peer Connection
// ============================================

function createPeerConnection() {
    Logger.info('Creating RTCPeerConnection...');
    
    const pc = new RTCPeerConnection({ iceServers: CONFIG.iceServers });
    
    // Create a data channel to force ICE candidate generation
    const dataChannel = pc.createDataChannel('dummy');
    dataChannel.onopen = () => Logger.info('Data channel opened');
    dataChannel.onclose = () => Logger.info('Data channel closed');
    
    // Add local tracks to connection
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => {
            pc.addTrack(track, state.localStream);
            Logger.info(`Added ${track.kind} track to peer connection`);
        });
    }
    
    // Handle ICE candidates
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            Logger.info(`ICE candidate gathered: ${event.candidate.candidate.substring(0, 50)}...`);
            state.iceCandidates.push(event.candidate);
        } else {
            Logger.success('ICE gathering complete');
            state.iceGatheringComplete = true;
        }
    };
    
    // Debug: Track ICE gathering state changes
    pc.onicegatheringstatechange = () => {
        Logger.info(`ICE gathering state changed to: ${pc.iceGatheringState}`);
        console.log('ICE gathering state:', pc.iceGatheringState);
        console.log('Current candidate count:', state.iceCandidates.length);
    };
    
    // Handle ICE connection state changes - ENHANCED DEBUG
    pc.oniceconnectionstatechange = () => {
        Logger.info(`ICE connection state: ${pc.iceConnectionState}`);
        
        // Add debug info
        console.log('=== DEBUG: ICE State Change ===');
        console.log('ICE State:', pc.iceConnectionState);
        console.log('Connection State:', pc.connectionState);
        console.log('=============================');
        
        switch (pc.iceConnectionState) {
            case 'connected':
            case 'completed':
                updateSecurityIndicator('unverified');
                setButtonStates('connected');
                Logger.success('ICE connection established');
                
                // Force video play when connected
                if (elements.remoteVideo && elements.remoteVideo.srcObject) {
                    elements.remoteVideo.play().catch(err => {
                        Logger.error('Auto-play failed: ' + err.message);
                    });
                }
                break;
            case 'disconnected':
                updateSecurityIndicator('connecting');
                break;
            case 'failed':
                Logger.error('ICE connection failed');
                updateSecurityIndicator('disconnected');
                break;
            case 'closed':
                updateSecurityIndicator('disconnected');
                break;
        }
    };
    
    // Handle connection state changes
    pc.onconnectionstatechange = () => {
        Logger.info(`Connection state: ${pc.connectionState}`);
        
        if (pc.connectionState === 'failed') {
            Logger.error('Peer connection failed');
            hangUp();
        }
    };
    
    // Handle incoming tracks - ENHANCED DEBUG
    pc.ontrack = (event) => {
        Logger.success(`Received remote ${event.track.kind} track`);
        
        if (!state.remoteStream) {
            state.remoteStream = new MediaStream();
            elements.remoteVideo.srcObject = state.remoteStream;
            Logger.info('Created new MediaStream and attached to video element');
        }
        
        state.remoteStream.addTrack(event.track);
        
        // Debug: Check track state
        console.log('=== DEBUG: Track Added ===');
        console.log('Track kind:', event.track.kind);
        console.log('Track enabled:', event.track.enabled);
        console.log('Track muted:', event.track.muted);
        console.log('Track readyState:', event.track.readyState);
        console.log('Track ID:', event.track.id);
        console.log('Remote video element exists:', !!elements.remoteVideo);
        console.log('Remote video srcObject:', elements.remoteVideo?.srcObject);
        console.log('Remote video muted:', elements.remoteVideo?.muted);
        console.log('Remote stream track count:', state.remoteStream?.getTracks().length);
        console.log('=========================');
        
        // Force unmute the track if it's muted
        if (event.track.muted) {
            Logger.warning(`Track ${event.track.kind} is muted at source - this needs peer to unmute`);
        }
        
        // Don't hide placeholder here anymore
        // elements.remotePlaceholder.classList.add('hidden');
    };
    
    // Handle negotiation needed (for future use)
    pc.onnegotiationneeded = () => {
        Logger.info('Negotiation needed');
    };
    
    state.peerConnection = pc;
    return pc;
}

// ============================================
// DAY 2: Enhanced Signaling Token with Crypto
// ============================================

/**
 * Create signaling token that includes SDP, ICE candidates, and crypto data
 */
function createSignalingToken(sdp, iceCandidates, cryptoData = null) {
    const token = {
        sdp: sdp,
        ice: iceCandidates,
        timestamp: Date.now(),
        version: '2.0',  // Updated version for Day 2
        crypto: cryptoData  // New: crypto key exchange data
    };
    return btoa(JSON.stringify(token));
}

/**
 * Parse signaling token and extract all data
 */
function parseSignalingToken(tokenString) {
    try {
        const decoded = atob(tokenString.trim());
        const token = JSON.parse(decoded);
        
        if (!token.sdp || !token.ice) {
            throw new Error('Invalid token structure');
        }
        
        return token;
    } catch (error) {
        Logger.error(`Failed to parse signaling token: ${error.message}`);
        throw new Error('Invalid signaling token. Please check and try again.');
    }
}

// Wait for ICE gathering to complete (with timeout)
function waitForIceGathering() {
    return new Promise((resolve) => {
        const startTime = Date.now();
        const minWaitTime = 1000; // Wait at least 1 second for candidates
        
        const checkComplete = () => {
            const elapsed = Date.now() - startTime;
            const gatheringState = state.peerConnection?.iceGatheringState;
            const candidateCount = state.iceCandidates.length;
            
            console.log(`ICE check: state=${gatheringState}, candidates=${candidateCount}, elapsed=${elapsed}ms`);
            
            // Need at least 1 candidate AND either gathering complete OR enough time passed
            if (candidateCount > 0 && (gatheringState === 'complete' || elapsed >= minWaitTime)) {
                Logger.info(`ICE gathering finished with ${candidateCount} candidates`);
                resolve();
            } else if (elapsed >= CONFIG.iceGatheringTimeout) {
                Logger.warning(`ICE gathering timeout with ${candidateCount} candidates`);
                resolve();
            } else {
                setTimeout(checkComplete, 200);
            }
        };
        
        // Start checking after a short delay
        setTimeout(checkComplete, 200);
    });
}

// ============================================
// Call Flow: Create Call (Peer A / Initiator)
// DAY 2: Now includes hybrid key generation
// ============================================

async function createCall() {
    Logger.info('=== Starting Create Call Flow ===');
    state.isInitiator = true;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    // Reset crypto state
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    
    // Initialize media if not already done
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    // Create peer connection
    createPeerConnection();
    
    updateSecurityIndicator('connecting');
    setButtonStates('calling');
    
    try {
        // DAY 2: Generate hybrid key pair
        Logger.crypto('Generating hybrid key pair (X25519 + Kyber512)...');
        state.crypto.myKeys = await Crypto.generateHybridKeyPair();  // Add await
        Logger.crypto('Hybrid key pair generated successfully');
        
        // Create offer
        Logger.info('Creating SDP offer...');
        const offer = await state.peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true
        });
        
        // Set local description
        await state.peerConnection.setLocalDescription(offer);
        Logger.success('Local description set (offer)');
        
        // Debug: Check SDP for candidates
        const sdp = state.peerConnection.localDescription.sdp;
        const candidateLines = sdp.split('\n').filter(line => line.startsWith('a=candidate'));
        console.log('=== SDP Candidate Lines ===');
        console.log('Number of candidates in SDP:', candidateLines.length);
        candidateLines.forEach(line => console.log(line));
        console.log('===========================');
        
        // Wait for ICE gathering
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        // Get candidates from the local description itself (they're embedded in SDP)
        // Also include any separately collected candidates
        const localDesc = state.peerConnection.localDescription;
        
        // DAY 2: Create crypto data to include in token
        const cryptoData = {
            ecdhPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.ecdh.publicKey),
            kyberPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.kyber.publicKey)
        };
        Logger.crypto('Public keys encoded for transmission');
        
        // Create signaling token - use the final local description which contains ICE candidates
        const token = createSignalingToken(
            localDesc,
            state.iceCandidates,  // May be empty, but SDP has candidates
            cryptoData  // Include crypto data
        );
        
        // Display in modal
        elements.offerDisplay.value = token;
        elements.answerInput.value = '';
        openModal(elements.offerModal);
        
        Logger.success('Offer token generated with PQC key material - ready to share');
        
    } catch (error) {
        Logger.error(`Failed to create offer: ${error.message}`);
        console.error(error);
        hangUp();
    }
}

// ============================================
// Process Answer from Peer B (Initiator completes key exchange)
// DAY 2: Now performs initiator key agreement
// ============================================

async function processAnswer() {
    const answerToken = elements.answerInput.value.trim();
    
    if (!answerToken) {
        alert('Please paste the Answer token');
        return;
    }
    
    try {
        Logger.info('Processing Answer token...');
        const parsed = parseSignalingToken(answerToken);
        
        // Set remote description
        const answerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(answerDesc);
        Logger.success('Remote description set (answer)');
        
        // Add ICE candidates
        Logger.info(`Adding ${parsed.ice.length} remote ICE candidates...`);
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`Failed to add ICE candidate: ${e.message}`);
            }
        }
        
        // DAY 2 & 3: Perform initiator key agreement + SAS
        if (parsed.crypto && state.crypto.myKeys) {
            Logger.crypto('Performing initiator key agreement...');
            
            // Decode responder's crypto data
            const theirEcdhPk = CryptoUtils.fromBase64(parsed.crypto.ecdhPublicKey);
            const kyberCiphertext = CryptoUtils.fromBase64(parsed.crypto.kyberCiphertext);
            
            // Store for SAS generation
            state.crypto.theirEcdhPk = theirEcdhPk;
            state.crypto.kyberCiphertext = kyberCiphertext;
            
            // Perform key agreement
            const keyAgreementResult = await Crypto.initiatorKeyAgreement(
                state.crypto.myKeys.ecdh.privateKey,
                state.crypto.myKeys.kyber.secretKey,
                theirEcdhPk,
                kyberCiphertext
            );
            
            // Derive master secret
            state.crypto.masterSecret = await Crypto.deriveMasterSecret(
                keyAgreementResult.ecdhSecret,
                keyAgreementResult.kyberSecret
            );
            
            state.crypto.isKeyExchangeComplete = true;
            Logger.crypto('✅ Master secret derived successfully!');
            
            // DAY 3: Generate SAS
            // Order: masterSecret, initiatorEcdhPk, responderEcdhPk, initiatorKyberPk, kyberCiphertext
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                state.crypto.myKeys.ecdh.publicKey,  // initiator ECDH (me)
                theirEcdhPk,                          // responder ECDH (them)
                state.crypto.myKeys.kyber.publicKey, // initiator Kyber PK
                kyberCiphertext                       // Kyber ciphertext (shared)
            );
            
            Logger.crypto(`SAS generated: ${state.crypto.sas.base32} / ${state.crypto.sas.words}`);
            updateSecurityIndicator('unverified');
            showSASVerification();
            
        } else {
            Logger.warning('No crypto data in answer or missing local keys');
        }
        
        closeModal(elements.offerModal);
        Logger.success('Connection process complete - waiting for media');
        
    } catch (error) {
        Logger.error(`Failed to process answer: ${error.message}`);
        console.error(error);
        alert(error.message);
    }
}

// ============================================
// Call Flow: Join Call (Peer B / Responder)
// ============================================

async function joinCall() {
    Logger.info('=== Starting Join Call Flow ===');
    state.isInitiator = false;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    // Reset crypto state
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    
    // Initialize media if not already done
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    // Open join modal
    elements.offerInput.value = '';
    openModal(elements.joinModal);
}

// ============================================
// Process Offer (Responder performs key agreement)
// DAY 2: Now performs responder key agreement
// ============================================

async function processOffer() {
    const offerToken = elements.offerInput.value.trim();
    
    if (!offerToken) {
        alert('Please paste the Offer token');
        return;
    }
    
    try {
        Logger.info('Processing Offer token...');
        const parsed = parseSignalingToken(offerToken);
        
        // Create peer connection
        createPeerConnection();
        
        updateSecurityIndicator('connecting');
        setButtonStates('calling');
        
        // Set remote description
        const offerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(offerDesc);
        Logger.success('Remote description set (offer)');
        
        // Add ICE candidates from offer
        Logger.info(`Adding ${parsed.ice.length} remote ICE candidates...`);
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`Failed to add ICE candidate: ${e.message}`);
            }
        }
        
        // DAY 2 & 3: Perform responder key agreement + SAS
        let cryptoResponseData = null;
        
        if (parsed.crypto) {
            Logger.crypto('Performing responder key agreement...');
            
            // Decode initiator's public keys
            const theirEcdhPk = CryptoUtils.fromBase64(parsed.crypto.ecdhPublicKey);
            const theirKyberPk = CryptoUtils.fromBase64(parsed.crypto.kyberPublicKey);
            
            // Perform key agreement (generates our ECDH keys, encapsulates Kyber)
            const keyAgreementResult = await Crypto.responderKeyAgreement(theirEcdhPk, theirKyberPk);
            
            // Store for SAS generation
            state.crypto.myEcdhPk = keyAgreementResult.myEcdhPublicKey;
            state.crypto.theirEcdhPk = theirEcdhPk;
            state.crypto.theirKyberPk = theirKyberPk;
            state.crypto.kyberCiphertext = keyAgreementResult.kyberCiphertext;
            
            // Derive master secret
            state.crypto.masterSecret = await Crypto.deriveMasterSecret(
                keyAgreementResult.ecdhSecret,
                keyAgreementResult.kyberSecret
            );
            
            state.crypto.isKeyExchangeComplete = true;
            Logger.crypto('✅ Master secret derived successfully!');
            
            // DAY 3: Generate SAS
            // Order must match initiator: masterSecret, initiatorEcdhPk, responderEcdhPk, initiatorKyberPk, kyberCiphertext
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                theirEcdhPk,                              // initiator ECDH (them)
                keyAgreementResult.myEcdhPublicKey,       // responder ECDH (me)
                theirKyberPk,                             // initiator Kyber PK
                keyAgreementResult.kyberCiphertext        // Kyber ciphertext (shared)
            );
            
            Logger.crypto(`SAS generated: ${state.crypto.sas.base32} / ${state.crypto.sas.words}`);
            updateSecurityIndicator('unverified');
            showSASVerification();
            
            // Prepare crypto data for answer
            cryptoResponseData = {
                ecdhPublicKey: CryptoUtils.toBase64(keyAgreementResult.myEcdhPublicKey),
                kyberCiphertext: CryptoUtils.toBase64(keyAgreementResult.kyberCiphertext)
            };
            Logger.crypto('Crypto response data prepared for answer');
            
        } else {
            Logger.warning('No crypto data in offer - proceeding without PQC');
        }
        
        // Create answer
        Logger.info('Creating SDP answer...');
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);
        Logger.success('Local description set (answer)');
        
        // Wait for ICE gathering
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        // Create signaling token with crypto response
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates,
            cryptoResponseData  // Include crypto response
        );
        
        // Close join modal, open answer modal
        closeModal(elements.joinModal);
        elements.answerDisplay.value = token;
        openModal(elements.answerModal);
        
        Logger.success('Answer token generated with PQC key material - ready to share');
        
    } catch (error) {
        Logger.error(`Failed to process offer: ${error.message}`);
        console.error(error);
        alert(error.message);
        hangUp();
    }
}

// ============================================
// Call Teardown
// ============================================

function hangUp() {
    Logger.info('=== Hanging up call ===');
    
    // Close modals
    closeAllModals();
    
    // Close peer connection
    if (state.peerConnection) {
        state.peerConnection.close();
        state.peerConnection = null;
        Logger.info('Peer connection closed');
    }
    
    // Stop remote stream
    if (state.remoteStream) {
        state.remoteStream.getTracks().forEach(track => track.stop());
        state.remoteStream = null;
        elements.remoteVideo.srcObject = null;
    }
    
    // Stop local stream
    stopLocalMedia();
    
    // Reset state
    state.isInitiator = false;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    // DAY 2 & 3: Clear crypto state
    state.crypto.myKeys = null;
    state.crypto.theirEcdhPk = null;
    state.crypto.theirKyberPk = null;
    state.crypto.kyberCiphertext = null;
    state.crypto.myEcdhPk = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    // Reset UI
    updateSecurityIndicator('disconnected');
    updateConnectionStateDisplay('Not Connected');
    setButtonStates('initial');
    elements.remotePlaceholder.classList.remove('hidden');
    
    Logger.success('Call ended');
}

// ============================================
// Media Toggle Controls
// ============================================

function toggleVideo() {
    if (!state.localStream) return;
    
    const videoTrack = state.localStream.getVideoTracks()[0];
    if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        elements.toggleVideoBtn.textContent = videoTrack.enabled ? '📹 Video On' : '📹 Video Off';
        elements.toggleVideoBtn.classList.toggle('muted', !videoTrack.enabled);
        Logger.info(`Video ${videoTrack.enabled ? 'enabled' : 'disabled'}`);
    }
}

function toggleAudio() {
    if (!state.localStream) return;
    
    const audioTrack = state.localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        elements.toggleAudioBtn.textContent = audioTrack.enabled ? '🎤 Mic On' : '🎤 Mic Off';
        elements.toggleAudioBtn.classList.toggle('muted', !audioTrack.enabled);
        Logger.info(`Audio ${audioTrack.enabled ? 'enabled' : 'disabled'}`);
    }
}

// ============================================
// Clipboard Utilities
// ============================================

async function copyToClipboard(text, button) {
    try {
        await navigator.clipboard.writeText(text);
        
        const originalText = button.textContent;
        button.textContent = '✓ Copied!';
        button.classList.add('copy-success');
        
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copy-success');
        }, 2000);
        
        Logger.success('Token copied to clipboard');
    } catch (error) {
        Logger.error('Failed to copy to clipboard');
        // Fallback: select the text
        const textarea = button.previousElementSibling;
        if (textarea) {
            textarea.select();
            alert('Please copy the selected text manually (Ctrl+C)');
        }
    }
}

// ============================================
// DAY 3: SAS Verification UI
// ============================================

function showSASVerification() {
    if (!state.crypto.sas) {
        Logger.error('No SAS available to display');
        return;
    }
    
    // Mute remote media until verified
    muteUntilVerified();
    
    // Update SAS display with both formats
    const sasDisplay = elements.sasCode;
    sasDisplay.innerHTML = `
        <div class="sas-base32">${state.crypto.sas.base32}</div>
        <div class="sas-words">${state.crypto.sas.words}</div>
    `;
    
    // Show the modal
    Logger.info('Showing SAS verification modal');
    openModal(elements.sasModal);
}

function muteUntilVerified() {
    Logger.info('muteUntilVerified called - NOT actually muting for debug');
    // Keep it simple for now - we'll add muting back after it works
}

function unmuteAfterVerified() {
    Logger.success('unmuteAfterVerified called');
    
    if (elements.remoteVideo) {
        console.log('=== DEBUG: Unmute Attempt ===');
        console.log('Video element exists:', !!elements.remoteVideo);
        console.log('Has srcObject:', !!elements.remoteVideo.srcObject);
        console.log('Current muted state:', elements.remoteVideo.muted);
        console.log('============================');
        
        elements.remoteVideo.muted = false;
        elements.remoteVideo.style.filter = 'none';
        elements.remoteVideo.style.opacity = '1';
        
        // Try to play
        elements.remoteVideo.play().then(() => {
            Logger.success('Video play() succeeded');
        }).catch(err => {
            Logger.error('Video play() failed: ' + err.message);
        });
    } else {
        Logger.error('Remote video element not found!');
    }
}

// ============================================
// Event Listeners
// ============================================

function initializeEventListeners() {
    // Main controls
    elements.createCallBtn.addEventListener('click', createCall);
    elements.joinCallBtn.addEventListener('click', joinCall);
    elements.hangupBtn.addEventListener('click', hangUp);
    
    // Media controls
    elements.toggleVideoBtn.addEventListener('click', toggleVideo);
    elements.toggleAudioBtn.addEventListener('click', toggleAudio);
    
    // Offer modal
    elements.copyOfferBtn.addEventListener('click', () => {
        copyToClipboard(elements.offerDisplay.value, elements.copyOfferBtn);
    });
    elements.cancelOfferBtn.addEventListener('click', () => {
        closeModal(elements.offerModal);
        hangUp();
    });
    elements.connectBtn.addEventListener('click', processAnswer);
    
    // Join modal
    elements.processOfferBtn.addEventListener('click', processOffer);
    
    // Answer modal
    elements.copyAnswerBtn.addEventListener('click', () => {
        copyToClipboard(elements.answerDisplay.value, elements.copyAnswerBtn);
    });
    elements.answerDoneBtn.addEventListener('click', () => {
        closeModal(elements.answerModal);
    });
    
    // SAS modal
    elements.sasAccept.addEventListener('click', () => {
        Logger.success('SAS verification ACCEPTED by user');
        updateSecurityIndicator('verified');
        unmuteAfterVerified();  // Call unmute function
        closeModal(elements.sasModal);
    });
    
    elements.sasReject.addEventListener('click', () => {
        Logger.warning('SAS verification REJECTED by user');
        updateSecurityIndicator('disconnected');
        hangUp();
        closeModal(elements.sasModal);
    });
    
    // Debug controls
    elements.clearLogBtn.addEventListener('click', () => {
        elements.debugLog.innerHTML = '';
    });
    
    // Close modal buttons
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const modal = btn.closest('dialog');
            if (modal) closeModal(modal);
        });
    });
    
    // Close modal on backdrop click
    document.querySelectorAll('dialog').forEach(dialog => {
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) {
                closeModal(dialog);
            }
        });
    });
    
    // Handle page unload
    window.addEventListener('beforeunload', () => {
        if (state.peerConnection) {
            hangUp();
        }
    });
}

// ============================================
// Initialization
// ============================================

async function initialize() {
    Logger.info('=== AEGIS-VoIP Initializing ===');
    Logger.info(`Browser: ${navigator.userAgent}`);
    
    // Check WebRTC support
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        Logger.error('WebRTC is not supported in this browser');
        alert('Your browser does not support WebRTC. Please use Chrome, Firefox, or Edge.');
        return;
    }
    
    if (!window.RTCPeerConnection) {
        Logger.error('RTCPeerConnection is not available');
        alert('RTCPeerConnection is not supported in this browser.');
        return;
    }
    
    Logger.success('WebRTC support confirmed');
    
    // DAY 2: Initialize crypto libraries
    try {
        Logger.info('Initializing cryptographic libraries...');
        await Crypto.initialize();
        Logger.success('Crypto libraries initialized (libsodium + Kyber512)');
    } catch (error) {
        Logger.error(`Failed to initialize crypto: ${error.message}`);
        console.error(error);
        alert('Failed to initialize cryptographic libraries. Check console for details.');
        return;
    }
    
    // Initialize event listeners
    initializeEventListeners();
    Logger.success('Event listeners initialized');
    
    // Set initial UI state
    setButtonStates('initial');
    updateSecurityIndicator('disconnected');
    
    Logger.success('=== AEGIS-VoIP Ready (Day 2: Hybrid PQC Enabled) ===');
}

// Start the application
document.addEventListener('DOMContentLoaded', initialize);