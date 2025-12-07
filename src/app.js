/**
 * AEGIS-VoIP - Post-Quantum Secure Communication
 * Day 3: SAS Verification Implementation
 */

import { Crypto, CryptoUtils } from './crypto.js';

// ============================================
// Configuration
// ============================================

const CONFIG = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
    ],
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
    
    crypto: {
        myKeys: null,
        theirEcdhPk: null,
        theirKyberPk: null,
        myEcdhPk: null,
        kyberCiphertext: null,
        masterSecret: null,
        isKeyExchangeComplete: false,
        sas: null
    }
};

// ============================================
// DOM Elements
// ============================================

const elements = {
    localVideo: document.getElementById('localVideo'),
    remoteVideo: document.getElementById('remoteVideo'),
    remotePlaceholder: document.getElementById('remote-placeholder'),
    
    createCallBtn: document.getElementById('createCallBtn'),
    joinCallBtn: document.getElementById('joinCallBtn'),
    hangupBtn: document.getElementById('hangupBtn'),
    toggleVideoBtn: document.getElementById('toggleVideoBtn'),
    toggleAudioBtn: document.getElementById('toggleAudioBtn'),
    
    securityIndicator: document.getElementById('security-indicator'),
    connectionState: document.getElementById('connection-state'),
    mediaControls: document.getElementById('media-controls'),
    
    offerModal: document.getElementById('offer-modal'),
    offerDisplay: document.getElementById('offer-display'),
    answerInput: document.getElementById('answer-input'),
    copyOfferBtn: document.getElementById('copy-offer-btn'),
    cancelOfferBtn: document.getElementById('cancel-offer-btn'),
    connectBtn: document.getElementById('connect-btn'),
    
    joinModal: document.getElementById('join-modal'),
    offerInput: document.getElementById('offer-input'),
    processOfferBtn: document.getElementById('process-offer-btn'),
    
    answerModal: document.getElementById('answer-modal'),
    answerDisplay: document.getElementById('answer-display'),
    copyAnswerBtn: document.getElementById('copy-answer-btn'),
    answerDoneBtn: document.getElementById('answer-done-btn'),
    
    sasModal: document.getElementById('sas-modal'),
    sasCode: document.getElementById('sas-code'),
    sasAccept: document.getElementById('sas-accept'),
    sasReject: document.getElementById('sas-reject'),
    
    debugLog: document.getElementById('debug-log'),
    clearLogBtn: document.getElementById('clearLogBtn')
};

// ============================================
// Logging
// ============================================

const Logger = {
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        console.log(`[${timestamp}] [${type.toUpperCase()}] ${message}`);
        
        if (elements.debugLog) {
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `<span class="log-time">${timestamp}</span><span class="log-${type}">${message}</span>`;
            elements.debugLog.appendChild(entry);
            elements.debugLog.scrollTop = elements.debugLog.scrollHeight;
        }
    },
    info(msg) { this.log(msg, 'info'); },
    success(msg) { this.log(msg, 'success'); },
    warning(msg) { this.log(msg, 'warning'); },
    error(msg) { this.log(msg, 'error'); },
    crypto(msg) { this.log(`🔐 ${msg}`, 'crypto'); }
};

// ============================================
// UI Management
// ============================================

function updateSecurityIndicator(status) {
    const indicator = elements.securityIndicator;
    const textSpan = indicator.querySelector('.indicator-text');
    
    indicator.classList.remove('disconnected', 'connecting', 'connected', 'unverified', 'verified');
    indicator.classList.add(status);
    
    const statusTexts = {
        'disconnected': 'Disconnected',
        'connecting': 'Connecting...',
        'connected': 'Connected',
        'unverified': 'Unverified',
        'verified': 'Verified ✓'
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

function openModal(modal) { modal.showModal(); }
function closeModal(modal) { modal.close(); }

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
        alert('Could not access camera/microphone.');
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
    
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => {
            pc.addTrack(track, state.localStream);
            Logger.info(`Added ${track.kind} track to peer connection`);
        });
    }
    
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            Logger.info(`ICE candidate gathered: ${event.candidate.candidate.substring(0, 50)}...`);
            state.iceCandidates.push(event.candidate);
        } else {
            Logger.success('ICE gathering complete');
            state.iceGatheringComplete = true;
        }
    };
    
    pc.oniceconnectionstatechange = () => {
        Logger.info(`ICE connection state: ${pc.iceConnectionState}`);
        
        switch (pc.iceConnectionState) {
            case 'connected':
            case 'completed':
                if (!state.crypto.isKeyExchangeComplete) {
                    updateSecurityIndicator('connected');
                }
                setButtonStates('connected');
                elements.remotePlaceholder.classList.add('hidden');
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
    
    pc.onconnectionstatechange = () => {
        Logger.info(`Connection state: ${pc.connectionState}`);
        if (pc.connectionState === 'failed') {
            Logger.error('Peer connection failed');
            hangUp();
        }
    };
    
    pc.ontrack = (event) => {
        Logger.success(`Received remote ${event.track.kind} track`);
        
        if (!state.remoteStream) {
            state.remoteStream = new MediaStream();
            elements.remoteVideo.srcObject = state.remoteStream;
        }
        
        state.remoteStream.addTrack(event.track);
        elements.remotePlaceholder.classList.add('hidden');
    };
    
    pc.onnegotiationneeded = () => {
        Logger.info('Negotiation needed');
    };
    
    state.peerConnection = pc;
    return pc;
}

// ============================================
// Signaling
// ============================================

function createSignalingToken(sdp, iceCandidates, cryptoData = null) {
    const token = {
        sdp: sdp,
        ice: iceCandidates,
        timestamp: Date.now(),
        version: '3.0',
        crypto: cryptoData
    };
    return btoa(JSON.stringify(token));
}

function parseSignalingToken(tokenString) {
    try {
        const decoded = atob(tokenString.trim());
        const token = JSON.parse(decoded);
        if (!token.sdp || !token.ice) throw new Error('Invalid token structure');
        return token;
    } catch (error) {
        Logger.error(`Failed to parse signaling token: ${error.message}`);
        throw new Error('Invalid signaling token.');
    }
}

function waitForIceGathering() {
    return new Promise((resolve) => {
        if (state.iceGatheringComplete) {
            resolve();
            return;
        }
        
        const checkInterval = setInterval(() => {
            if (state.iceGatheringComplete) {
                clearInterval(checkInterval);
                resolve();
            }
        }, 100);
        
        setTimeout(() => {
            clearInterval(checkInterval);
            Logger.warning('ICE gathering timeout - proceeding with available candidates');
            resolve();
        }, CONFIG.iceGatheringTimeout);
    });
}

// ============================================
// Create Call (Initiator)
// ============================================

async function createCall() {
    Logger.info('=== Starting Create Call Flow ===');
    state.isInitiator = true;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    createPeerConnection();
    updateSecurityIndicator('connecting');
    setButtonStates('calling');
    
    try {
        Logger.crypto('Generating hybrid key pair (X25519 + Kyber)...');
        state.crypto.myKeys = await Crypto.generateHybridKeyPair();
        Logger.crypto('Hybrid key pair generated successfully');
        
        Logger.info('Creating SDP offer...');
        const offer = await state.peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true
        });
        
        await state.peerConnection.setLocalDescription(offer);
        Logger.success('Local description set (offer)');
        
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        const cryptoData = {
            ecdhPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.ecdh.publicKey),
            kyberPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.kyber.publicKey)
        };
        Logger.crypto('Public keys encoded for transmission');
        
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates,
            cryptoData
        );
        
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
// Process Answer (Initiator)
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
        
        const answerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(answerDesc);
        Logger.success('Remote description set (answer)');
        
        Logger.info(`Adding ${parsed.ice.length} remote ICE candidates...`);
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`Failed to add ICE candidate: ${e.message}`);
            }
        }
        
        if (parsed.crypto && state.crypto.myKeys) {
            Logger.crypto('Performing initiator key agreement...');
            
            const theirEcdhPk = CryptoUtils.fromBase64(parsed.crypto.ecdhPublicKey);
            const kyberCiphertext = CryptoUtils.fromBase64(parsed.crypto.kyberCiphertext);
            
            state.crypto.theirEcdhPk = theirEcdhPk;
            state.crypto.kyberCiphertext = kyberCiphertext;
            
            const keyAgreementResult = await Crypto.initiatorKeyAgreement(
                state.crypto.myKeys.ecdh.privateKey,
                state.crypto.myKeys.kyber.secretKey,
                theirEcdhPk,
                kyberCiphertext
            );
            
            state.crypto.masterSecret = await Crypto.deriveMasterSecret(
                keyAgreementResult.ecdhSecret,
                keyAgreementResult.kyberSecret
            );
            
            state.crypto.isKeyExchangeComplete = true;
            Logger.crypto('✅ Master secret derived successfully!');
            
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                state.crypto.myKeys.ecdh.publicKey,
                theirEcdhPk,
                state.crypto.myKeys.kyber.publicKey,
                kyberCiphertext
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
// Join Call (Responder)
// ============================================

async function joinCall() {
    Logger.info('=== Starting Join Call Flow ===');
    state.isInitiator = false;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    elements.offerInput.value = '';
    openModal(elements.joinModal);
}

// ============================================
// Process Offer (Responder)
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
        
        createPeerConnection();
        updateSecurityIndicator('connecting');
        setButtonStates('calling');
        
        const offerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(offerDesc);
        Logger.success('Remote description set (offer)');
        
        Logger.info(`Adding ${parsed.ice.length} remote ICE candidates...`);
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`Failed to add ICE candidate: ${e.message}`);
            }
        }
        
        let cryptoResponseData = null;
        
        if (parsed.crypto) {
            Logger.crypto('Performing responder key agreement...');
            
            const theirEcdhPk = CryptoUtils.fromBase64(parsed.crypto.ecdhPublicKey);
            const theirKyberPk = CryptoUtils.fromBase64(parsed.crypto.kyberPublicKey);
            
            const keyAgreementResult = await Crypto.responderKeyAgreement(theirEcdhPk, theirKyberPk);
            
            state.crypto.myEcdhPk = keyAgreementResult.myEcdhPublicKey;
            state.crypto.theirEcdhPk = theirEcdhPk;
            state.crypto.theirKyberPk = theirKyberPk;
            state.crypto.kyberCiphertext = keyAgreementResult.kyberCiphertext;
            
            state.crypto.masterSecret = await Crypto.deriveMasterSecret(
                keyAgreementResult.ecdhSecret,
                keyAgreementResult.kyberSecret
            );
            
            state.crypto.isKeyExchangeComplete = true;
            Logger.crypto('✅ Master secret derived successfully!');
            
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                theirEcdhPk,
                keyAgreementResult.myEcdhPublicKey,
                theirKyberPk,
                keyAgreementResult.kyberCiphertext
            );
            
            Logger.crypto(`SAS generated: ${state.crypto.sas.base32} / ${state.crypto.sas.words}`);
            updateSecurityIndicator('unverified');
            showSASVerification();
            
            cryptoResponseData = {
                ecdhPublicKey: CryptoUtils.toBase64(keyAgreementResult.myEcdhPublicKey),
                kyberCiphertext: CryptoUtils.toBase64(keyAgreementResult.kyberCiphertext)
            };
            Logger.crypto('Crypto response data prepared for answer');
            
        } else {
            Logger.warning('No crypto data in offer - proceeding without PQC');
        }
        
        Logger.info('Creating SDP answer...');
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);
        Logger.success('Local description set (answer)');
        
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates,
            cryptoResponseData
        );
        
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
// Hang Up
// ============================================

function hangUp() {
    Logger.info('=== Hanging up call ===');
    
    closeAllModals();
    
    if (state.peerConnection) {
        state.peerConnection.close();
        state.peerConnection = null;
        Logger.info('Peer connection closed');
    }
    
    if (state.remoteStream) {
        state.remoteStream.getTracks().forEach(track => track.stop());
        state.remoteStream = null;
        elements.remoteVideo.srcObject = null;
    }
    
    stopLocalMedia();
    
    state.isInitiator = false;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
    state.crypto.myKeys = null;
    state.crypto.theirEcdhPk = null;
    state.crypto.theirKyberPk = null;
    state.crypto.kyberCiphertext = null;
    state.crypto.myEcdhPk = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    updateSecurityIndicator('disconnected');
    updateConnectionStateDisplay('Not Connected');
    setButtonStates('initial');
    elements.remotePlaceholder.classList.remove('hidden');
    
    Logger.success('Call ended');
}

// ============================================
// Media Controls
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
// Clipboard
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
        const textarea = button.previousElementSibling;
        if (textarea) {
            textarea.select();
            alert('Please copy the selected text manually (Ctrl+C)');
        }
    }
}

// ============================================
// SAS Verification
// ============================================

function showSASVerification() {
    if (!state.crypto.sas) {
        Logger.error('No SAS available to display');
        return;
    }
    
    const sasDisplay = elements.sasCode;
    sasDisplay.innerHTML = `
        <div class="sas-base32">${state.crypto.sas.base32}</div>
        <div class="sas-words">${state.crypto.sas.words}</div>
    `;
    
    Logger.info('Showing SAS verification modal');
    openModal(elements.sasModal);
}

// ============================================
// Event Listeners
// ============================================

function initializeEventListeners() {
    elements.createCallBtn.addEventListener('click', createCall);
    elements.joinCallBtn.addEventListener('click', joinCall);
    elements.hangupBtn.addEventListener('click', hangUp);
    
    elements.toggleVideoBtn.addEventListener('click', toggleVideo);
    elements.toggleAudioBtn.addEventListener('click', toggleAudio);
    
    elements.copyOfferBtn.addEventListener('click', () => {
        copyToClipboard(elements.offerDisplay.value, elements.copyOfferBtn);
    });
    elements.cancelOfferBtn.addEventListener('click', () => {
        closeModal(elements.offerModal);
        hangUp();
    });
    elements.connectBtn.addEventListener('click', processAnswer);
    
    elements.processOfferBtn.addEventListener('click', processOffer);
    
    elements.copyAnswerBtn.addEventListener('click', () => {
        copyToClipboard(elements.answerDisplay.value, elements.copyAnswerBtn);
    });
    elements.answerDoneBtn.addEventListener('click', () => {
        closeModal(elements.answerModal);
    });
    
    elements.sasAccept.addEventListener('click', () => {
        Logger.success('SAS verification ACCEPTED by user');
        updateSecurityIndicator('verified');
        closeModal(elements.sasModal);
    });
    
    elements.sasReject.addEventListener('click', () => {
        Logger.error('SAS verification REJECTED - possible MITM attack!');
        closeModal(elements.sasModal);
        alert('⚠️ SECURITY WARNING ⚠️\n\nThe security codes did not match!\nThis call may be intercepted by an attacker.\n\nThe call will now be terminated for your safety.');
        hangUp();
    });
    
    elements.clearLogBtn.addEventListener('click', () => {
        elements.debugLog.innerHTML = '';
    });
    
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const modal = btn.closest('dialog');
            if (modal) closeModal(modal);
        });
    });
    
    document.querySelectorAll('dialog').forEach(dialog => {
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) closeModal(dialog);
        });
    });
    
    window.addEventListener('beforeunload', () => {
        if (state.peerConnection) hangUp();
    });
}

// ============================================
// Initialization
// ============================================

async function initialize() {
    Logger.info('=== AEGIS-VoIP Initializing ===');
    Logger.info(`Browser: ${navigator.userAgent}`);
    
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        Logger.error('WebRTC is not supported in this browser');
        alert('Your browser does not support WebRTC.');
        return;
    }
    
    if (!window.RTCPeerConnection) {
        Logger.error('RTCPeerConnection is not available');
        alert('RTCPeerConnection is not supported.');
        return;
    }
    
    Logger.success('WebRTC support confirmed');
    
    try {
        Logger.info('Initializing cryptographic libraries...');
        await Crypto.initialize();
        Logger.success('Crypto libraries initialized (libsodium + Kyber)');
    } catch (error) {
        Logger.error(`Failed to initialize crypto: ${error.message}`);
        console.error(error);
        alert('Failed to initialize cryptographic libraries.');
        return;
    }
    
    initializeEventListeners();
    Logger.success('Event listeners initialized');
    
    setButtonStates('initial');
    updateSecurityIndicator('disconnected');
    
    Logger.success('=== AEGIS-VoIP Ready (Day 3: SAS Verification Enabled) ===');
}

document.addEventListener('DOMContentLoaded', initialize);