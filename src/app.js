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
    iceGatheringTimeout: 5000,
    signalingServer: 'ws://localhost:8080'
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
    
    signaling: {
        ws: null,
        roomId: null,
        clientId: null,
        connected: false
    },
    
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
    
    roomModal: document.getElementById('room-modal'),
    roomIdDisplay: document.getElementById('room-id-display'),
    copyRoomIdBtn: document.getElementById('copy-room-id-btn'),
    cancelRoomBtn: document.getElementById('cancel-room-btn'),
    
    joinModal: document.getElementById('join-modal'),
    roomIdInput: document.getElementById('room-id-input'),
    joinRoomBtn: document.getElementById('join-room-btn'),
    
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
    [elements.roomModal, elements.joinModal, elements.sasModal].forEach(modal => {
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
// Signaling
// ============================================

function connectSignaling() {
    return new Promise((resolve, reject) => {
        Logger.info(`Connecting to signaling server: ${CONFIG.signalingServer}`);
        
        const ws = new WebSocket(CONFIG.signalingServer);
        
        ws.onopen = () => {
            Logger.success('Connected to signaling server');
            state.signaling.ws = ws;
            state.signaling.connected = true;
            resolve(ws);
        };
        
        ws.onerror = (error) => {
            Logger.error('Signaling connection error');
            reject(new Error('Failed to connect to signaling server'));
        };
        
        ws.onclose = () => {
            Logger.info('Signaling connection closed');
            state.signaling.connected = false;
            state.signaling.ws = null;
        };
        
        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                handleSignalingMessage(message);
            } catch (error) {
                Logger.error(`Failed to parse signaling message: ${error.message}`);
            }
        };
    });
}

function disconnectSignaling() {
    if (state.signaling.ws) {
        state.signaling.ws.close();
        state.signaling.ws = null;
        state.signaling.connected = false;
        state.signaling.roomId = null;
        state.signaling.clientId = null;
    }
}

function sendSignalingMessage(message) {
    if (state.signaling.ws && state.signaling.connected) {
        state.signaling.ws.send(JSON.stringify(message));
    } else {
        Logger.error('Cannot send message: signaling not connected');
    }
}

async function handleSignalingMessage(message) {
    Logger.info(`Signaling message: ${message.type}`);
    
    switch (message.type) {
        case 'room-created':
            state.signaling.roomId = message.roomId;
            state.signaling.clientId = message.clientId;
            Logger.success(`Room created: ${message.roomId}`);
            elements.roomIdDisplay.value = message.roomId;
            openModal(elements.roomModal);
            break;
            
        case 'room-joined':
            state.signaling.roomId = message.roomId;
            state.signaling.clientId = message.clientId;
            Logger.success(`Joined room: ${message.roomId}`);
            closeModal(elements.joinModal);
            updateSecurityIndicator('connecting');
            setButtonStates('calling');
            break;
            
        case 'peer-joined':
            Logger.success('Peer joined the room - sending offer');
            await sendOffer();
            break;
            
        case 'offer':
            Logger.info('Received offer from peer');
            await handleOffer(message);
            break;
            
        case 'answer':
            Logger.info('Received answer from peer');
            await handleAnswer(message);
            break;
            
        case 'ice-candidate':
            if (message.candidate) {
                try {
                    await state.peerConnection.addIceCandidate(new RTCIceCandidate(message.candidate));
                    Logger.info('Added remote ICE candidate');
                } catch (error) {
                    Logger.warning(`Failed to add ICE candidate: ${error.message}`);
                }
            }
            break;
            
        case 'peer-left':
            Logger.warning('Peer left the room');
            alert('The other peer has left the call.');
            hangUp();
            break;
            
        case 'error':
            Logger.error(`Signaling error: ${message.message}`);
            alert(`Error: ${message.message}`);
            hangUp();
            break;
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
            sendSignalingMessage({
                type: 'ice-candidate',
                candidate: event.candidate
            });
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
// Create Call (Initiator)
// ============================================

async function createCall() {
    Logger.info('=== Starting Create Call Flow ===');
    state.isInitiator = true;
    
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    try {
        await connectSignaling();
        
        Logger.crypto('Generating hybrid key pair (X25519 + Kyber)...');
        state.crypto.myKeys = await Crypto.generateHybridKeyPair();
        Logger.crypto('Hybrid key pair generated successfully');
        
        createPeerConnection();
        updateSecurityIndicator('connecting');
        setButtonStates('calling');
        
        sendSignalingMessage({ type: 'create-room' });
        Logger.info('Requesting room creation...');
        
    } catch (error) {
        Logger.error(`Failed to create call: ${error.message}`);
        console.error(error);
        alert('Failed to connect to signaling server. Please try again.');
        hangUp();
    }
}

async function sendOffer() {
    try {
        Logger.info('Creating SDP offer...');
        const offer = await state.peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true
        });
        
        await state.peerConnection.setLocalDescription(offer);
        Logger.success('Local description set (offer)');
        
        const cryptoData = {
            ecdhPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.ecdh.publicKey),
            kyberPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.kyber.publicKey)
        };
        Logger.crypto('Public keys encoded for transmission');
        
        sendSignalingMessage({
            type: 'offer',
            sdp: state.peerConnection.localDescription,
            crypto: cryptoData
        });
        
        Logger.success('Offer sent with PQC key material');
        closeModal(elements.roomModal);
        
    } catch (error) {
        Logger.error(`Failed to send offer: ${error.message}`);
        console.error(error);
        hangUp();
    }
}

// ============================================
// Handle Answer (Initiator)
// ============================================

async function handleAnswer(message) {
    try {
        const answerDesc = new RTCSessionDescription(message.sdp);
        await state.peerConnection.setRemoteDescription(answerDesc);
        Logger.success('Remote description set (answer)');
        
        if (message.crypto && state.crypto.myKeys) {
            Logger.crypto('Performing initiator key agreement...');
            
            const theirEcdhPk = CryptoUtils.fromBase64(message.crypto.ecdhPublicKey);
            const kyberCiphertext = CryptoUtils.fromBase64(message.crypto.kyberCiphertext);
            
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
        
        Logger.success('Answer processed - connection established');
        
    } catch (error) {
        Logger.error(`Failed to handle answer: ${error.message}`);
        console.error(error);
        hangUp();
    }
}

// ============================================
// Join Call (Responder)
// ============================================

async function joinCall() {
    Logger.info('=== Starting Join Call Flow ===');
    state.isInitiator = false;
    
    state.crypto.myKeys = null;
    state.crypto.masterSecret = null;
    state.crypto.isKeyExchangeComplete = false;
    state.crypto.sas = null;
    
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    elements.roomIdInput.value = '';
    openModal(elements.joinModal);
}

async function joinRoomById() {
    const roomId = elements.roomIdInput.value.trim().toUpperCase();
    if (!roomId) {
        alert('Please enter a Room ID');
        return;
    }
    
    try {
        await connectSignaling();
        sendSignalingMessage({
            type: 'join-room',
            roomId: roomId
        });
        Logger.info(`Attempting to join room: ${roomId}`);
    } catch (error) {
        Logger.error(`Failed to join room: ${error.message}`);
        alert('Failed to connect to signaling server. Please try again.');
    }
}

// ============================================
// Handle Offer (Responder)
// ============================================

async function handleOffer(message) {
    try {
        createPeerConnection();
        
        const offerDesc = new RTCSessionDescription(message.sdp);
        await state.peerConnection.setRemoteDescription(offerDesc);
        Logger.success('Remote description set (offer)');
        
        let cryptoResponseData = null;
        
        if (message.crypto) {
            Logger.crypto('Performing responder key agreement...');
            
            const theirEcdhPk = CryptoUtils.fromBase64(message.crypto.ecdhPublicKey);
            const theirKyberPk = CryptoUtils.fromBase64(message.crypto.kyberPublicKey);
            
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
        
        sendSignalingMessage({
            type: 'answer',
            sdp: state.peerConnection.localDescription,
            crypto: cryptoResponseData
        });
        
        Logger.success('Answer sent with PQC key material');
        
    } catch (error) {
        Logger.error(`Failed to handle offer: ${error.message}`);
        console.error(error);
        hangUp();
    }
}

// ============================================
// Hang Up
// ============================================

function hangUp() {
    Logger.info('=== Hanging up call ===');
    
    closeAllModals();
    
    if (state.signaling.connected) {
        sendSignalingMessage({ type: 'leave-room' });
        disconnectSignaling();
    }
    
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
    
    elements.copyRoomIdBtn.addEventListener('click', () => {
        copyToClipboard(elements.roomIdDisplay.value, elements.copyRoomIdBtn);
    });
    elements.cancelRoomBtn.addEventListener('click', () => {
        closeModal(elements.roomModal);
        hangUp();
    });
    
    elements.joinRoomBtn.addEventListener('click', joinRoomById);
    
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