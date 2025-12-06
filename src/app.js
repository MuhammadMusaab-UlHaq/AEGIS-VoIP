/**
 * AEGIS-VoIP - Post-Quantum Secure Communication
 * Day 1: Foundational WebRTC Video Call with Manual Signaling
 * 
 * This module implements a peer-to-peer video call using WebRTC
 * with manual signaling (copy/paste of offer/answer tokens).
 */

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
        { urls: 'stun:stun4.l.google.com:19302' }
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
    iceGatheringTimeout: 3000
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
    iceGatheringComplete: false
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
    error(msg) { this.log(msg, 'error'); }
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
        if (modal.open) modal.close();
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
    
    // Handle ICE connection state changes
    pc.oniceconnectionstatechange = () => {
        Logger.info(`ICE connection state: ${pc.iceConnectionState}`);
        updateConnectionStateDisplay(`ICE: ${pc.iceConnectionState}`);
        
        switch (pc.iceConnectionState) {
            case 'connected':
            case 'completed':
                updateSecurityIndicator('connected');
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
    
    // Handle connection state changes
    pc.onconnectionstatechange = () => {
        Logger.info(`Connection state: ${pc.connectionState}`);
        
        if (pc.connectionState === 'failed') {
            Logger.error('Peer connection failed');
            hangUp();
        }
    };
    
    // Handle incoming tracks
    pc.ontrack = (event) => {
        Logger.success(`Received remote ${event.track.kind} track`);
        
        if (!state.remoteStream) {
            state.remoteStream = new MediaStream();
            elements.remoteVideo.srcObject = state.remoteStream;
        }
        
        state.remoteStream.addTrack(event.track);
        elements.remotePlaceholder.classList.add('hidden');
    };
    
    // Handle negotiation needed (for future use)
    pc.onnegotiationneeded = () => {
        Logger.info('Negotiation needed');
    };
    
    state.peerConnection = pc;
    return pc;
}

// ============================================
// Signaling Token Helpers
// ============================================

function createSignalingToken(sdp, iceCandidates) {
    const token = {
        sdp: sdp,
        ice: iceCandidates,
        timestamp: Date.now(),
        version: '1.0'
    };
    return btoa(JSON.stringify(token));
}

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
        
        // Timeout fallback
        setTimeout(() => {
            clearInterval(checkInterval);
            Logger.warning('ICE gathering timeout - proceeding with available candidates');
            resolve();
        }, CONFIG.iceGatheringTimeout);
    });
}

// ============================================
// Call Flow: Create Call (Peer A / Initiator)
// ============================================

async function createCall() {
    Logger.info('=== Starting Create Call Flow ===');
    state.isInitiator = true;
    state.iceCandidates = [];
    state.iceGatheringComplete = false;
    
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
        // Create offer
        Logger.info('Creating SDP offer...');
        const offer = await state.peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true
        });
        
        // Set local description
        await state.peerConnection.setLocalDescription(offer);
        Logger.success('Local description set (offer)');
        
        // Wait for ICE gathering
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        // Create signaling token
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates
        );
        
        // Display in modal
        elements.offerDisplay.value = token;
        elements.answerInput.value = '';
        openModal(elements.offerModal);
        
        Logger.success('Offer token generated - ready to share');
        
    } catch (error) {
        Logger.error(`Failed to create offer: ${error.message}`);
        hangUp();
    }
}

// Process answer from Peer B
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
        
        closeModal(elements.offerModal);
        Logger.success('Connection process complete - waiting for media');
        
    } catch (error) {
        Logger.error(`Failed to process answer: ${error.message}`);
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
    
    // Initialize media if not already done
    if (!state.localStream) {
        const success = await initializeLocalMedia();
        if (!success) return;
    }
    
    // Open join modal
    elements.offerInput.value = '';
    openModal(elements.joinModal);
}

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
        
        // Create answer
        Logger.info('Creating SDP answer...');
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);
        Logger.success('Local description set (answer)');
        
        // Wait for ICE gathering
        Logger.info('Gathering ICE candidates...');
        await waitForIceGathering();
        
        // Create signaling token
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates
        );
        
        // Close join modal, open answer modal
        closeModal(elements.joinModal);
        elements.answerDisplay.value = token;
        openModal(elements.answerModal);
        
        Logger.success('Answer token generated - ready to share');
        
    } catch (error) {
        Logger.error(`Failed to process offer: ${error.message}`);
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
    
    // SAS modal (placeholder for Day 3)
    elements.sasAccept.addEventListener('click', () => {
        updateSecurityIndicator('verified');
        closeModal(elements.sasModal);
        Logger.success('SAS verification accepted');
    });
    elements.sasReject.addEventListener('click', () => {
        closeModal(elements.sasModal);
        Logger.error('SAS verification rejected - possible MITM attack');
        alert('Connection terminated due to security mismatch. Possible MITM attack.');
        hangUp();
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
    
    // Initialize event listeners
    initializeEventListeners();
    Logger.success('Event listeners initialized');
    
    // Set initial UI state
    setButtonStates('initial');
    updateSecurityIndicator('disconnected');
    
    Logger.success('=== AEGIS-VoIP Ready ===');
}

// Start the application
document.addEventListener('DOMContentLoaded', initialize);
