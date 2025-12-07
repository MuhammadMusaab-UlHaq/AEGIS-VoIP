import { Crypto, CryptoUtils } from './crypto.js';

// Double encryption support
let encryptionWorker = null;

const hasModernInsertableStreams = typeof RTCRtpScriptTransform !== 'undefined';
const hasLegacyInsertableStreams = typeof RTCRtpSender !== 'undefined' && 
                                    typeof RTCRtpSender.prototype.createEncodedStreams !== 'undefined';
const supportsInsertableStreams = hasModernInsertableStreams || hasLegacyInsertableStreams;

function initializeEncryptionWorker() {
    if (!supportsInsertableStreams) {
        Logger.warning('Insertable Streams not supported - double encryption unavailable');
        return null;
    }
    
    try {
        encryptionWorker = new Worker('/src/worker.js', { name: 'AEGIS-E2EE-Worker' });
        Logger.success('Encryption worker initialized');
        return encryptionWorker;
    } catch (error) {
        Logger.error(`Failed to initialize encryption worker: ${error.message}`);
        return null;
    }
}

async function activateDoubleEncryption() {
    if (!encryptionWorker || !state.crypto.masterSecret) {
        Logger.warning('Cannot activate double encryption - missing worker or key');
        return false;
    }
    
    encryptionWorker.postMessage({
        operation: 'setKey',
        masterSecret: state.crypto.masterSecret,
        enabled: true
    });
    
    Logger.success('Double encryption ACTIVATED');
    return true;
}

function deactivateDoubleEncryption() {
    if (encryptionWorker) {
        encryptionWorker.postMessage({
            operation: 'setKey',
            masterSecret: null,
            enabled: true
        });
        Logger.info('Double encryption deactivated');
    }
}

// Configuration
const CONFIG = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
        { urls: 'stun:stun.relay.metered.ca:80' },
        { urls: 'stun:stun.miwifi.com:3478' },
        { urls: 'stun:stun.qq.com:3478' },
        { urls: 'stun:stun.twilio.com:3478' },
        { urls: 'stun:stun.xirsys.com' },
        { urls: 'stun:stun.nextcloud.com:3478' },
        { urls: 'stun:relay.webwormhole.io:3478' },
        { urls: 'stun:freeturn.net:3478' },
        { urls: 'stun:stun.sipgate.net:3478' },
        { urls: 'stun:stun.ekiga.net' }
    ],
    iceTransportPolicy: 'all',
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
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

// State
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
        sas: null,
        sasVerified: false
    }
};

// DOM Elements
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

// Logging
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
    crypto(msg) { this.log(`🔐 ${msg}`, 'info'); }
};

// UI helpers
function updateSecurityIndicator(status) {
    const indicator = elements.securityIndicator;
    const textSpan = indicator.querySelector('.indicator-text');
    
    indicator.classList.remove('disconnected', 'connecting', 'connected', 'unverified', 'verified', 'verified-e2ee');
    indicator.classList.add(status);
    
    const statusTexts = {
        'disconnected': 'Disconnected',
        'connecting': 'Connecting...',
        'connected': 'Connected',
        'unverified': 'Unverified',
        'verified': 'Verified ✓',
        'verified-e2ee': 'Verified + E2EE 🔒'
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

// Media
async function initializeLocalMedia() {
    try {
        Logger.info('Requesting camera and microphone access...');
        state.localStream = await navigator.mediaDevices.getUserMedia(CONFIG.mediaConstraints);
        elements.localVideo.srcObject = state.localStream;
        Logger.success('Local media initialized');
        return true;
    } catch (error) {
        Logger.error(`Failed to access media: ${error.message}`);
        alert('Could not access camera/microphone.');
        return false;
    }
}

function stopLocalMedia() {
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => track.stop());
        state.localStream = null;
        elements.localVideo.srcObject = null;
    }
}

// WebRTC
function createPeerConnection() {
    Logger.info('Creating RTCPeerConnection...');
    
    const config = {
        iceServers: CONFIG.iceServers,
        iceTransportPolicy: CONFIG.iceTransportPolicy,
        bundlePolicy: CONFIG.bundlePolicy,
        rtcpMuxPolicy: CONFIG.rtcpMuxPolicy,
        iceCandidatePoolSize: 10
    };
    
    if (hasLegacyInsertableStreams && !hasModernInsertableStreams) {
        config.encodedInsertableStreams = true;
        Logger.info('Using legacy encodedInsertableStreams');
    }
    
    const pc = new RTCPeerConnection(config);
    
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => {
            pc.addTrack(track, state.localStream);
        });
    }
    
    // Setup sender transforms for video only
    if (encryptionWorker && supportsInsertableStreams) {
        pc.getSenders().forEach(sender => {
            if (sender.track && sender.track.kind === 'video') {
                try {
                    if (hasModernInsertableStreams) {
                        sender.transform = new RTCRtpScriptTransform(encryptionWorker, { operation: 'encode' });
                        Logger.crypto('Sender transform ready (video)');
                    } else if (hasLegacyInsertableStreams) {
                        const streams = sender.createEncodedStreams();
                        encryptionWorker.postMessage({
                            operation: 'encode',
                            readable: streams.readable,
                            writable: streams.writable
                        }, [streams.readable, streams.writable]);
                        Logger.crypto('Sender transform ready (video, legacy)');
                    }
                } catch (error) {
                    Logger.error(`Sender transform failed: ${error.message}`);
                }
            }
        });
    }
    
    pc.onicecandidate = (event) => {
        if (event.candidate) {
            state.iceCandidates.push(event.candidate);
        } else {
            Logger.success(`ICE complete (${state.iceCandidates.length} candidates)`);
            state.iceGatheringComplete = true;
        }
    };
    
    pc.onicegatheringstatechange = () => {
        Logger.info(`ICE gathering: ${pc.iceGatheringState}`);
    };
    
    pc.oniceconnectionstatechange = () => {
        Logger.info(`ICE connection: ${pc.iceConnectionState}`);
        
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
        Logger.info(`Connection: ${pc.connectionState}`);
        if (pc.connectionState === 'failed') {
            hangUp();
        }
    };
    
    pc.ontrack = async (event) => {
        Logger.success(`Received remote ${event.track.kind} track`);
        
        if (!state.remoteStream) {
            state.remoteStream = new MediaStream();
            elements.remoteVideo.srcObject = state.remoteStream;
        }
        
        state.remoteStream.addTrack(event.track);
        elements.remotePlaceholder.classList.add('hidden');
        
        // Setup receiver transform for video only
        if (encryptionWorker && supportsInsertableStreams && event.track.kind === 'video') {
            try {
                if (hasModernInsertableStreams) {
                    event.receiver.transform = new RTCRtpScriptTransform(encryptionWorker, { operation: 'decode' });
                    Logger.crypto('Receiver transform ready (video)');
                } else if (hasLegacyInsertableStreams) {
                    const streams = event.receiver.createEncodedStreams();
                    encryptionWorker.postMessage({
                        operation: 'decode',
                        readable: streams.readable,
                        writable: streams.writable
                    }, [streams.readable, streams.writable]);
                    Logger.crypto('Receiver transform ready (video, legacy)');
                }
            } catch (error) {
                Logger.error(`Receiver transform failed: ${error.message}`);
            }
        }
    };
    
    pc.onnegotiationneeded = () => {
        Logger.info('Negotiation needed');
    };
    
    state.peerConnection = pc;
    return pc;
}

// Signaling
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
        Logger.error(`Failed to parse token: ${error.message}`);
        throw new Error('Invalid signaling token.');
    }
}

function waitForIceGathering() {
    return new Promise((resolve) => {
        const pc = state.peerConnection;
        const MIN_CANDIDATES = 2;
        const MIN_WAIT = 1500;
        const MAX_WAIT = 5000;
        
        const startTime = Date.now();
        
        const checkAndResolve = () => {
            const elapsed = Date.now() - startTime;
            const candidateCount = state.iceCandidates.length;
            
            if (candidateCount >= MIN_CANDIDATES && elapsed >= MIN_WAIT) {
                Logger.success(`ICE complete: ${candidateCount} candidates`);
                resolve();
            } else if (elapsed >= MAX_WAIT) {
                if (candidateCount === 0) {
                    Logger.error('No ICE candidates - check network/firewall');
                } else {
                    Logger.warning(`Only ${candidateCount} candidates after timeout`);
                }
                resolve();
            } else {
                setTimeout(checkAndResolve, 250);
            }
        };
        
        setTimeout(checkAndResolve, MIN_WAIT);
    });
}

// Create Call (Initiator)
async function createCall() {
    Logger.info('Starting Create Call...');
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
        Logger.crypto('Generating hybrid key pair...');
        state.crypto.myKeys = await Crypto.generateHybridKeyPair();
        
        const offer = await state.peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: true
        });
        
        await state.peerConnection.setLocalDescription(offer);
        Logger.success('Local description set');
        
        await waitForIceGathering();
        
        const cryptoData = {
            ecdhPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.ecdh.publicKey),
            kyberPublicKey: CryptoUtils.toBase64(state.crypto.myKeys.kyber.publicKey)
        };
        
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates,
            cryptoData
        );
        
        elements.offerDisplay.value = token;
        elements.answerInput.value = '';
        openModal(elements.offerModal);
        
        Logger.success('Offer ready');
        
    } catch (error) {
        Logger.error(`Create offer failed: ${error.message}`);
        hangUp();
    }
}

// Process Answer (Initiator)
async function processAnswer() {
    const answerToken = elements.answerInput.value.trim();
    if (!answerToken) {
        alert('Please paste the Answer token');
        return;
    }
    
    try {
        Logger.info('Processing Answer...');
        const parsed = parseSignalingToken(answerToken);
        
        const answerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(answerDesc);
        Logger.success('Remote description set');
        
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`ICE candidate failed: ${e.message}`);
            }
        }
        
        if (parsed.crypto && state.crypto.myKeys) {
            Logger.crypto('Initiator key agreement...');
            
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
            Logger.crypto('Master secret derived');
            
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                state.crypto.myKeys.ecdh.publicKey,
                theirEcdhPk,
                state.crypto.myKeys.kyber.publicKey,
                kyberCiphertext
            );
            
            Logger.crypto(`SAS: ${state.crypto.sas.base32} / ${state.crypto.sas.words}`);
            updateSecurityIndicator('unverified');
            showSASVerification();
        }
        
        closeModal(elements.offerModal);
        Logger.success('Connection process complete');
        
    } catch (error) {
        Logger.error(`Process answer failed: ${error.message}`);
        alert(error.message);
    }
}

// Join Call (Responder)
async function joinCall() {
    Logger.info('Starting Join Call...');
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

// Process Offer (Responder)
async function processOffer() {
    const offerToken = elements.offerInput.value.trim();
    if (!offerToken) {
        alert('Please paste the Offer token');
        return;
    }
    
    try {
        Logger.info('Processing Offer...');
        const parsed = parseSignalingToken(offerToken);
        
        createPeerConnection();
        updateSecurityIndicator('connecting');
        setButtonStates('calling');
        
        const offerDesc = new RTCSessionDescription(parsed.sdp);
        await state.peerConnection.setRemoteDescription(offerDesc);
        Logger.success('Remote description set');
        
        for (const candidate of parsed.ice) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                Logger.warning(`ICE candidate failed: ${e.message}`);
            }
        }
        
        let cryptoResponseData = null;
        
        if (parsed.crypto) {
            Logger.crypto('Responder key agreement...');
            
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
            Logger.crypto('Master secret derived');
            
            state.crypto.sas = await Crypto.generateSAS(
                state.crypto.masterSecret,
                theirEcdhPk,
                keyAgreementResult.myEcdhPublicKey,
                theirKyberPk,
                keyAgreementResult.kyberCiphertext
            );
            
            Logger.crypto(`SAS: ${state.crypto.sas.base32} / ${state.crypto.sas.words}`);
            updateSecurityIndicator('unverified');
            showSASVerification();
            
            cryptoResponseData = {
                ecdhPublicKey: CryptoUtils.toBase64(keyAgreementResult.myEcdhPublicKey),
                kyberCiphertext: CryptoUtils.toBase64(keyAgreementResult.kyberCiphertext)
            };
        }
        
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);
        Logger.success('Local description set');
        
        await waitForIceGathering();
        
        const token = createSignalingToken(
            state.peerConnection.localDescription,
            state.iceCandidates,
            cryptoResponseData
        );
        
        closeModal(elements.joinModal);
        elements.answerDisplay.value = token;
        openModal(elements.answerModal);
        
        Logger.success('Answer ready');
        
    } catch (error) {
        Logger.error(`Process offer failed: ${error.message}`);
        alert(error.message);
        hangUp();
    }
}

// Hang Up
function hangUp() {
    Logger.info('Hanging up...');
    
    closeAllModals();
    deactivateDoubleEncryption();
    
    if (state.peerConnection) {
        state.peerConnection.close();
        state.peerConnection = null;
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
    state.crypto.sasVerified = false;
    
    updateSecurityIndicator('disconnected');
    updateConnectionStateDisplay('Not Connected');
    setButtonStates('initial');
    elements.remotePlaceholder.classList.remove('hidden');
    
    Logger.success('Call ended');
}

// Media Controls
function toggleVideo() {
    if (!state.localStream) return;
    const videoTrack = state.localStream.getVideoTracks()[0];
    if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        elements.toggleVideoBtn.textContent = videoTrack.enabled ? '📹 Video On' : '📹 Video Off';
        elements.toggleVideoBtn.classList.toggle('muted', !videoTrack.enabled);
    }
}

function toggleAudio() {
    if (!state.localStream) return;
    const audioTrack = state.localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        elements.toggleAudioBtn.textContent = audioTrack.enabled ? '🎤 Mic On' : '🎤 Mic Off';
        elements.toggleAudioBtn.classList.toggle('muted', !audioTrack.enabled);
    }
}

// Clipboard
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
    } catch (error) {
        const textarea = button.previousElementSibling;
        if (textarea) {
            textarea.select();
            alert('Please copy manually (Ctrl+C)');
        }
    }
}

// SAS Verification
function showSASVerification() {
    if (!state.crypto.sas) {
        Logger.error('No SAS available');
        return;
    }
    
    elements.sasCode.innerHTML = `
        <div class="sas-base32">${state.crypto.sas.base32}</div>
        <div class="sas-words">${state.crypto.sas.words}</div>
    `;
    
    openModal(elements.sasModal);
}

// Event Listeners
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
    
    elements.sasAccept.addEventListener('click', async () => {
        Logger.success('SAS accepted');
        closeModal(elements.sasModal);
        updateSecurityIndicator('verified');

        const activated = await activateDoubleEncryption();
        if (activated) {
            updateSecurityIndicator('verified-e2ee');
        }
    });
    
    elements.sasReject.addEventListener('click', () => {
        Logger.error('SAS REJECTED - possible MITM!');
        closeModal(elements.sasModal);
        alert('⚠️ SECURITY WARNING ⚠️\n\nThe codes did not match!\nPossible MITM attack.\n\nTerminating call.');
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

// Initialize
async function initialize() {
    Logger.info('AEGIS-VoIP Initializing...');
    
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        Logger.error('WebRTC not supported');
        alert('Your browser does not support WebRTC.');
        return;
    }
    
    if (!window.RTCPeerConnection) {
        Logger.error('RTCPeerConnection not available');
        alert('RTCPeerConnection not supported.');
        return;
    }
    
    Logger.success('WebRTC supported');
    
    if (navigator.userAgent.includes('Chrome') && !navigator.userAgent.includes('Edg')) {
        const isPC = !/Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
        if (isPC) {
            Logger.warning('Chrome on PC may have issues - consider using Edge');
        }
    }
    
    try {
        await Crypto.initialize();
        Logger.success('Crypto libraries ready');
    } catch (error) {
        Logger.error(`Crypto init failed: ${error.message}`);
        alert('Failed to initialize crypto.');
        return;
    }
    
    initializeEncryptionWorker();
    if (hasModernInsertableStreams) {
        Logger.success('Double encryption: RTCRtpScriptTransform');
    } else if (hasLegacyInsertableStreams) {
        Logger.success('Double encryption: legacy API');
    } else {
        Logger.warning('Double encryption not available');
    }
    
    initializeEventListeners();
    setButtonStates('initial');
    updateSecurityIndicator('disconnected');
    
    Logger.success('AEGIS-VoIP Ready');
}

document.addEventListener('DOMContentLoaded', initialize);