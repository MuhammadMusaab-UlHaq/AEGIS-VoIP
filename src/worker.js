/**
 * AEGIS-VoIP - Encryption Worker (v2 - Codec Header Preservation)
 * Implements frame-level encryption while preserving VP8 headers to prevent video corruption.
 */
'use strict';

let encryptionKey = null;
let isEncryptionEnabled = false;

// Sender and receiver frame counts must be tracked separately
let sendFrameCount = 0;
let receiveFrameCount = 0;

// Constants for frame structure
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16; // AES-GCM uses a 128-bit (16-byte) auth tag

// ============================================
// Key Management
// ============================================

async function deriveEncryptionKey(masterSecret) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        masterSecret,
        { name: 'HKDF' },
        false,
        ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('AEGIS-VoIP-E2EE-v1-FrameKey'),
            info: new TextEncoder().encode('aes-gcm-256-key')
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, // Key is extractable for debugging if needed, but set to false for production
        ['encrypt', 'decrypt']
    );
}

// Generate a unique IV for each frame based on a counter
function generateIV(frameCount) {
    const iv = new Uint8Array(IV_LENGTH);
    const view = new DataView(iv.buffer);
    // Use a 64-bit counter which is safe from ever repeating
    view.setBigUint64(4, BigInt(frameCount));
    return iv;
}

// ============================================
// VP8 Codec Header Parsing
// (Needed to avoid encrypting critical frame metadata)
// ============================================

function getVp8HeaderLength(data) {
    const view = new DataView(data.buffer);
    // VP8 Payload Descriptor
    const payloadDescriptor = view.getUint8(0);
    
    // Check for extended control bits
    const extendedControlBitsPresent = (payloadDescriptor & 0x80) !== 0;
    if (!extendedControlBitsPresent) {
        return 1; // Basic header is just 1 byte
    }

    // Extended control bits are present
    let headerLength = 2;
    const extendedControlByte = view.getUint8(1);

    // Check for PictureID, TL0PICIDX, TID/KEYIDX
    if ((extendedControlByte & 0x80) !== 0) { // I bit
        headerLength += (view.getUint8(headerLength) & 0x80) ? 2 : 1;
    }
    if ((extendedControlByte & 0x40) !== 0) { // L bit
        headerLength++;
    }
    if ((extendedControlByte & 0x20) !== 0 || (extendedControlByte & 0x10) !== 0) { // T or K bit
        headerLength++;
    }
    return headerLength;
}

// ============================================
// Frame Encryption / Decryption Logic
// ============================================

async function encryptFrame(encodedFrame, controller) {
    if (!encryptionKey || !isEncryptionEnabled) {
        controller.enqueue(encodedFrame);
        return;
    }

    const frameData = new Uint8Array(encodedFrame.data);
    
    try {
        const headerLength = getVp8HeaderLength(frameData);
        const header = frameData.slice(0, headerLength);
        const payload = frameData.slice(headerLength);

        const iv = generateIV(sendFrameCount++);
        
        const encryptedPayload = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            encryptionKey,
            payload
        );
        
        // New frame structure: [Unencrypted Header][IV][Encrypted Payload + Auth Tag]
        const newFrameData = new Uint8Array(headerLength + IV_LENGTH + encryptedPayload.byteLength);
        newFrameData.set(header, 0);
        newFrameData.set(iv, headerLength);
        newFrameData.set(new Uint8Array(encryptedPayload), headerLength + IV_LENGTH);

        encodedFrame.data = newFrameData.buffer;
        controller.enqueue(encodedFrame);

    } catch (error) {
        console.error('[Worker] Encryption failed:', error);
        // Don't enqueue corrupted frames
    }
}

async function decryptFrame(encodedFrame, controller) {
    if (!encryptionKey || !isEncryptionEnabled) {
        controller.enqueue(encodedFrame);
        return;
    }

    const frameData = new Uint8Array(encodedFrame.data);
    
    try {
        const headerLength = getVp8HeaderLength(frameData);
        
        // Check if the frame is long enough to contain our encrypted structure
        if (frameData.length < headerLength + IV_LENGTH + AUTH_TAG_LENGTH) {
            // This might be an unencrypted frame or a different codec, pass it through
            controller.enqueue(encodedFrame);
            return;
        }

        const header = frameData.slice(0, headerLength);
        const iv = frameData.slice(headerLength, headerLength + IV_LENGTH);
        const encryptedPayload = frameData.slice(headerLength + IV_LENGTH);

        const decryptedPayload = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            encryptionKey,
            encryptedPayload
        );
        
        // Reconstruct original frame: [Header][Decrypted Payload]
        const originalFrameData = new Uint8Array(headerLength + decryptedPayload.byteLength);
        originalFrameData.set(header, 0);
        originalFrameData.set(new Uint8Array(decryptedPayload), headerLength);
        
        encodedFrame.data = originalFrameData.buffer;
        controller.enqueue(encodedFrame);

    } catch (error) {
        // Decryption can fail if the auth tag is invalid (tampering) or key is wrong.
        // It's safest to drop the frame.
        console.warn('[Worker] Decryption failed, dropping frame:', error.message);
    }
}

// ============================================
// Worker Setup
// ============================================

function handleTransform(operation, readable, writable) {
    const transformFn = operation === 'encode' ? encryptFrame : decryptFrame;
    
    const transformStream = new TransformStream({
        transform: transformFn
    });
    
    readable.pipeThrough(transformStream).pipeTo(writable);
}

self.onmessage = async (event) => {
    const { operation } = event.data;
    
    if (operation === 'setKey') {
        const { masterSecret, enabled } = event.data;
        if (masterSecret) {
            encryptionKey = await deriveEncryptionKey(masterSecret);
            isEncryptionEnabled = enabled;
            sendFrameCount = 0;
            receiveFrameCount = 0;
            console.log(`[Worker] E2EE Key derived. Encryption is now ${isEncryptionEnabled ? 'ENABLED' : 'DISABLED'}.`);
        } else {
            encryptionKey = null;
            isEncryptionEnabled = false;
        }
    } else if (operation === 'encode' || operation === 'decode') {
        if (event.data.readable && event.data.writable) {
            handleTransform(operation, event.data.readable, event.data.writable);
        }
    }
};

// For modern browsers supporting RTCRtpScriptTransform
if (self.RTCTransformEvent) {
    self.onrtctransform = (event) => {
        const transformer = event.transformer;
        handleTransform(transformer.options.operation, transformer.readable, transformer.writable);
    };
}

console.log('[Worker] v2 with VP8 header preservation is ready.');