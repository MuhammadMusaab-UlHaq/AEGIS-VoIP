// Frame-level AES-256-GCM encryption with VP8 header preservation
'use strict';

let encryptionKey = null;
let isEncryptionEnabled = false;
let sendFrameCount = 0;
let receiveFrameCount = 0;

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

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
        false,
        ['encrypt', 'decrypt']
    );
}

function generateIV(frameCount) {
    const iv = new Uint8Array(IV_LENGTH);
    const view = new DataView(iv.buffer);
    view.setBigUint64(4, BigInt(frameCount));
    return iv;
}

function getVp8HeaderLength(data) {
    const view = new DataView(data.buffer);
    const payloadDescriptor = view.getUint8(0);
    
    const extendedControlBitsPresent = (payloadDescriptor & 0x80) !== 0;
    if (!extendedControlBitsPresent) {
        return 1;
    }

    let headerLength = 2;
    const extendedControlByte = view.getUint8(1);

    if ((extendedControlByte & 0x80) !== 0) {
        headerLength += (view.getUint8(headerLength) & 0x80) ? 2 : 1;
    }
    if ((extendedControlByte & 0x40) !== 0) {
        headerLength++;
    }
    if ((extendedControlByte & 0x20) !== 0 || (extendedControlByte & 0x10) !== 0) {
        headerLength++;
    }
    return headerLength;
}

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
        
        // Frame structure: [Header][IV][Encrypted Payload + Auth Tag]
        const newFrameData = new Uint8Array(headerLength + IV_LENGTH + encryptedPayload.byteLength);
        newFrameData.set(header, 0);
        newFrameData.set(iv, headerLength);
        newFrameData.set(new Uint8Array(encryptedPayload), headerLength + IV_LENGTH);

        encodedFrame.data = newFrameData.buffer;
        controller.enqueue(encodedFrame);
    } catch (error) {
        console.error('[Worker] Encryption failed:', error);
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
        
        if (frameData.length < headerLength + IV_LENGTH + AUTH_TAG_LENGTH) {
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
        
        const originalFrameData = new Uint8Array(headerLength + decryptedPayload.byteLength);
        originalFrameData.set(header, 0);
        originalFrameData.set(new Uint8Array(decryptedPayload), headerLength);
        
        encodedFrame.data = originalFrameData.buffer;
        controller.enqueue(encodedFrame);
    } catch (error) {
        console.warn('[Worker] Decryption failed, dropping frame:', error.message);
    }
}

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
            console.log(`[Worker] E2EE ${isEncryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
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

if (self.RTCTransformEvent) {
    self.onrtctransform = (event) => {
        const transformer = event.transformer;
        handleTransform(transformer.options.operation, transformer.readable, transformer.writable);
    };
}

console.log('[Worker] Ready');