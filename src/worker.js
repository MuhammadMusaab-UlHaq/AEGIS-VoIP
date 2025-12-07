/**
 * AEGIS-VoIP - Encryption Worker (SIMPLIFIED - NO HEADER PRESERVATION)
 */

'use strict';

let encryptionKey = null;
let isEncryptionEnabled = false;
let frameCounter = 0;

// Constants
const IV_LENGTH = 12;
const MAGIC_BYTES = new Uint8Array([0xAE, 0x61, 0x53]);

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
            salt: new TextEncoder().encode('AEGIS-VoIP-E2EE-v1'),
            info: new TextEncoder().encode('frame-encryption-key')
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

function generateIV(counter) {
    const iv = new Uint8Array(IV_LENGTH);
    const view = new DataView(iv.buffer);
    view.setUint32(0, 0xAE615000);
    view.setBigUint64(4, BigInt(counter));
    return iv;
}

async function encryptFrame(encodedFrame, controller) {
    if (!encryptionKey || !isEncryptionEnabled) {
        controller.enqueue(encodedFrame);
        return;
    }

    try {
        const data = new Uint8Array(encodedFrame.data);
        
        // Skip tiny frames
        if (data.length < 10) {
            controller.enqueue(encodedFrame);
            return;
        }
        
        const iv = generateIV(frameCounter++);
        
        // Encrypt ENTIRE frame data - no header preservation
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            data
        );
        
        // Create new frame: [magic][iv][encrypted]
        const newData = new Uint8Array(MAGIC_BYTES.length + IV_LENGTH + encrypted.byteLength);
        newData.set(MAGIC_BYTES, 0);
        newData.set(iv, MAGIC_BYTES.length);
        newData.set(new Uint8Array(encrypted), MAGIC_BYTES.length + IV_LENGTH);
        
        encodedFrame.data = newData.buffer;
    } catch (error) {
        console.error('[Worker] Encrypt error:', error);
    }
    
    controller.enqueue(encodedFrame);
}

async function decryptFrame(encodedFrame, controller) {
    if (!encryptionKey || !isEncryptionEnabled) {
        controller.enqueue(encodedFrame);
        return;
    }

    try {
        const data = new Uint8Array(encodedFrame.data);
        
        // Check for magic bytes
        if (data.length < MAGIC_BYTES.length + IV_LENGTH + 16) {
            controller.enqueue(encodedFrame);
            return;
        }
        
        let hasMagic = true;
        for (let i = 0; i < MAGIC_BYTES.length; i++) {
            if (data[i] !== MAGIC_BYTES[i]) {
                hasMagic = false;
                break;
            }
        }
        
        if (!hasMagic) {
            controller.enqueue(encodedFrame);
            return;
        }
        
        const iv = data.slice(MAGIC_BYTES.length, MAGIC_BYTES.length + IV_LENGTH);
        const encrypted = data.slice(MAGIC_BYTES.length + IV_LENGTH);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            encrypted
        );
        
        encodedFrame.data = decrypted;
        controller.enqueue(encodedFrame);
    } catch (error) {
        console.error('[Worker] Decrypt error:', error);
        // Drop corrupted frame
    }
}

function handleTransform(operation, readable, writable) {
    const transform = operation === 'encode' ? encryptFrame : decryptFrame;
    
    const transformStream = new TransformStream({
        transform: transform
    });
    
    readable.pipeThrough(transformStream).pipeTo(writable);
}

self.onmessage = async (event) => {
    const { operation } = event.data;
    
    if (operation === 'setKey') {
        const { masterSecret, enabled } = event.data;
        if (masterSecret) {
            encryptionKey = await deriveEncryptionKey(masterSecret);
            isEncryptionEnabled = enabled !== false;
            frameCounter = 0;
            console.log('[Worker] Encryption', isEncryptionEnabled ? 'enabled' : 'disabled');
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

console.log('[Worker] Ready (simplified version)');