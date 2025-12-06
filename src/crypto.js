/**
 * AEGIS-VoIP - Crypto Module
 * Implements Hybrid Post-Quantum Key Exchange: X25519 (ECDH) + Kyber512 (PQC KEM)
 */

import _sodium from 'libsodium-wrappers';
import { kyber } from 'kyber-crystals';

// ============================================
// Utility Functions
// ============================================

const CryptoUtils = {
    /**
     * Convert Uint8Array to Base64 string
     */
    toBase64(bytes) {
        if (!(bytes instanceof Uint8Array)) {
            bytes = new Uint8Array(bytes);
        }
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    /**
     * Convert Base64 string to Uint8Array
     */
    fromBase64(str) {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    /**
     * Convert Uint8Array to Hex string (for debugging)
     */
    toHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Compare two Uint8Arrays for equality
     */
    constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }
};

// ============================================
// Crypto Module State
// ============================================

let cryptoInitialized = false;
let sodium = null;
let Kyber = null;

// ============================================
// Initialization
// ============================================

/**
 * Initialize cryptographic libraries
 * Must be called before any other crypto operations
 */
async function initializeCrypto() {
    if (cryptoInitialized) {
        console.log('[Crypto] Already initialized');
        return true;
    }

    try {
        // Initialize libsodium
        await _sodium.ready;
        sodium = _sodium;
        console.log('[Crypto] libsodium initialized');

        // Kyber is already ready (using Kyber-1024 by default)
        Kyber = kyber;
        console.log('[Crypto] Kyber initialized (using Kyber-1024)');

        cryptoInitialized = true;
        console.log('[Crypto] All crypto libraries initialized successfully');
        return true;

    } catch (error) {
        console.error('[Crypto] Initialization failed:', error);
        throw error;
    }
}

// ============================================
// X25519 (ECDH) Operations
// ============================================

/**
 * Generate X25519 key pair for ECDH
 */
function generateECDHKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const keyPair = sodium.crypto_box_keypair();
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
    };
}

/**
 * Perform X25519 ECDH to compute shared secret
 */
function computeECDHSecret(myPrivateKey, theirPublicKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    // crypto_scalarmult computes the shared secret
    return sodium.crypto_scalarmult(myPrivateKey, theirPublicKey);
}

// ============================================
// Kyber (PQC KEM) Operations
// ============================================

/**
 * Generate Kyber key pair
 * Returns { publicKey, secretKey }
 */
async function generateKyberKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const keyPair = await Kyber.keyPair();
    return {
        publicKey: new Uint8Array(keyPair.publicKey),
        secretKey: new Uint8Array(keyPair.privateKey)  // Note: it's privateKey, not secretKey
    };
}

/**
 * Kyber Encapsulation - generates shared secret and ciphertext
 * Used by the responder (Peer B)
 */
async function kyberEncapsulate(theirPublicKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const result = await Kyber.encrypt(theirPublicKey);
    return {
        ciphertext: new Uint8Array(result.cyphertext),  // Note: it's cyphertext with 'y'
        sharedSecret: new Uint8Array(result.secret)     // Note: it's secret, not sharedSecret
    };
}

/**
 * Kyber Decapsulation - recovers shared secret from ciphertext
 * Used by the initiator (Peer A)
 */
async function kyberDecapsulate(ciphertext, mySecretKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const sharedSecret = await Kyber.decrypt(ciphertext, mySecretKey);
    return new Uint8Array(sharedSecret);
}

// ============================================
// Hybrid Key Exchange
// ============================================

/**
 * Generate hybrid key pair (X25519 + Kyber)
 * Used when creating a call (Peer A)
 */
async function generateHybridKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const ecdhKeys = generateECDHKeyPair();
    const kyberKeys = await generateKyberKeyPair();  // Add await
    
    console.log('[Crypto] Generated hybrid key pair');
    console.log('[Crypto] ECDH Public Key length:', ecdhKeys.publicKey.length);
    console.log('[Crypto] Kyber Public Key length:', kyberKeys.publicKey.length);
    
    return {
        ecdh: ecdhKeys,
        kyber: kyberKeys
    };
}

/**
 * Responder's key agreement (Peer B - joining a call)
 * Takes initiator's public keys, performs key exchange, returns response data
 */
async function responderKeyAgreement(theirEcdhPk, theirKyberPk) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    console.log('[Crypto] Responder performing key agreement...');
    
    // 1. Generate our own ephemeral ECDH key pair
    const myEcdhKeys = generateECDHKeyPair();
    
    // 2. Compute ECDH shared secret
    const ecdhSecret = computeECDHSecret(myEcdhKeys.privateKey, theirEcdhPk);
    console.log('[Crypto] ECDH secret computed, length:', ecdhSecret.length);
    
    // 3. Perform Kyber encapsulation on their public key
    const kyberResult = await kyberEncapsulate(theirKyberPk);  // Add await
    console.log('[Crypto] Kyber encapsulation done');
    console.log('[Crypto] Kyber ciphertext length:', kyberResult.ciphertext.length);
    console.log('[Crypto] Kyber shared secret length:', kyberResult.sharedSecret.length);
    
    return {
        // Our ECDH public key to send back
        myEcdhPublicKey: myEcdhKeys.publicKey,
        // Kyber ciphertext to send back
        kyberCiphertext: kyberResult.ciphertext,
        // Secrets (not sent, used locally)
        ecdhSecret: ecdhSecret,
        kyberSecret: kyberResult.sharedSecret
    };
}

/**
 * Initiator's key agreement (Peer A - after receiving answer)
 * Takes responder's data, completes key exchange
 */
async function initiatorKeyAgreement(myEcdhPrivateKey, myKyberSecretKey, theirEcdhPk, kyberCiphertext) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    console.log('[Crypto] Initiator performing key agreement...');
    
    // 1. Compute ECDH shared secret
    const ecdhSecret = computeECDHSecret(myEcdhPrivateKey, theirEcdhPk);
    console.log('[Crypto] ECDH secret computed, length:', ecdhSecret.length);
    
    // 2. Perform Kyber decapsulation to recover shared secret
    const kyberSecret = await kyberDecapsulate(kyberCiphertext, myKyberSecretKey);  // Add await
    console.log('[Crypto] Kyber decapsulation done, secret length:', kyberSecret.length);
    
    return {
        ecdhSecret: ecdhSecret,
        kyberSecret: kyberSecret
    };
}

// ============================================
// Key Derivation Function (HKDF)
// ============================================

/**
 * HKDF-Extract: Extracts a pseudorandom key from input keying material
 */
async function hkdfExtract(salt, ikm) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        salt.length > 0 ? salt : new Uint8Array(32), // Use zero-filled salt if empty
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const prk = await crypto.subtle.sign('HMAC', keyMaterial, ikm);
    return new Uint8Array(prk);
}

/**
 * HKDF-Expand: Expands the PRK into output keying material
 */
async function hkdfExpand(prk, info, length) {
    const prkKey = await crypto.subtle.importKey(
        'raw',
        prk,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const n = Math.ceil(length / 32);
    const okm = new Uint8Array(n * 32);
    let prev = new Uint8Array(0);
    
    for (let i = 0; i < n; i++) {
        const input = new Uint8Array(prev.length + info.length + 1);
        input.set(prev);
        input.set(info, prev.length);
        input[input.length - 1] = i + 1;
        
        const block = await crypto.subtle.sign('HMAC', prkKey, input);
        prev = new Uint8Array(block);
        okm.set(prev, i * 32);
    }
    
    return okm.slice(0, length);
}

/**
 * Derive master shared secret from ECDH and Kyber secrets
 * Uses HKDF to combine both secrets securely
 */
async function deriveMasterSecret(ecdhSecret, kyberSecret) {
    console.log('[Crypto] Deriving master secret...');
    
    // Concatenate both secrets as IKM (Input Keying Material)
    const ikm = new Uint8Array(ecdhSecret.length + kyberSecret.length);
    ikm.set(ecdhSecret, 0);
    ikm.set(kyberSecret, ecdhSecret.length);
    
    // Context info for domain separation
    const info = new TextEncoder().encode('AEGIS-VoIP-v1-Master-Secret');
    
    // Extract phase (using empty salt - could be improved with a protocol-specific salt)
    const prk = await hkdfExtract(new Uint8Array(0), ikm);
    
    // Expand phase - derive 32 bytes for the master secret
    const masterSecret = await hkdfExpand(prk, info, 32);
    
    console.log('[Crypto] Master secret derived, length:', masterSecret.length);
    console.log('[Crypto] Master secret (hex):', CryptoUtils.toHex(masterSecret));
    
    return masterSecret;
}

// ============================================
// DAY 3: Short Authentication String (SAS)
// ============================================

// RFC 4648 Base32 alphabet
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// PGP Word List (256 even words, 256 odd words)
// Even words (2 syllables) - used for even byte positions
const PGP_WORDS_EVEN = [
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
    "aimless", "Algol", "allow", "almost", "ammo", "ancient", "apple", "artist",
    "assume", "Athens", "atlas", "Aztec", "baboon", "backfield", "backward", "banjo",
    "beaming", "bedlamp", "beehive", "beeswax", "befriend", "Belfast", "berserk", "billiard",
    "bison", "blackjack", "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
    "breadline", "breakup", "brickyard", "briefcase", "Burbank", "button", "buzzard", "cement",
    "chairlift", "chatter", "checkup", "chisel", "choking", "chopper", "Christmas", "clamshell",
    "classic", "classroom", "cleanup", "clockwork", "cobra", "commence", "concert", "cowbell",
    "crackdown", "cranky", "crowfoot", "crucial", "crumpled", "crusade", "cubic", "dashboard",
    "deadbolt", "deckhand", "dogsled", "dragnet", "drainage", "dreadful", "drifter", "dromedary",
    "drumbeat", "drunken", "Dupont", "dwelling", "eating", "edict", "egghead", "eightball",
    "endorse", "endow", "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth",
    "facial", "fallout", "flagpole", "flatfoot", "flytrap", "fracture", "framework", "freedom",
    "frighten", "gazelle", "Geiger", "glitter", "glucose", "goggles", "goldfish", "gremlin",
    "guidance", "hamlet", "highchair", "hockey", "indoors", "indulge", "inverse", "involve",
    "island", "jawbone", "keyboard", "kickoff", "kiwi", "klaxon", "locale", "lockup",
    "merit", "minnow", "miser", "Mohawk", "mural", "music", "necklace", "Neptune",
    "newborn", "nightbird", "Oakland", "obtuse", "offload", "optic", "orca", "payday",
    "peachy", "pheasant", "physique", "playhouse", "Pluto", "preclude", "prefer", "preshrunk",
    "printer", "prowler", "pupil", "puppy", "python", "quadrant", "quiver", "quota",
    "ragtime", "ratchet", "rebirth", "reform", "regain", "reindeer", "rematch", "repay",
    "retouch", "revenge", "reward", "rhythm", "ribcage", "ringbolt", "robust", "rocker",
    "ruffled", "sailboat", "sawdust", "scallion", "scenic", "scorecard", "Scotland", "seabird",
    "select", "sentence", "shadow", "shamrock", "showgirl", "skullcap", "skydive", "slingshot",
    "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "southward", "soybean",
    "spaniel", "spearhead", "spellbound", "spheroid", "spigot", "spindle", "spyglass", "stagehand",
    "stagnate", "stairway", "standard", "stapler", "steamship", "sterling", "stockman", "stopwatch",
    "stormy", "stranger", "streamline", "striking", "stubborn", "stupendous", "Stuttgart", "subway",
    "surmount", "suspense", "sweatband", "swelter", "tactics", "talon", "tapeworm", "tempest",
    "tiger", "tissue", "tonic", "topmost", "tracker", "transit", "trauma", "treadmill",
    "Trojan", "trouble", "tumor", "tunnel", "tycoon", "uncut", "unearth", "unwind",
    "uproot", "upset", "upshot", "vapor", "village", "virus", "Vulcan", "waffle",
    "wallet", "watchword", "wayside", "willow", "woodlark", "Zulu"
];

// Odd words (3 syllables) - used for odd byte positions  
const PGP_WORDS_ODD = [
    "adroitness", "adviser", "aftermath", "aggregate", "alkali", "almighty", "amulet", "amusement",
    "antenna", "applicant", "Apollo", "armistice", "article", "asteroid", "Atlantic", "atmosphere",
    "autopsy", "Babylon", "backwater", "barbecue", "belowground", "bifocals", "bodyguard", "bookseller",
    "borderline", "bottomless", "Bradbury", "bravado", "Brazilian", "breakaway", "Burlington", "businessman",
    "butterfat", "Camelot", "candidate", "cannonball", "Capricorn", "caravan", "caretaker", "celebrate",
    "cellulose", "certify", "chambermaid", "Cherokee", "Chicago", "clergyman", "coherence", "combustion",
    "commando", "company", "component", "concurrent", "confidence", "conformist", "congregate", "consensus",
    "consulting", "corporate", "corrosion", "councilman", "crossover", "crucifix", "cumbersome", "customer",
    "Dakota", "decadence", "December", "decimal", "designing", "detector", "detergent", "determine",
    "dictator", "dinosaur", "direction", "disbelief", "disruptive", "distortion", "document", "embezzle",
    "embroider", "emerald", "emission", "emphasize", "employer", "endeavor", "envelope", "escapade",
    "Ede", "everyday", "examine", "existence", "exodus", "fascinate", "filament", "finicky",
    "forever", "fortitude", "frequency", "gadgetry", "Galveston", "getaway", "glossary", "gossamer",
    "graduate", "gravity", "guitarist", "hamburger", "Hamilton", "handiwork", "hazardous", "headwaters",
    "hemisphere", "hesitate", "hideaway", "holiness", "hurricane", "hydraulic", "impartial", "impetus",
    "inception", "indigo", "inertia", "infancy", "inferno", "informant", "insincere", "insurgent",
    "integrate", "intention", "inventive", "Istanbul", "Jamaica", "judiciary", "Junction", "Kentucky",
    "kindergarten", "leadership", "legacy", "liberation", "liability", "likelihood", "literature", "livelihood",
    "longitude", "Louisiana", "lucrative", "lymphoma", "magazine", "malady", "manageable", "mandate",
    "Manitoba", "marathon", "medusa", "megaton", "microscope", "microwave", "midsummer", "millionaire",
    "miracle", "misnomer", "molasses", "molecule", "Montana", "monument", "mosquito", "narrative",
    "nebula", "newsletter", "Norwegian", "October", "Ohio", "onlooker", "opulent", "Orlando",
    "outfielder", "Pacific", "pandemic", "Pandora", "paperweight", "paragon", "paragraph", "paramount",
    "passenger", "pedigree", "Pegasus", "penetrate", "perceptive", "performance", "pharmacy", "phonetic",
    "photograph", "pioneer", "pocketful", "politeness", "positive", "potato", "processor", "provincial",
    "proximate", "puberty", "publisher", "pyramid", "quantity", "racketeer", "rebellion", "recipe",
    "recover", "redirect", "repellent", "replica", "reproduce", "resistor", "responsive", "retraction",
    "retrieval", "retrospect", "revenue", "revival", "revolver", "sandalwood", "sardonic", "Saturday",
    "savagery", "scavenger", "sensation", "sociable", "souvenir", "specialist", "speculate", "stethoscope",
    "stupidity", "subscriber", "subterfuge", "suggestion", "supernova", "surrender", "suspicious", "sympathy",
    "tambourine", "telephone", "therapist", "tobacco", "tolerance", "tomorrow", "torpedo", "tradition",
    "travesty", "trombonist", "truncated", "typewriter", "ultimate", "undaunted", "underfoot", "unicorn",
    "unify", "universe", "unravel", "upcoming", "vacancy", "vagabond", "vertigo", "Virginia",
    "visitor", "vocalist", "voyager", "warranty", "Waterloo", "whimsical", "Wichita", "Wilmington",
    "Wyoming", "yesteryear", "Yucatan", "Yugoslav"
];

/**
 * Generate Short Authentication String (SAS) from master secret and public keys
 * Both peers MUST call this with the same ordered inputs to get matching SAS
 * 
 * @param {Uint8Array} masterSecret - The derived master shared secret
 * @param {Uint8Array} initiatorEcdhPk - Initiator's ECDH public key
 * @param {Uint8Array} responderEcdhPk - Responder's ECDH public key  
 * @param {Uint8Array} initiatorKyberPk - Initiator's Kyber public key
 * @param {Uint8Array} responderKyberPk - Responder's Kyber public key
 * @returns {Promise<{base32: string, words: string, numeric: string}>}
 */
async function generateSAS(masterSecret, initiatorEcdhPk, responderEcdhPk, initiatorKyberPk, responderKyberPk) {
    console.log('[Crypto] Generating SAS...');
    
    // Concatenate all inputs in consistent order
    // Both peers must use: initiator keys first, then responder keys
    const dataToHash = new Uint8Array([
        ...masterSecret,
        ...initiatorEcdhPk,
        ...responderEcdhPk,
        ...initiatorKyberPk,
        ...responderKyberPk
    ]);
    
    console.log('[Crypto] SAS input data length:', dataToHash.length);
    
    // Hash with SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Extract first 20 bits for Base32 (4 characters)
    const first20Bits = (hashArray[0] << 12) | (hashArray[1] << 4) | (hashArray[2] >> 4);
    
    // Extract first 16 bits for PGP words (2 words)
    const byte0 = hashArray[0]; // Even position -> even word
    const byte1 = hashArray[1]; // Odd position -> odd word
    
    // Generate Base32 encoding (4 characters from 20 bits)
    const base32 = encodeBase32_20bit(first20Bits);
    
    // Generate PGP word encoding (2 words from 16 bits)
    const word1 = PGP_WORDS_EVEN[byte0] || "unknown";
    const word2 = PGP_WORDS_ODD[byte1] || "unknown";
    const words = `${word1} ${word2}`;
    
    // Generate numeric fallback (4 digits)
    const numeric = ((hashArray[0] << 8) | hashArray[1]).toString().padStart(5, '0').substring(0, 4);
    
    console.log('[Crypto] SAS generated:', { base32, words, numeric });
    
    return {
        base32,  // e.g., "BZ4F"
        words,   // e.g., "spearhead Yucatan"
        numeric  // e.g., "1234"
    };
}

/**
 * Encode 20 bits as 4 Base32 characters (RFC 4648)
 * @param {number} bits20 - 20-bit integer
 * @returns {string} 4-character Base32 string
 */
function encodeBase32_20bit(bits20) {
    let result = '';
    
    // Extract 5 bits at a time (4 groups of 5 bits = 20 bits)
    for (let i = 3; i >= 0; i--) {
        const index = (bits20 >> (i * 5)) & 0x1F;
        result += BASE32_ALPHABET[index];
    }
    
    return result;
}

// ============================================
// Public API
// ============================================

const Crypto = {
    // Initialization
    initialize: initializeCrypto,
    isInitialized: () => cryptoInitialized,
    
    // Key generation
    generateHybridKeyPair,
    
    // Key agreement
    responderKeyAgreement,
    initiatorKeyAgreement,
    
    // Key derivation
    deriveMasterSecret,
    
    // DAY 3: SAS
    generateSAS,
};

// Export for ES modules
export { Crypto, CryptoUtils };
