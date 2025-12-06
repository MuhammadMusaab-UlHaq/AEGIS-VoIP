/**
 * AEGIS-VoIP - Crypto Module
 * Implements Hybrid Post-Quantum Key Exchange: X25519 (ECDH) + Kyber (PQC KEM)
 * Day 3: Added SAS generation
 */

import _sodium from 'libsodium-wrappers';
import { kyber } from 'kyber-crystals';

// ============================================
// Utility Functions
// ============================================

const CryptoUtils = {
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

    fromBase64(str) {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    },

    toHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
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

async function initializeCrypto() {
    if (cryptoInitialized) {
        console.log('[Crypto] Already initialized');
        return true;
    }

    try {
        await _sodium.ready;
        sodium = _sodium;
        console.log('[Crypto] libsodium initialized');

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

function generateECDHKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const keyPair = sodium.crypto_box_keypair();
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
    };
}

function computeECDHSecret(myPrivateKey, theirPublicKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    return sodium.crypto_scalarmult(myPrivateKey, theirPublicKey);
}

// ============================================
// Kyber (PQC KEM) Operations
// ============================================

async function generateKyberKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const keyPair = await Kyber.keyPair();
    return {
        publicKey: new Uint8Array(keyPair.publicKey),
        secretKey: new Uint8Array(keyPair.privateKey)
    };
}

async function kyberEncapsulate(theirPublicKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const result = await Kyber.encrypt(theirPublicKey);
    return {
        ciphertext: new Uint8Array(result.cyphertext),
        sharedSecret: new Uint8Array(result.secret)
    };
}

async function kyberDecapsulate(ciphertext, mySecretKey) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const sharedSecret = await Kyber.decrypt(ciphertext, mySecretKey);
    return new Uint8Array(sharedSecret);
}

// ============================================
// Hybrid Key Exchange
// ============================================

async function generateHybridKeyPair() {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    const ecdhKeys = generateECDHKeyPair();
    const kyberKeys = await generateKyberKeyPair();
    
    console.log('[Crypto] Generated hybrid key pair');
    console.log('[Crypto] ECDH Public Key length:', ecdhKeys.publicKey.length);
    console.log('[Crypto] Kyber Public Key length:', kyberKeys.publicKey.length);
    
    return {
        ecdh: ecdhKeys,
        kyber: kyberKeys
    };
}

async function responderKeyAgreement(theirEcdhPk, theirKyberPk) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    console.log('[Crypto] Responder performing key agreement...');
    
    const myEcdhKeys = generateECDHKeyPair();
    const ecdhSecret = computeECDHSecret(myEcdhKeys.privateKey, theirEcdhPk);
    console.log('[Crypto] ECDH secret computed, length:', ecdhSecret.length);
    
    const kyberResult = await kyberEncapsulate(theirKyberPk);
    console.log('[Crypto] Kyber encapsulation done');
    console.log('[Crypto] Kyber ciphertext length:', kyberResult.ciphertext.length);
    console.log('[Crypto] Kyber shared secret length:', kyberResult.sharedSecret.length);
    
    return {
        myEcdhPublicKey: myEcdhKeys.publicKey,
        kyberCiphertext: kyberResult.ciphertext,
        ecdhSecret: ecdhSecret,
        kyberSecret: kyberResult.sharedSecret
    };
}

async function initiatorKeyAgreement(myEcdhPrivateKey, myKyberSecretKey, theirEcdhPk, kyberCiphertext) {
    if (!cryptoInitialized) throw new Error('Crypto not initialized');
    
    console.log('[Crypto] Initiator performing key agreement...');
    
    const ecdhSecret = computeECDHSecret(myEcdhPrivateKey, theirEcdhPk);
    console.log('[Crypto] ECDH secret computed, length:', ecdhSecret.length);
    
    const kyberSecret = await kyberDecapsulate(kyberCiphertext, myKyberSecretKey);
    console.log('[Crypto] Kyber decapsulation done, secret length:', kyberSecret.length);
    
    return {
        ecdhSecret: ecdhSecret,
        kyberSecret: kyberSecret
    };
}

// ============================================
// Key Derivation Function (HKDF)
// ============================================

async function hkdfExtract(salt, ikm) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        salt.length > 0 ? salt : new Uint8Array(32),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const prk = await crypto.subtle.sign('HMAC', keyMaterial, ikm);
    return new Uint8Array(prk);
}

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

async function deriveMasterSecret(ecdhSecret, kyberSecret) {
    console.log('[Crypto] Deriving master secret...');
    
    const ikm = new Uint8Array(ecdhSecret.length + kyberSecret.length);
    ikm.set(ecdhSecret, 0);
    ikm.set(kyberSecret, ecdhSecret.length);
    
    const info = new TextEncoder().encode('AEGIS-VoIP-v1-Master-Secret');
    const prk = await hkdfExtract(new Uint8Array(0), ikm);
    const masterSecret = await hkdfExpand(prk, info, 32);
    
    console.log('[Crypto] Master secret derived, length:', masterSecret.length);
    console.log('[Crypto] Master secret (hex):', CryptoUtils.toHex(masterSecret));
    
    return masterSecret;
}

// ============================================
// DAY 3: Short Authentication String (SAS)
// ============================================

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

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

async function generateSAS(masterSecret, initiatorEcdhPk, responderEcdhPk, initiatorKyberPk, responderKyberPk) {
    console.log('[Crypto] Generating SAS...');
    
    const dataToHash = new Uint8Array([
        ...masterSecret,
        ...initiatorEcdhPk,
        ...responderEcdhPk,
        ...initiatorKyberPk,
        ...responderKyberPk
    ]);
    
    console.log('[Crypto] SAS input data length:', dataToHash.length);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
    const hashArray = new Uint8Array(hashBuffer);
    
    const first20Bits = (hashArray[0] << 12) | (hashArray[1] << 4) | (hashArray[2] >> 4);
    const byte0 = hashArray[0];
    const byte1 = hashArray[1];
    
    const base32 = encodeBase32_20bit(first20Bits);
    const word1 = PGP_WORDS_EVEN[byte0] || "unknown";
    const word2 = PGP_WORDS_ODD[byte1] || "unknown";
    const words = `${word1} ${word2}`;
    const numeric = ((hashArray[0] << 8) | hashArray[1]).toString().padStart(5, '0').substring(0, 4);
    
    console.log('[Crypto] SAS generated:', { base32, words, numeric });
    
    return { base32, words, numeric };
}

function encodeBase32_20bit(bits20) {
    let result = '';
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
    initialize: initializeCrypto,
    isInitialized: () => cryptoInitialized,
    generateHybridKeyPair,
    responderKeyAgreement,
    initiatorKeyAgreement,
    deriveMasterSecret,
    generateSAS,
};

export { Crypto, CryptoUtils };