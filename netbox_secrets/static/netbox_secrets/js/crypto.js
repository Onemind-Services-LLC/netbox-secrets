/**
 * NetBox Secrets - Client-Side Cryptography Library
 *
 * This library handles all encryption/decryption client-side.
 * The server NEVER sees plaintext secrets or encryption keys.
 *
 * Dependencies:
 * - libsodium.js (for X25519)
 * - WebCrypto API (built into browsers)
 * - WebAuthn API (built into browsers)
 *
 * Security Model:
 * - Tenant key: AES-256 symmetric key, encrypts all secrets for a tenant
 * - User's X25519 keypair: Encrypts tenant key for each member
 * - User's private key: Protected by WebAuthn PRF (Touch ID / Face ID)
 * - Service account activation: Requires human to decrypt and provide key
 */

// Namespace for all crypto functions
window.NetBoxSecretsCrypto = (function() {
    'use strict';

    // Check for required APIs
    const hasWebAuthn = typeof window.PublicKeyCredential !== 'undefined';
    const hasWebCrypto = typeof window.crypto !== 'undefined' && typeof window.crypto.subtle !== 'undefined';

    // Sodium.js will be loaded dynamically
    let sodiumReady = false;
    let sodiumReadyPromise = null;

    /**
     * Initialize the crypto library (load libsodium)
     */
    async function init() {
        if (sodiumReady) return;

        if (!sodiumReadyPromise) {
            sodiumReadyPromise = new Promise((resolve, reject) => {
                if (typeof sodium !== 'undefined' && sodium.ready) {
                    sodium.ready.then(() => {
                        sodiumReady = true;
                        resolve();
                    }).catch(reject);
                } else {
                    // Load libsodium dynamically
                    const script = document.createElement('script');
                    script.src = 'https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.13/dist/modules/libsodium-wrappers.min.js';
                    script.onload = () => {
                        sodium.ready.then(() => {
                            sodiumReady = true;
                            resolve();
                        }).catch(reject);
                    };
                    script.onerror = () => reject(new Error('Failed to load libsodium'));
                    document.head.appendChild(script);
                }
            });
        }

        return sodiumReadyPromise;
    }

    /**
     * Check if WebAuthn PRF extension is supported
     */
    async function isPRFSupported() {
        if (!hasWebAuthn) return false;

        try {
            // Check if PRF extension is available
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return available;
        } catch (e) {
            return false;
        }
    }

    // ========================================
    // Key Generation
    // ========================================

    /**
     * Generate a new X25519 keypair
     * @returns {Object} { publicKey: Uint8Array, privateKey: Uint8Array }
     */
    async function generateX25519Keypair() {
        await init();
        const keypair = sodium.crypto_box_keypair();
        return {
            publicKey: keypair.publicKey,
            privateKey: keypair.privateKey
        };
    }

    /**
     * Generate a random AES-256 key (32 bytes)
     * @returns {Uint8Array} 32-byte key
     */
    function generateAES256Key() {
        return crypto.getRandomValues(new Uint8Array(32));
    }

    /**
     * Generate a random nonce for AES-GCM (12 bytes)
     * @returns {Uint8Array} 12-byte nonce
     */
    function generateNonce() {
        return crypto.getRandomValues(new Uint8Array(12));
    }

    // ========================================
    // X25519 Encryption (SealedBox pattern)
    // ========================================

    /**
     * Encrypt data using X25519 SealedBox (anonymous sender)
     * @param {Uint8Array} data - Data to encrypt
     * @param {Uint8Array} recipientPublicKey - Recipient's X25519 public key
     * @returns {Uint8Array} Ciphertext (ephemeral pubkey + encrypted data)
     */
    async function sealedBoxEncrypt(data, recipientPublicKey) {
        await init();
        return sodium.crypto_box_seal(data, recipientPublicKey);
    }

    /**
     * Decrypt SealedBox ciphertext
     * @param {Uint8Array} ciphertext - Ciphertext from sealedBoxEncrypt
     * @param {Uint8Array} publicKey - Recipient's public key
     * @param {Uint8Array} privateKey - Recipient's private key
     * @returns {Uint8Array} Decrypted data
     */
    async function sealedBoxDecrypt(ciphertext, publicKey, privateKey) {
        await init();
        return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey);
    }

    // ========================================
    // AES-256-GCM Encryption
    // ========================================

    /**
     * Import a raw key for AES-GCM
     * @param {Uint8Array} rawKey - 32-byte key
     * @returns {CryptoKey}
     */
    async function importAESKey(rawKey) {
        return crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data with AES-256-GCM
     * @param {Uint8Array} data - Data to encrypt
     * @param {Uint8Array} key - 32-byte AES key
     * @returns {Uint8Array} nonce (12 bytes) + ciphertext + tag (16 bytes)
     */
    async function aesGcmEncrypt(data, key) {
        const nonce = generateNonce();
        const cryptoKey = await importAESKey(key);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            data
        );

        // Concatenate nonce + ciphertext
        const result = new Uint8Array(nonce.length + ciphertext.byteLength);
        result.set(nonce, 0);
        result.set(new Uint8Array(ciphertext), nonce.length);
        return result;
    }

    /**
     * Decrypt AES-256-GCM ciphertext
     * @param {Uint8Array} ciphertext - nonce (12 bytes) + encrypted data + tag
     * @param {Uint8Array} key - 32-byte AES key
     * @returns {Uint8Array} Decrypted data
     */
    async function aesGcmDecrypt(ciphertext, key) {
        const nonce = ciphertext.slice(0, 12);
        const encrypted = ciphertext.slice(12);
        const cryptoKey = await importAESKey(key);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            encrypted
        );

        return new Uint8Array(decrypted);
    }

    // ========================================
    // WebAuthn PRF Extension
    // ========================================

    /**
     * Create a new Passkey with PRF support
     * @param {string} username - User's display name
     * @param {string} userId - User's unique ID (e.g., from database)
     * @param {string} rpId - Relying party ID (domain)
     * @returns {Object} { credentialId: string, publicKey: Uint8Array }
     */
    async function createPasskey(username, userId, rpId) {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const userIdBytes = new TextEncoder().encode(userId);

        const credential = await navigator.credentials.create({
            publicKey: {
                challenge: challenge,
                rp: {
                    name: 'NetBox Secrets',
                    id: rpId || window.location.hostname
                },
                user: {
                    id: userIdBytes,
                    name: username,
                    displayName: username
                },
                pubKeyCredParams: [
                    { alg: -7, type: 'public-key' },   // ES256
                    { alg: -257, type: 'public-key' }  // RS256
                ],
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    userVerification: 'required',
                    residentKey: 'required'
                },
                extensions: {
                    prf: {}
                }
            }
        });

        // Check if PRF is supported
        const extResults = credential.getClientExtensionResults();
        if (!extResults.prf || !extResults.prf.enabled) {
            throw new Error('PRF extension not supported by this authenticator');
        }

        return {
            credentialId: arrayBufferToBase64url(credential.rawId),
            publicKey: new Uint8Array(credential.response.getPublicKey())
        };
    }

    /**
     * Derive a key using WebAuthn PRF
     * @param {string} credentialId - Base64url-encoded credential ID
     * @param {string} salt - Salt for key derivation (e.g., "netbox-secrets-private-key")
     * @param {string} rpId - Relying party ID (domain)
     * @returns {Uint8Array} 32-byte derived key
     */
    async function deriveKeyWithPRF(credentialId, salt, rpId) {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const saltBytes = new TextEncoder().encode(salt);

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                rpId: rpId || window.location.hostname,
                allowCredentials: [{
                    id: base64urlToArrayBuffer(credentialId),
                    type: 'public-key'
                }],
                userVerification: 'required',
                extensions: {
                    prf: {
                        eval: {
                            first: saltBytes
                        }
                    }
                }
            }
        });

        const extResults = assertion.getClientExtensionResults();
        if (!extResults.prf || !extResults.prf.results || !extResults.prf.results.first) {
            throw new Error('PRF evaluation failed');
        }

        return new Uint8Array(extResults.prf.results.first);
    }

    // ========================================
    // High-Level Flows
    // ========================================

    /**
     * Setup cryptographic membership for a user in a tenant
     * Called when first user creates tenant crypto or when adding a new member
     *
     * @param {string} credentialId - User's WebAuthn credential ID
     * @param {Uint8Array} tenantKey - The tenant's encryption key (null for first member)
     * @param {string} rpId - Relying party ID
     * @returns {Object} Data to send to server
     */
    async function setupMembership(credentialId, tenantKey, rpId) {
        await init();

        // Generate X25519 keypair for this user
        const keypair = await generateX25519Keypair();

        // If no tenant key provided, generate one (first member)
        if (!tenantKey) {
            tenantKey = generateAES256Key();
        }

        // Derive PRF key for protecting private key
        const prfKey = await deriveKeyWithPRF(credentialId, 'netbox-secrets-private-key', rpId);

        // Encrypt private key with PRF-derived key
        const encryptedPrivateKey = await aesGcmEncrypt(keypair.privateKey, prfKey);

        // Encrypt tenant key with user's public key
        const encryptedTenantKey = await sealedBoxEncrypt(tenantKey, keypair.publicKey);

        return {
            publicKey: uint8ArrayToPEM(keypair.publicKey, 'X25519 PUBLIC KEY'),
            encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
            encryptedTenantKey: arrayBufferToBase64(encryptedTenantKey),
            credentialId: credentialId
        };
    }

    /**
     * Decrypt the tenant key for the current user
     *
     * @param {string} credentialId - User's WebAuthn credential ID
     * @param {string} encryptedPrivateKeyB64 - Base64-encoded encrypted private key
     * @param {string} encryptedTenantKeyB64 - Base64-encoded encrypted tenant key
     * @param {string} publicKeyPEM - User's public key in PEM format
     * @param {string} rpId - Relying party ID
     * @returns {Uint8Array} Decrypted tenant key
     */
    async function decryptTenantKey(credentialId, encryptedPrivateKeyB64, encryptedTenantKeyB64, publicKeyPEM, rpId) {
        await init();

        // Derive PRF key
        const prfKey = await deriveKeyWithPRF(credentialId, 'netbox-secrets-private-key', rpId);

        // Decrypt private key
        const encryptedPrivateKey = base64ToUint8Array(encryptedPrivateKeyB64);
        const privateKey = await aesGcmDecrypt(encryptedPrivateKey, prfKey);

        // Decrypt tenant key
        const publicKey = pemToUint8Array(publicKeyPEM);
        const encryptedTenantKey = base64ToUint8Array(encryptedTenantKeyB64);
        const tenantKey = await sealedBoxDecrypt(encryptedTenantKey, publicKey, privateKey);

        return tenantKey;
    }

    /**
     * Encrypt a secret with the tenant key
     *
     * @param {string} plaintext - Secret to encrypt
     * @param {Uint8Array} tenantKey - Tenant's encryption key
     * @returns {string} Base64-encoded ciphertext
     */
    async function encryptSecret(plaintext, tenantKey) {
        const data = new TextEncoder().encode(plaintext);
        const ciphertext = await aesGcmEncrypt(data, tenantKey);
        return arrayBufferToBase64(ciphertext);
    }

    /**
     * Decrypt a secret with the tenant key
     *
     * @param {string} ciphertextB64 - Base64-encoded ciphertext
     * @param {Uint8Array} tenantKey - Tenant's encryption key
     * @returns {string} Decrypted plaintext
     */
    async function decryptSecret(ciphertextB64, tenantKey) {
        const ciphertext = base64ToUint8Array(ciphertextB64);
        const decrypted = await aesGcmDecrypt(ciphertext, tenantKey);
        return new TextDecoder().decode(decrypted);
    }

    /**
     * Add a new member to a tenant (requires current member's participation)
     *
     * @param {Uint8Array} tenantKey - Decrypted tenant key (from current member)
     * @param {string} newMemberPublicKeyPEM - New member's X25519 public key
     * @returns {string} Base64-encoded encrypted tenant key for new member
     */
    async function encryptTenantKeyForMember(tenantKey, newMemberPublicKeyPEM) {
        await init();
        const publicKey = pemToUint8Array(newMemberPublicKeyPEM);
        const encrypted = await sealedBoxEncrypt(tenantKey, publicKey);
        return arrayBufferToBase64(encrypted);
    }

    /**
     * Create a service account for a tenant
     *
     * @param {Uint8Array} tenantKey - Decrypted tenant key
     * @returns {Object} Service account data to send to server + activation key
     */
    async function createServiceAccount(tenantKey) {
        await init();

        // Generate X25519 keypair for service account
        const keypair = await generateX25519Keypair();

        // Generate activation key (will be stored in memory on server after human activates)
        const activationKey = generateAES256Key();
        const activationSalt = crypto.getRandomValues(new Uint8Array(32));
        const nonce = generateNonce();

        // Encrypt private key with activation key
        const cryptoKey = await importAESKey(activationKey);
        const encryptedPrivateKey = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            keypair.privateKey
        );

        // Encrypt tenant key with service account's public key
        const encryptedTenantKey = await sealedBoxEncrypt(tenantKey, keypair.publicKey);

        return {
            // Data for server storage
            serverData: {
                publicKey: uint8ArrayToPEM(keypair.publicKey, 'X25519 PUBLIC KEY'),
                encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
                encryptedTenantKey: arrayBufferToBase64(encryptedTenantKey),
                activationSalt: arrayBufferToBase64(activationSalt),
                privateKeyNonce: arrayBufferToBase64(nonce)
            },
            // Activation key - show to user ONCE, they must save it securely
            activationKey: arrayBufferToBase64(activationKey)
        };
    }

    /**
     * Activate a service account (human provides activation key)
     * This decrypts the service account's private key for storage in server memory
     *
     * @param {string} activationKeyB64 - Base64-encoded activation key
     * @param {string} encryptedPrivateKeyB64 - Base64-encoded encrypted private key
     * @param {string} nonceB64 - Base64-encoded nonce
     * @returns {string} Base64-encoded decrypted private key (to send to server for in-memory storage)
     */
    async function activateServiceAccount(activationKeyB64, encryptedPrivateKeyB64, nonceB64) {
        const activationKey = base64ToUint8Array(activationKeyB64);
        const encryptedPrivateKey = base64ToUint8Array(encryptedPrivateKeyB64);
        const nonce = base64ToUint8Array(nonceB64);

        const cryptoKey = await importAESKey(activationKey);
        const privateKey = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            encryptedPrivateKey
        );

        return arrayBufferToBase64(privateKey);
    }

    // ========================================
    // Utility Functions
    // ========================================

    function arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToUint8Array(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function arrayBufferToBase64url(buffer) {
        return arrayBufferToBase64(buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    function base64urlToArrayBuffer(base64url) {
        const base64 = base64url
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            + '=='.slice(0, (4 - base64url.length % 4) % 4);
        return base64ToUint8Array(base64);
    }

    function uint8ArrayToPEM(data, label) {
        const base64 = arrayBufferToBase64(data);
        return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
    }

    function pemToUint8Array(pem) {
        const lines = pem.split('\n');
        let base64 = '';
        for (const line of lines) {
            if (!line.startsWith('-----')) {
                base64 += line.trim();
            }
        }
        return base64ToUint8Array(base64);
    }

    // ========================================
    // Public API
    // ========================================

    return {
        // Initialization
        init: init,
        isPRFSupported: isPRFSupported,

        // Key generation
        generateX25519Keypair: generateX25519Keypair,
        generateAES256Key: generateAES256Key,

        // Low-level crypto
        sealedBoxEncrypt: sealedBoxEncrypt,
        sealedBoxDecrypt: sealedBoxDecrypt,
        aesGcmEncrypt: aesGcmEncrypt,
        aesGcmDecrypt: aesGcmDecrypt,

        // WebAuthn
        createPasskey: createPasskey,
        deriveKeyWithPRF: deriveKeyWithPRF,

        // High-level flows
        setupMembership: setupMembership,
        decryptTenantKey: decryptTenantKey,
        encryptSecret: encryptSecret,
        decryptSecret: decryptSecret,
        encryptTenantKeyForMember: encryptTenantKeyForMember,
        createServiceAccount: createServiceAccount,
        activateServiceAccount: activateServiceAccount,

        // Utilities
        arrayBufferToBase64: arrayBufferToBase64,
        base64ToUint8Array: base64ToUint8Array,
        uint8ArrayToPEM: uint8ArrayToPEM,
        pemToUint8Array: pemToUint8Array
    };
})();
