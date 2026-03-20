export function textToBytes(text: string) {
    const enc = new TextEncoder();
    return enc.encode(text);
}

export function encodeBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary);
}

export function decodeBase64(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

export async function deriveKey(password: BufferSource, salt: BufferSource, rounds = 250000) {
    // Import password as a CryptoKey
    const keyMaterial = await crypto.subtle.importKey(
        "raw", // raw bytes
        password,
        { name: "PBKDF2" },
        false, // not extractable
        ["deriveKey"] // usage
    );

    // Derive a key using PBKDF2
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt, // Uint8Array
            iterations: rounds, // recommended: 100k+
            hash: "SHA-256", // hash function
        },
        keyMaterial,
        {
            name: "AES-GCM", // target algorithm
            length: 256, // key length in bits
        },
        true, // extractable
        ["encrypt", "decrypt"] // key usages
    );

    return derivedKey;
}

export async function generateSignKeypair() {
    return await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        true, // extractable
        ["sign", "verify"]
    );
}

export async function sign(data: BufferSource, privateKey: CryptoKey) {
    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" },
        },
        privateKey,
        data
    );

    return signature;
}

export async function verifySignature(data: BufferSource, signature: BufferSource, publicKey: CryptoKey) {
    return await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" },
        },
        publicKey,
        signature,
        data
    );
}

export async function generateRsaKeypair() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function encryptRsa(data: BufferSource, publicKey: CryptoKey) {
    return await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
}

export async function decryptRsa(encryptedData: BufferSource, privateKey: CryptoKey) {
    return await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedData);
}

export async function generateAesKey() {
    return await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256, // 128 or 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

export function generateIv() {
    return crypto.getRandomValues(new Uint8Array(12));
}

// iv = nonce, must be 12 bytes
export async function encryptAes(data: BufferSource, iv: BufferSource, key: CryptoKey) {
    return await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        data
    );
}

export async function decryptAes(encryptedData: BufferSource, iv: BufferSource, key: CryptoKey) {
    return await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encryptedData
    );
}

export async function sha256(data: BufferSource) {
    return await crypto.subtle.digest("SHA-256", data);
}

export async function exportRawKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("raw", key);
}

export async function exportAesKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("raw", key);
}

export async function importAesKey(rawKey: BufferSource, exportable = false) {
    return await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, exportable, ["encrypt", "decrypt"]);
}

export async function importRsaPrivateKey(rawKey: BufferSource, exportable = false) {
    return await crypto.subtle.importKey("pkcs8", rawKey, { name: "RSA-OAEP", hash: "SHA-256" }, exportable, ["decrypt"]);
}

export async function exportRsaPrivateKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("pkcs8", key);
}

export async function importRsaPublicKey(rawKey: BufferSource, exportable = false) {
    return await crypto.subtle.importKey("spki", rawKey, { name: "RSA-OAEP", hash: "SHA-256" }, exportable, ["encrypt"]);
}

export async function exportRsaPublicKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("spki", key);
}

export async function importSignPrivateKey(rawKey: BufferSource, exportable = false) {
    return await crypto.subtle.importKey("pkcs8", rawKey, { name: "ECDSA", namedCurve: "P-256" }, exportable, ["sign"]);
}

export async function exportSignPrivateKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("pkcs8", key);
}

export async function importSignPublicKey(rawKey: BufferSource, exportable = false) {
    return await crypto.subtle.importKey("spki", rawKey, { name: "ECDSA", namedCurve: "P-256" }, exportable, ["verify"]);
}

export async function exportSignPublicKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("spki", key);
}
