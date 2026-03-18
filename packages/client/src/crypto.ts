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

export async function deriveKey(password: Uint8Array, salt: Uint8Array) {
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
            iterations: 250000, // recommended: 100k+
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

export async function sign(data: Uint8Array, privateKey: CryptoKey) {
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

export async function verifySignature(data: Uint8Array, signature: Uint8Array, publicKey: CryptoKey) {
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

export async function encryptRsa(data: Uint8Array, publicKey: CryptoKey) {
    return await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
}

export async function decryptRsa(encryptedData: Uint8Array, privateKey: CryptoKey) {
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
export async function encryptAes(data: Uint8Array, iv: Uint8Array, key: CryptoKey) {
    return await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        data
    );
}

export async function decryptAes(encryptedData: Uint8Array, iv: Uint8Array, key: CryptoKey) {
    return await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encryptedData
    );
}

export async function sha256(data: Uint8Array) {
    return await crypto.subtle.digest("SHA-256", data);
}

export async function exportAesKey(key: CryptoKey) {
    return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function importAesKey(rawKey: Uint8Array) {
    return await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

export async function importRsaPrivateKey(rawKey: Uint8Array) {
    return await crypto.subtle.importKey("pkcs8", rawKey, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

export async function exportRsaPrivateKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("pkcs8", key);
}

export async function importRsaPublicKey(rawKey: Uint8Array) {
    return await crypto.subtle.importKey("spki", rawKey, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

export async function exportRsaPublicKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("spki", key);
}

export async function importSignPrivateKey(rawKey: Uint8Array) {
    return await crypto.subtle.importKey("pkcs8", rawKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}

export async function exportSignPrivateKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("pkcs8", key);
}

export async function importSignPublicKey(rawKey: Uint8Array) {
    return await crypto.subtle.importKey("spki", rawKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

export async function exportSignPublicKey(key: CryptoKey) {
    return await crypto.subtle.exportKey("spki", key);
}
