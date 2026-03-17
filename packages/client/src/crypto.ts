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

export function decodeBase64(base64: string): Uint8Array<ArrayBuffer> {
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
            iterations: 1000000, // recommended: 100k+
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

export async function keyToBuffer(key: CryptoKey) {
    return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}
