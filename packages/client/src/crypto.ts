import nacl from "tweetnacl";

// https://github.com/dchest/tweetnacl-js/blob/master/README.md#usage

function deriveNonce(ephemeralPk: Uint8Array, recipientPk: Uint8Array): Uint8Array {
    const input = new Uint8Array(64);
    input.set(ephemeralPk, 0);
    input.set(recipientPk, 32);
    // SHA-512, take first 24 bytes for the nonce
    return nacl.hash(input).slice(0, 24);
}

export function naclBoxEphemeral(message: Uint8Array, recipientPk: Uint8Array): Uint8Array {
    const ephemeral = nacl.box.keyPair();
    const nonce = deriveNonce(ephemeral.publicKey, recipientPk);
    const encrypted = nacl.box(message, nonce, recipientPk, ephemeral.secretKey);

    const result = new Uint8Array(32 + encrypted.length);
    result.set(ephemeral.publicKey, 0);
    result.set(encrypted, 32);
    return result;
}

export function naclBoxEphemeralOpen(ciphertext: Uint8Array, recipientPk: Uint8Array, recipientSk: Uint8Array): Uint8Array {
    const ephemeralPk = ciphertext.slice(0, 32);
    const box = ciphertext.slice(32);
    const nonce = deriveNonce(ephemeralPk, recipientPk);
    const result = nacl.box.open(box, nonce, ephemeralPk, recipientSk);
    if (result === null) {
        throw new Error("Decryption failed: invalid ciphertext or key");
    }
    return result;
}

export async function deriveKey(password: Uint8Array, salt: Uint8Array, outputBytes: number, rounds = 250_000): Promise<Uint8Array> {
    const keyMaterial = await crypto.subtle.importKey("raw", password as Uint8Array<ArrayBuffer>, { name: "PBKDF2" }, false, ["deriveBits"]);

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt as Uint8Array<ArrayBuffer>,
            iterations: rounds,
            hash: "SHA-256",
        },
        keyMaterial,
        outputBytes * 8 // Convert to bits
    );

    return new Uint8Array(bits);
}
