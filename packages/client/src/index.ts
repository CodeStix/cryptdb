import z from "zod";
import { LoginRequestSchema, LoginResponse, RegisterRequestSchema, RegisterResponse } from "./types";
import {
    decodeBase64,
    decryptAes,
    deriveKey,
    encodeBase64,
    encryptAes,
    encryptRsa,
    exportAesKey,
    exportRsaPrivateKey,
    exportRsaPublicKey,
    exportSignPrivateKey,
    exportSignPublicKey,
    generateAesKey,
    generateRsaKeypair,
    generateSignKeypair,
    importAesKey,
    importRsaPrivateKey,
    importRsaPublicKey,
    importSignPrivateKey,
    importSignPublicKey,
    textToBytes,
} from "./crypto";

export * from "./types";
export * from "./crypto";

const AUTH_SALT_PREFIX = "ap";
const KEY_SALT_PREFIX = "mk";

export class CryptClient {
    appName: string;
    url: string;

    signKeyPair?: { public: CryptoKey; private: CryptoKey };
    dataKeyPair?: { public: CryptoKey; private: CryptoKey };

    constructor(appName: string, url: string) {
        this.appName = appName;
        this.url = url;
    }

    private async fetchJson<Req, Res>(method: string, path: string, body?: Req) {
        const res = await fetch(
            this.url + "/login",
            body
                ? {
                      method: method,
                      headers: {
                          "Content-Type": "application/json",
                      },
                      body: JSON.stringify(body),
                  }
                : {
                      method: method,
                  }
        );

        if (!res.ok) {
            throw new Error("Could not fetch " + path + ": " + res.status);
        }

        return (await res.json()) as Res;
    }

    textToSalt(str: string, length = 32) {
        const salt = new Uint8Array(length);
        const b = textToBytes(str);
        for (let i = 0; i < b.length && i < length; i++) {
            salt[i] = b[i]!;
        }
        return salt;
    }

    getIdentifierDerivedSalt(identifier: string, prefix: string, length = 32) {
        if (prefix.length !== 2) {
            throw new Error("Prefix must be 2 characters");
        }
        // Prefix + appname make up 8 characters of the salt, remaining 24 chars for identifier/username
        return this.textToSalt(prefix + this.appName.substring(0, 6) + identifier, length);
    }

    async loginUsingPassword(identifier: string, password: string) {
        const authenticationSalt = this.getIdentifierDerivedSalt(identifier, AUTH_SALT_PREFIX);
        const keySalt = this.getIdentifierDerivedSalt(identifier, KEY_SALT_PREFIX);

        console.log({ authenticationSalt, masterKeySalt: keySalt });

        const passwordBytes = textToBytes(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt);
        const keyPassword = await deriveKey(passwordBytes, keySalt);

        const res = await this.fetchJson<z.infer<typeof LoginRequestSchema>, LoginResponse>("POST", "/login", {
            method: "password",
            identifier: identifier,
            password: encodeBase64(new Uint8Array(await exportAesKey(authPassword))),
        });

        if (res.status !== "ok") {
            throw new Error("Could not log in using password: " + res.status);
        }

        const encryptedMasterKey = decodeBase64(res.encryptedMasterKey);
        const encryptedMasterKeyIV = decodeBase64(res.encryptedMasterKeyIV);

        const masterKey = await importAesKey(await decryptAes(encryptedMasterKey, encryptedMasterKeyIV, keyPassword));

        const publicSignKey = await importSignPublicKey(decodeBase64(res.publicSignKey));
        const encryptedPrivateSignKey = decodeBase64(res.encryptedPrivateSignKey);
        const encryptedPrivateSignKeyIV = decodeBase64(res.encryptedPrivateSignKeyIV);
        const privateSignKey = await importSignPrivateKey(await decryptAes(encryptedPrivateSignKey, encryptedPrivateSignKeyIV, masterKey));

        const publicDataKey = await importRsaPublicKey(decodeBase64(res.publicDataKey));
        const encryptedPrivateDataKey = decodeBase64(res.encryptedPrivateDataKey);
        const encryptedPrivateDataKeyIV = decodeBase64(res.encryptedPrivateDataKeyIV);
        const privateDataKey = await importRsaPrivateKey(await decryptAes(encryptedPrivateDataKey, encryptedPrivateDataKeyIV, masterKey));

        this.signKeyPair = {
            private: privateSignKey,
            public: publicSignKey,
        };
        this.dataKeyPair = {
            private: privateDataKey,
            public: publicDataKey,
        };

        console.log("Succesfully authenticated using password", res, {
            privateSignKey,
            publicSignKey,
            privateDataKey,
            publicDataKey,
        });
    }

    async registerUsingPassword(identifier: string, password: string) {
        const authenticationSalt = this.getIdentifierDerivedSalt(identifier, AUTH_SALT_PREFIX);
        const keySalt = this.getIdentifierDerivedSalt(identifier, KEY_SALT_PREFIX);

        const passwordBytes = textToBytes(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt);
        const keyPassword = await deriveKey(passwordBytes, keySalt);

        const masterKey = await generateAesKey();

        const encryptedMasterKeyIV = crypto.getRandomValues(new Uint8Array(16));
        const encryptedMasterKey = await encryptAes(await exportAesKey(masterKey), encryptedMasterKeyIV, keyPassword);

        const userKeypair = await generateRsaKeypair();
        const userPublicKey = await exportRsaPublicKey(userKeypair.publicKey);
        const userEncryptedPrivateKeyIV = crypto.getRandomValues(new Uint8Array(16));
        const userEncryptedPrivateKey = await encryptAes(await exportRsaPrivateKey(userKeypair.privateKey), userEncryptedPrivateKeyIV, masterKey);

        const userSignKeypair = await generateSignKeypair();
        const userSignPublicKey = await exportSignPublicKey(userSignKeypair.publicKey);
        const userEncryptedPrivateSignKeyIV = crypto.getRandomValues(new Uint8Array(16));
        const userEncryptedPrivateSignKey = await encryptAes(
            await exportSignPrivateKey(userSignKeypair.privateKey),
            userEncryptedPrivateSignKeyIV,
            masterKey
        );

        const groupKeypair = await generateRsaKeypair();
        const groupPublicKey = await exportRsaPublicKey(groupKeypair.publicKey);
        const groupEncryptedPrivateKey = await encryptRsa(await exportRsaPrivateKey(groupKeypair.privateKey), userKeypair.publicKey);

        const collectionKeypair = await generateRsaKeypair();
        const collectionPublicKey = await exportRsaPublicKey(collectionKeypair.publicKey);
        const collectionEncryptedPrivateKey = await encryptRsa(await exportRsaPrivateKey(collectionKeypair.privateKey), groupKeypair.publicKey);

        const res = await this.fetchJson<z.infer<typeof RegisterRequestSchema>, RegisterResponse>("POST", "/register", {
            method: "password",
            identifier: identifier,
            password: encodeBase64(new Uint8Array(await exportAesKey(authPassword))),

            encryptedMasterKey: encodeBase64(new Uint8Array(encryptedMasterKey)),
            encryptedMasterKeyIV: encodeBase64(encryptedMasterKeyIV),

            publicDataKey: encodeBase64(new Uint8Array(userPublicKey)),
            encryptedPrivateDataKey: encodeBase64(new Uint8Array(userEncryptedPrivateKey)),
            encryptedPrivateDataKeyIV: encodeBase64(new Uint8Array(userEncryptedPrivateKeyIV)),

            publicSignKey: encodeBase64(new Uint8Array(userSignPublicKey)),
            encryptedPrivateSignKey: encodeBase64(new Uint8Array(userEncryptedPrivateSignKey)),
            encryptedPrivateSignKeyIV: encodeBase64(new Uint8Array(userEncryptedPrivateSignKeyIV)),

            groupPublicKey: encodeBase64(new Uint8Array(groupPublicKey)),
            groupEncryptedPrivateKey: encodeBase64(new Uint8Array(groupEncryptedPrivateKey)),

            collectionPublicKey: encodeBase64(new Uint8Array(collectionPublicKey)),
            collectionEncryptedPrivateKey: encodeBase64(new Uint8Array(collectionEncryptedPrivateKey)),
        });

        if (res.status !== "ok") {
            throw new Error("Error during registration: " + res.status);
        }

        this.signKeyPair = {
            private: userSignKeypair.privateKey,
            public: userSignKeypair.publicKey,
        };
        this.dataKeyPair = {
            private: userKeypair.privateKey,
            public: userKeypair.publicKey,
        };

        console.log("Register ok", res);
    }
}
