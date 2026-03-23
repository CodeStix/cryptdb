import z from "zod";
import {} from "./types";
import nacl from "tweetnacl";
import { decodeBase64, encodeBase64, decodeUTF8, encodeUTF8 } from "tweetnacl-util";
import { naclBoxEphemeral, deriveKey } from "./crypto";
import { LoginRequest, LoginRequestSchema, LoginResponse } from "./generated/protocol_pb";
import { create, MessageInitShape } from "@bufbuild/protobuf";

export * from "./types";
export * from "./crypto";
export * from "./generated/protocol_pb";

const AUTH_SALT_PREFIX = "ap";
const KEY_SALT_PREFIX = "mk";

export class CryptClient {
    appName: string;
    url: string;

    signKeyPair?: { public: Uint8Array; private: Uint8Array };
    dataKeyPair?: { public: Uint8Array; private: Uint8Array };

    constructor(appName: string, url: string) {
        this.appName = appName;
        this.url = url;
    }

    private async fetchJson<Req, Res>(method: string, path: string, body?: Req) {
        const res = await fetch(
            this.url + path,
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

    getIdentifierDerivedSalt(identifier: string, prefix: string, length = 32) {
        if (prefix.length !== 2) {
            throw new Error("Prefix must be 2 characters");
        }
        const saltStr = prefix + this.appName + identifier;
        return nacl.hash(decodeUTF8(saltStr)).slice(0, length);
    }

    async loginUsingPassword(identifier: string, password: string) {
        const authenticationSalt = this.getIdentifierDerivedSalt(identifier, AUTH_SALT_PREFIX);
        const keySalt = this.getIdentifierDerivedSalt(identifier, KEY_SALT_PREFIX);

        console.log({ authenticationSalt, masterKeySalt: keySalt });

        const passwordBytes = decodeUTF8(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt, nacl.secretbox.keyLength);
        const masterKeyPassword = await deriveKey(passwordBytes, keySalt, nacl.secretbox.keyLength);

        // create(LoginRequestSchema, {
        //     method: {
        //         case: "password",
        //         value: {
        //             identifier: identifier,
        //             password: encodeBase64(authPassword),
        //         },
        //     },
        // });

        const res = await this.fetchJson<LoginRequest, LoginResponse>("POST", "/login", {
            method: {
                case: "password",
                value: {
                    identifier: identifier,
                    password: encodeBase64(authPassword),
                },
            },
        });

        if (res.status !== "ok") {
            throw new Error("Could not log in using password: " + res.status);
        }

        const encryptedMasterKey = decodeBase64(res.encryptedMasterKey);
        const encryptedMasterKeyNonce = decodeBase64(res.encryptedMasterKeyNonce);

        const masterKey = nacl.secretbox.open(encryptedMasterKey, encryptedMasterKeyNonce, masterKeyPassword);
        if (!masterKey) {
            throw new Error("Could not decrypt master key");
        }

        const publicSignKey = decodeBase64(res.publicSignKey);
        const encryptedPrivateSignKey = decodeBase64(res.encryptedPrivateSignKey);
        const encryptedPrivateSignKeyNonce = decodeBase64(res.encryptedPrivateSignKeyNonce);
        const privateSignKey = nacl.secretbox.open(encryptedPrivateSignKey, encryptedPrivateSignKeyNonce, masterKey);
        if (!privateSignKey) {
            throw new Error("Could not decrypt private sign key using master key");
        }

        const publicDataKey = decodeBase64(res.publicDataKey);
        const encryptedPrivateDataKey = decodeBase64(res.encryptedPrivateDataKey);
        const encryptedPrivateDataKeyNonce = decodeBase64(res.encryptedPrivateDataKeyNonce);
        const privateDataKey = nacl.secretbox.open(encryptedPrivateDataKey, encryptedPrivateDataKeyNonce, masterKey);
        if (!privateDataKey) {
            throw new Error("Could not decrypt private data key using master key");
        }

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

        const passwordBytes = decodeUTF8(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt, nacl.secretbox.keyLength);
        const masterKeyPassword = await deriveKey(passwordBytes, keySalt, nacl.secretbox.keyLength);

        const masterKey = nacl.randomBytes(nacl.secretbox.keyLength);

        const encryptedMasterKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const encryptedMasterKey = nacl.secretbox(masterKey, encryptedMasterKeyNonce, masterKeyPassword);

        const userKeypair = nacl.box.keyPair();
        const userEncryptedPrivateKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const userEncryptedPrivateKey = nacl.secretbox(userKeypair.secretKey, userEncryptedPrivateKeyNonce, masterKey);

        const userSignKeypair = nacl.sign.keyPair();
        const userEncryptedPrivateSignKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const userEncryptedPrivateSignKey = nacl.secretbox(userSignKeypair.secretKey, userEncryptedPrivateSignKeyNonce, masterKey);

        const groupKeypair = nacl.box.keyPair();
        const groupEncryptedPrivateKey = naclBoxEphemeral(groupKeypair.secretKey, userKeypair.publicKey);

        const collectionKeypair = nacl.box.keyPair();
        const collectionEncryptedPrivateKey = naclBoxEphemeral(collectionKeypair.secretKey, groupKeypair.publicKey);

        const res = await this.fetchJson<z.infer<typeof RegisterRequestSchema>, RegisterResponse>("POST", "/register", {
            method: "password",
            identifier: identifier,
            password: encodeBase64(authPassword),

            encryptedMasterKey: encodeBase64(encryptedMasterKey),
            encryptedMasterKeyNonce: encodeBase64(encryptedMasterKeyNonce),

            publicDataKey: encodeBase64(userKeypair.publicKey),
            encryptedPrivateDataKey: encodeBase64(userEncryptedPrivateKey),
            encryptedPrivateDataKeyNonce: encodeBase64(userEncryptedPrivateKeyNonce),

            publicSignKey: encodeBase64(userSignKeypair.publicKey),
            encryptedPrivateSignKey: encodeBase64(userEncryptedPrivateSignKey),
            encryptedPrivateSignKeyNonce: encodeBase64(userEncryptedPrivateSignKeyNonce),

            groupPublicKey: encodeBase64(groupKeypair.publicKey),
            groupEncryptedPrivateKey: encodeBase64(groupEncryptedPrivateKey),

            collectionPublicKey: encodeBase64(collectionKeypair.publicKey),
            collectionEncryptedPrivateKey: encodeBase64(collectionEncryptedPrivateKey),
        });

        if (res.status !== "ok") {
            throw new Error("Error during registration: " + res.status);
        }

        this.signKeyPair = {
            private: userSignKeypair.secretKey,
            public: userSignKeypair.publicKey,
        };
        this.dataKeyPair = {
            private: userKeypair.secretKey,
            public: userKeypair.publicKey,
        };

        console.log("Register ok", res);
    }
}
