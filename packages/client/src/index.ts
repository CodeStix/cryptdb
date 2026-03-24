import z from "zod";
import {} from "./types";
import nacl from "tweetnacl";
import { decodeBase64, encodeBase64, decodeUTF8, encodeUTF8 } from "tweetnacl-util";
import { naclBoxEphemeral, deriveKey } from "./crypto";
import {
    ErrorCode,
    LoginRequest,
    LoginRequestSchema,
    LoginResponse,
    LoginResponseSchema,
    RegisterRequestSchema,
    RegisterResponseSchema,
} from "./generated/protocol_pb";
import { create, DescMessage, fromBinary, MessageInitShape, MessageShape, toBinary } from "@bufbuild/protobuf";

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

    private async fetchProto<Req extends DescMessage, Res extends DescMessage>(
        method: string,
        path: string,
        requestSchema: Req,
        responseSchema: Res,
        body: MessageInitShape<Req>
    ): Promise<MessageShape<Res>> {
        let res: Response;

        if (method === "GET") {
            res = await fetch(this.url + path, {
                method: "GET",
            });
        } else {
            const msg = create(requestSchema, body);
            res = await fetch(this.url + path, {
                method: method,
                headers: {
                    "Content-Type": "application/octet-stream",
                },
                body: toBinary(requestSchema, msg),
            });
        }

        if (!res.ok) {
            throw new Error("Could not fetch " + path + ": " + res.status);
        }

        const bytes = new Uint8Array(await res.arrayBuffer());
        const parsed = fromBinary(responseSchema, bytes);

        return parsed;
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

        const res = await this.fetchProto("POST", "/login", LoginRequestSchema, LoginResponseSchema, {
            method: {
                case: "password",
                value: {
                    identifier: identifier,
                    password: authPassword,
                },
            },
        });

        if (res.response.case != "ok") {
            throw new Error("Could not log in using password: " + ErrorCode[res.response.value!.errorCode]);
        }

        const okResponse = res.response.value!;

        const masterKey = nacl.secretbox.open(okResponse.encryptedMasterKey, okResponse.encryptedMasterKeyNonce, masterKeyPassword);
        if (!masterKey) {
            throw new Error("Could not decrypt master key");
        }

        const privateSignKey = nacl.secretbox.open(okResponse.encryptedPrivateSignKey, okResponse.encryptedPrivateSignKeyNonce, masterKey);
        if (!privateSignKey) {
            throw new Error("Could not decrypt private sign key using master key");
        }

        const privateDataKey = nacl.secretbox.open(okResponse.encryptedPrivateDataKey, okResponse.encryptedPrivateDataKeyNonce, masterKey);
        if (!privateDataKey) {
            throw new Error("Could not decrypt private data key using master key");
        }

        this.signKeyPair = {
            private: privateSignKey,
            public: okResponse.publicSignKey,
        };
        this.dataKeyPair = {
            private: privateDataKey,
            public: okResponse.publicDataKey,
        };

        console.log("Succesfully authenticated using password", res, {
            privateSignKey,
            publicSignKey: okResponse.publicSignKey,
            privateDataKey,
            publicDataKey: okResponse.publicDataKey,
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

        const res = await this.fetchProto("POST", "/register", RegisterRequestSchema, RegisterResponseSchema, {
            method: {
                case: "password",
                value: {
                    identifier: identifier,
                    password: authPassword,
                    keys: {
                        encryptedMasterKey: encryptedMasterKey,
                        encryptedMasterKeyNonce: encryptedMasterKeyNonce,

                        publicDataKey: userKeypair.publicKey,
                        encryptedPrivateDataKey: userEncryptedPrivateKey,
                        encryptedPrivateDataKeyNonce: userEncryptedPrivateKeyNonce,

                        publicSignKey: userSignKeypair.publicKey,
                        encryptedPrivateSignKey: userEncryptedPrivateSignKey,
                        encryptedPrivateSignKeyNonce: userEncryptedPrivateSignKeyNonce,

                        groupPublicKey: groupKeypair.publicKey,
                        groupEncryptedPrivateKey: groupEncryptedPrivateKey,

                        collectionPublicKey: collectionKeypair.publicKey,
                        collectionEncryptedPrivateKey: collectionEncryptedPrivateKey,
                    },
                },
            },
        });

        if (res.response.case !== "ok") {
            throw new Error("Error during registration: " + res.response.value!.errorCode);
        }

        this.signKeyPair = {
            private: userSignKeypair.secretKey,
            public: userSignKeypair.publicKey,
        };
        this.dataKeyPair = {
            private: userKeypair.secretKey,
            public: userKeypair.publicKey,
        };

        console.log("Register ok", res.response.value.token);
    }
}
