import z from "zod";
import {} from "./types";
import nacl from "tweetnacl";
import { decodeBase64, encodeBase64, decodeUTF8, encodeUTF8 } from "tweetnacl-util";
import { naclBoxEphemeral, deriveKey } from "./crypto";
import {
    Collection,
    ErrorCode,
    GetChallengeRequestSchema,
    GetChallengeResponseSchema,
    GetCollectionRequestSchema,
    GetCollectionResponseSchema,
    GetGroupRequestSchema,
    GetGroupResponseSchema,
    GetObjectRequestSchema,
    GetObjectResponseSchema,
    Group,
    LoginRequest,
    LoginRequestSchema,
    LoginResponse,
    LoginResponseSchema,
    RegisterRequest_RegisterKeyMaterial,
    RegisterRequest_RegisterKeyMaterialSchema,
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
    token: string | undefined;
    cachedGroups = new Map<GroupId, Group>();
    cachedCollections = new Map<CollectionId, Collection>();

    signKeyPair?: { public: Uint8Array; private: Uint8Array };
    dataKeyPair?: { public: Uint8Array; private: Uint8Array };

    constructor(appName: string, url: string) {
        this.appName = appName;
        this.url = url;
        this.token = undefined;
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
            res = await fetch(this.url + path + (this.token ? "?token=" + encodeURIComponent(this.token) : ""), {
                method: "GET",
            });
        } else {
            const msg = create(requestSchema, body);

            const headers: HeadersInit = {};
            headers["Content-Type"] = "application/octet-stream";
            if (this.token) headers["Authorization"] = "Bearer " + this.token;

            res = await fetch(this.url + path, {
                method: method,
                headers: headers,
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

    async fetchChallenge() {
        const challenge = await this.fetchProto("GET", "/challenge", GetChallengeRequestSchema, GetChallengeResponseSchema, {});
        if (challenge.response.case !== "ok") {
            throw new Error("Could not fetch challenge");
        }
        return challenge.response.value.serverSignedChallenge;
    }

    async fetchChallengeAndSign(authPassword: Uint8Array) {
        const challengeSignKeypair = nacl.sign.keyPair.fromSeed(authPassword);

        const serverSignedChallenge = await this.fetchChallenge();

        const clientServerSignedChallenge = nacl.sign(serverSignedChallenge, challengeSignKeypair.secretKey);

        return { clientServerSignedChallenge, publicKey: challengeSignKeypair.publicKey };
    }

    async loginUsingPassword(identifier: string, password: string) {
        const authenticationSalt = this.getIdentifierDerivedSalt(identifier, AUTH_SALT_PREFIX);
        const masterKeySalt = this.getIdentifierDerivedSalt(identifier, KEY_SALT_PREFIX);

        console.log({ authenticationSalt, masterKeySalt: masterKeySalt });

        const passwordBytes = decodeUTF8(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt, nacl.sign.seedLength);

        const { clientServerSignedChallenge } = await this.fetchChallengeAndSign(authPassword);

        const res = await this.fetchProto("POST", "/login", LoginRequestSchema, LoginResponseSchema, {
            method: {
                case: "publicKey",
                value: {
                    identifier: identifier,
                    clientServerSignedChallenge: clientServerSignedChallenge,
                },
            },
        });

        if (res.response.case != "ok") {
            throw new Error("Could not log in using password: " + ErrorCode[res.response.value!.errorCode]);
        }

        const okResponse = res.response.value!;

        // const masterKey = nacl.secretbox.open(okResponse.encryptedMasterKey, okResponse.encryptedMasterKeyNonce, masterKey);
        // if (!masterKey) {
        //     throw new Error("Could not decrypt master key");
        // }

        const masterKey = await deriveKey(passwordBytes, masterKeySalt, nacl.secretbox.keyLength);

        const privateSignKey = nacl.secretbox.open(okResponse.encryptedPrivateSignKey, okResponse.encryptedPrivateSignKeyNonce, masterKey);
        if (!privateSignKey) {
            throw new Error("Could not decrypt private sign key using master key");
        }

        const privateDataKey = nacl.secretbox.open(okResponse.encryptedPrivateDataKey, okResponse.encryptedPrivateDataKeyNonce, masterKey);
        if (!privateDataKey) {
            throw new Error("Could not decrypt private data key using master key");
        }

        this.token = okResponse.token;

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

        return {
            personalCollectionId: okResponse.personalCollectionId,
            personalGroupId: okResponse.personalGroupId,
        };
    }

    generateNewCredential(masterKey: Uint8Array): {
        userSignKeyPair: nacl.SignKeyPair;
        userKeyPair: nacl.BoxKeyPair;
        keys: MessageInitShape<typeof RegisterRequest_RegisterKeyMaterialSchema>;
    } {
        // const masterKey = nacl.randomBytes(nacl.secretbox.keyLength);

        // const encryptedMasterKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        // const encryptedMasterKey = nacl.secretbox(masterKey, encryptedMasterKeyNonce, password);

        const userKeyPair = nacl.box.keyPair();
        const userEncryptedPrivateKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const userEncryptedPrivateKey = nacl.secretbox(userKeyPair.secretKey, userEncryptedPrivateKeyNonce, masterKey);

        const userSignKeyPair = nacl.sign.keyPair();
        const userEncryptedPrivateSignKeyNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
        const userEncryptedPrivateSignKey = nacl.secretbox(userSignKeyPair.secretKey, userEncryptedPrivateSignKeyNonce, masterKey);

        const groupKeyPair = nacl.box.keyPair();
        const groupEncryptedPrivateKey = naclBoxEphemeral(groupKeyPair.secretKey, userKeyPair.publicKey);

        const collectionKeyPair = nacl.box.keyPair();
        const collectionEncryptedPrivateKey = naclBoxEphemeral(collectionKeyPair.secretKey, groupKeyPair.publicKey);

        return {
            userKeyPair: userKeyPair,
            userSignKeyPair: userSignKeyPair,
            keys: {
                // encryptedMasterKey: encryptedMasterKey,
                // encryptedMasterKeyNonce: encryptedMasterKeyNonce,

                publicDataKey: userKeyPair.publicKey,

                encryptedPrivateDataKey: userEncryptedPrivateKey,
                encryptedPrivateDataKeyNonce: userEncryptedPrivateKeyNonce,

                publicSignKey: userSignKeyPair.publicKey,
                encryptedPrivateSignKey: userEncryptedPrivateSignKey,
                encryptedPrivateSignKeyNonce: userEncryptedPrivateSignKeyNonce,

                groupPublicKey: groupKeyPair.publicKey,
                groupEncryptedPrivateKey: groupEncryptedPrivateKey,

                collectionPublicKey: collectionKeyPair.publicKey,
                collectionEncryptedPrivateKey: collectionEncryptedPrivateKey,
            },
        };
    }

    async registerUsingPassword(identifier: string, password: string) {
        const authenticationSalt = this.getIdentifierDerivedSalt(identifier, AUTH_SALT_PREFIX);
        const masterKeySalt = this.getIdentifierDerivedSalt(identifier, KEY_SALT_PREFIX);

        const passwordBytes = decodeUTF8(password);
        const authPassword = await deriveKey(passwordBytes, authenticationSalt, nacl.sign.seedLength);
        const masterKey = await deriveKey(passwordBytes, masterKeySalt, nacl.secretbox.keyLength);

        const { userKeyPair, userSignKeyPair, keys } = this.generateNewCredential(masterKey);
        const { clientServerSignedChallenge, publicKey } = await this.fetchChallengeAndSign(authPassword);

        const res = await this.fetchProto("POST", "/register", RegisterRequestSchema, RegisterResponseSchema, {
            method: {
                case: "publicKey",
                value: {
                    identifier: identifier,
                    clientServerSignedChallenge: clientServerSignedChallenge,
                    publicKey: publicKey,
                    keys: keys,
                },
            },
        });

        if (res.response.case !== "ok") {
            throw new Error("Error during registration: " + res.response.value!.errorCode);
        }

        this.signKeyPair = {
            private: userSignKeyPair.secretKey,
            public: userSignKeyPair.publicKey,
        };
        this.dataKeyPair = {
            private: userKeyPair.secretKey,
            public: userKeyPair.publicKey,
        };

        this.token = res.response.value.token;

        console.log("Register ok", res.response.value.token);
    }

    async getCollection(id: CollectionId, requireKeyVersion?: number) {
        const cachedCollection = this.cachedCollections.get(id);
        if (cachedCollection && (requireKeyVersion === undefined || cachedCollection.keys.some((e) => e.version === requireKeyVersion))) {
            return cachedCollection;
        }

        const res = await this.fetchProto("POST", "/collection", GetCollectionRequestSchema, GetCollectionResponseSchema, {
            id: BigInt(id),
        });
        if (!res.collection) {
            return null;
        }

        this.cachedCollections.set(id, res.collection);

        if (requireKeyVersion !== undefined && !res.collection.keys.some((e) => e.version === requireKeyVersion)) {
            console.error(
                "The requested key version doesn't exist anymore for collection. This shouldn't happen and indicates a wrong deletion of keys on the server.",
                id,
                requireKeyVersion
            );
            return null;
        }

        return res.collection;
    }

    async getGroup(id: GroupId, requireKeyVersion?: number): Promise<Group | null> {
        const cachedGroup = this.cachedGroups.get(id);
        if (cachedGroup && (requireKeyVersion === undefined || cachedGroup.keys.some((e) => e.version === requireKeyVersion))) {
            return cachedGroup;
        }

        const res = await this.fetchProto("POST", "/group", GetGroupRequestSchema, GetGroupResponseSchema, {
            id: BigInt(id),
        });
        if (!res.group) {
            return null;
        }

        this.cachedGroups.set(id, res.group);

        if (requireKeyVersion !== undefined && !res.group.keys.some((e) => e.version === requireKeyVersion)) {
            console.error(
                "The requested key version doesn't exist anymore for group. This shouldn't happen and indicates a wrong deletion of keys on the server.",
                id,
                requireKeyVersion
            );
            return null;
        }

        return res.group;
    }

    async getObject(id: ObjectId) {
        const res = await this.fetchProto("POST", "/object", GetObjectRequestSchema, GetObjectResponseSchema, {
            id: BigInt(id),
        });

        return res.object;
    }
}

export type CollectionId = number | bigint;
export type GroupId = number | bigint;
export type ObjectId = number | bigint;
