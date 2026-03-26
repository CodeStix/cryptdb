import z from "zod";
import {} from "./types";
import nacl from "tweetnacl";
import { decodeBase64, encodeBase64, decodeUTF8, encodeUTF8 } from "tweetnacl-util";
import { naclBoxEphemeral, deriveKey, naclBoxEphemeralOpen } from "./crypto";
import {
    CollectionResponse,
    ErrorCode,
    GetChallengeRequestSchema,
    GetChallengeResponseSchema,
    GetCollectionRequestSchema,
    GetCollectionResponseSchema,
    GetGroupRequestSchema,
    GetGroupResponseSchema,
    GetObjectRequestSchema,
    GetObjectResponseSchema,
    GroupResponse,
    LoginRequest,
    LoginRequestSchema,
    LoginResponse,
    LoginResponseSchema,
    RegisterRequest_RegisterKeyMaterial,
    RegisterRequest_RegisterKeyMaterialSchema,
    RegisterRequestSchema,
    RegisterResponseSchema,
    CreateObjectRequestSchema,
    CreateObjectResponseSchema,
    ObjectValueSchema,
    PrivateObjectDataSchema,
} from "./generated/protocol_pb";
import { create, DescMessage, fromBinary, MessageInitShape, MessageShape, toBinary } from "@bufbuild/protobuf";
import en from "zod/v4/locales/en.js";
import { objectToProtoObject, protoObjectToObject } from "./util";
import { walk as canonicalJsonWalk } from "canonical-json";

export * from "./types";
export * from "./crypto";
export * from "./util";
export * from "./generated/protocol_pb";

const AUTH_SALT_PREFIX = "ap";
const KEY_SALT_PREFIX = "mk";

type KeyPair = {
    version: number;
    private: Uint8Array;
    public: Uint8Array;
};

// type GroupRoster = {
//     groupId:   bigint
//     epoch:     number
//     members: {
//       userId:    bigint
//       publicKey: Uint8Array  // bind identity to their current public key
//       role:      string
//     }[]  // sorted by userId ascending
//   }

export class Group {
    readonly id: GroupId;

    private client: CryptClient;
    private data!: GroupResponse;
    private cachedKeys = new Map<number, KeyPair>();

    constructor(client: CryptClient, id: GroupId) {
        this.client = client;
        this.id = id;
    }

    hasKey(version: number) {
        return this.data.keys.some((e) => e.version === version);
    }

    generateRoster() {
        // this.data.
    }

    // setData(data: GroupResponse) {
    //     this.data = data;
    // }

    async refresh() {
        const res = await this.client.fetchProto("GET", "/group", GetGroupRequestSchema, GetGroupResponseSchema, {
            id: BigInt(this.id),
        });

        if (!res.group) {
            console.error("Refresh failed, empty response");
            return;
        }

        this.data = res.group;
    }

    async verify() {
        type ServerGroupLogEntry = {
            sequenceNumber: number;
            payload:
                | {
                      type: "group-created";
                      groupId: number;
                      creatorId: number;
                      creatorPublicKey: Uint8Array;
                  }
                | {
                      type: "user-added";
                      groupId: number;
                      userId: number;
                      publicKey: Uint8Array;
                  }
                | {
                      type: "user-removed";
                      groupId: number;
                      userId: number;
                  }
                | {
                      type: "rotate-key";
                      groupId: number;
                      newPublicKey: Uint8Array;
                  };
            prevHash: Uint8Array;
            hash: Uint8Array; // hash(prevHash || payload || sequenceNumber)
            signature: Uint8Array; // sign(hash)
        };

        type LocalGroupState = {
            // Constructed from ServerGroupLogEntry[] blockchain (the whole chain is used)
            groupState: {
                id: number;
                keyVersion: number;
                publicKey: string;
                members: { userId: number; publicKey: number; role: any }[];
            };
            lastThrustedStateNum: number;
            lastThrustedStateHash: Uint8Array;
        };
    }

    async getKey(version: number): Promise<KeyPair | null> {
        const cachedKey = this.cachedKeys.get(version);
        if (cachedKey) {
            return cachedKey;
        }

        const userKeyPair = await this.client.getKey();
        if (!userKeyPair) {
            console.log("User key pair unavailable");
            return null;
        }

        let encryptedKey = this.data.keys.find((e) => e.version === version); //  && e.encryptedUsingKeyVersion === userKeyPair.version
        if (!encryptedKey) {
            await this.refresh();

            encryptedKey = this.data.keys.find((e) => e.version === version); //  && e.encryptedUsingKeyVersion === userKeyPair.version
            if (!encryptedKey) {
                console.error("Key with version not found", version, userKeyPair.version, this.data.keys);
                return null;
            }
        }

        const groupPublicKey = encryptedKey.publicKey;
        const groupPrivateKey = naclBoxEphemeralOpen(encryptedKey.encryptedPrivateKey, userKeyPair.public, userKeyPair.private);
        if (!groupPrivateKey) {
            console.error("Could not decrypt group key", version, encryptedKey);
            return null;
        }

        const keyPair: KeyPair = {
            version: version,
            public: groupPublicKey,
            private: groupPrivateKey,
        };

        this.cachedKeys.set(version, keyPair);

        return keyPair;
    }

    getNewestKeyVersion() {
        return Math.max(...this.data.keys.map((e) => e.version));
    }
}

export class Collection {
    readonly id: CollectionId;

    private client: CryptClient;
    private data!: CollectionResponse;
    private cachedKeys = new Map<number, KeyPair>();

    constructor(client: CryptClient, id: CollectionId) {
        this.client = client;
        this.id = id;
    }

    getNewestKeyVersion() {
        return Math.max(...this.data.keys.map((e) => e.version));
    }

    hasKey(version: number) {
        return this.data.keys.some((e) => e.version === version);
    }

    // setData(data: CollectionResponse) {
    //     this.data = data;
    // }

    async refresh() {
        const res = await this.client.fetchProto("GET", "/collection", GetCollectionRequestSchema, GetCollectionResponseSchema, {
            id: BigInt(this.id),
        });

        if (!res.collection) {
            console.error("Refresh failed, empty response");
            return;
        }

        this.data = res.collection;
    }

    async getNewestKey(): Promise<KeyPair | null> {
        return await this.getKey(this.getNewestKeyVersion());
    }

    // async rotateKey() {
    //     this.getNewestKeyVersion();

    //     // TODO: verify this.data.groups using signature

    //     const collectionKeyPair = nacl.box.keyPair();

    //     for (const group of this.data.groups) {
    //         group.$unknown;
    //     }

    //     const collectionEncryptedPrivateKey = naclBoxEphemeral(collectionKeyPair.secretKey, groupKeyPair.publicKey);
    // }

    async getKey(version: number): Promise<KeyPair | null> {
        const cachedKey = this.cachedKeys.get(version);
        if (cachedKey) {
            return cachedKey;
        }

        let encryptedKey = this.data.keys.find((e) => e.version === version);
        if (!encryptedKey) {
            await this.refresh();

            encryptedKey = this.data.keys.find((e) => e.version === version);
            if (!encryptedKey) {
                console.log("No encrypted collection key found", this.data);
                return null;
            }
        }

        const group = await this.client.getGroup(encryptedKey.groupId);
        if (!group) {
            console.log("Collection group not found", this.data, encryptedKey);
            return null;
        }

        const groupKeyPair = await group.getKey(encryptedKey.encryptedUsingKeyVersion);
        if (!groupKeyPair) {
            console.log("Could not find group keypair", this.data, encryptedKey);
            return null;
        }

        const collectionPublicKey = encryptedKey.publicKey;
        const collectionPrivateKey = naclBoxEphemeralOpen(encryptedKey.encryptedPrivateKey, groupKeyPair.public, groupKeyPair.private);
        if (!collectionPrivateKey) {
            console.error("Could not decrypt collection key", this.data, encryptedKey);
            return null;
        }

        const keyPair: KeyPair = {
            version: version,
            public: collectionPublicKey,
            private: collectionPrivateKey,
        };

        this.cachedKeys.set(version, keyPair);

        return keyPair;
    }

    async createObjectRaw(tableName: string, privateData: any, publicData: any): Promise<ObjectId> {
        const protoObj = objectToProtoObject(publicData);

        const key = nacl.randomBytes(nacl.secretbox.keyLength);
        const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

        while (true) {
            const encryptionKey = await this.getNewestKey();
            if (!encryptionKey) {
                throw new Error("Could not get encryption key to create object");
            }

            const encryptedKey = naclBoxEphemeral(key, encryptionKey.public);

            const data = toBinary(
                PrivateObjectDataSchema,
                create(PrivateObjectDataSchema, {
                    privateData: objectToProtoObject(privateData),
                    collections: [
                        {
                            collectionId: BigInt(this.id),
                            keyVersion: encryptionKey.version,
                        },
                    ],
                })
            );
            const encryptedData = nacl.secretbox(data, nonce, key);

            console.log("encryptedKey", encryptedKey.length);

            const res = await this.client.fetchProto("POST", "/object", CreateObjectRequestSchema, CreateObjectResponseSchema, {
                collectionId: BigInt(this.id),
                data: encryptedData,
                publicData: protoObj,
                encryptedObjectKey: encryptedKey,
                encryptedUsingKeyVersion: encryptionKey.version,
                nonce: nonce,
                tableName: tableName,
            });

            if (res.response.case !== "ok") {
                if (res.response.value!.errorCode === ErrorCode.PRIVATE_DATA_OUTDATED_KEY) {
                    console.warn("Refresing collection because key out of date");
                    // Make sure the newest keys are available
                    await this.refresh();
                    continue;
                }

                throw new Error("Could not create object: " + res.response.value!.errorCode);
            }

            return res.response.value.id;
        }
    }

    async rotateObjectKey(tableName: string, id: ObjectId) {
        const res = await this.client.fetchProto("GET", "/object", GetObjectRequestSchema, GetObjectResponseSchema, {
            id: BigInt(id),
            tableName: tableName,
        });

        res.object?.data;
    }
}

export class CryptClient {
    appName: string;
    url: string;
    token: string | undefined;
    cachedGroups = new Map<GroupId, Group>();
    cachedCollections = new Map<CollectionId, Collection>();

    signKeyPair?: { public: Uint8Array; private: Uint8Array };
    dataKeyPair?: { public: Uint8Array; private: Uint8Array };
    personalCollectionId?: CollectionId;
    personalGroupId?: GroupId;
    keyVersion?: number;

    constructor(appName: string, url: string) {
        this.appName = appName;
        this.url = url;
        this.token = undefined;
    }

    public async fetchProto<Req extends DescMessage, Res extends DescMessage>(
        method: string,
        path: string,
        requestSchema: Req,
        responseSchema: Res,
        body: MessageInitShape<Req>
    ): Promise<MessageShape<Res>> {
        let res: Response;

        const reqMsg = create(requestSchema, body);
        const reqBytes = toBinary(requestSchema, reqMsg);

        const headers: HeadersInit = {};
        if (this.token) {
            headers["Authorization"] = "Bearer " + this.token;
        }

        const params = new URLSearchParams();

        if (method === "GET") {
            params.set("data", encodeBase64(reqBytes));
        }

        const url = this.url + path + (params.size > 0 ? "?" + params.toString() : "");

        if (method === "GET") {
            console.log("===>", method, url);

            res = await fetch(url, {
                method: "GET",
                headers: headers,
            });
        } else {
            console.log("===>", method, url, encodeBase64(reqBytes));

            headers["Content-Type"] = "application/octet-stream";

            res = await fetch(url, {
                method: method,
                headers: headers,
                body: reqBytes,
            });
        }

        if (!res.ok) {
            throw new Error("Could not fetch " + path + ": " + res.status);
        }

        const resBytes = new Uint8Array(await res.arrayBuffer());
        const resMsg = fromBinary(responseSchema, resBytes);

        console.log("<===", method, this.url + path, encodeBase64(resBytes));

        return resMsg;
    }

    public async getKey(): Promise<KeyPair | null> {
        if (!this.dataKeyPair) {
            return null;
        }

        return {
            version: this.keyVersion!,
            private: this.dataKeyPair.private,
            public: this.dataKeyPair.public,
        };
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
        this.keyVersion = okResponse.version;
        this.personalCollectionId = okResponse.personalCollectionId;
        this.personalGroupId = okResponse.personalGroupId;

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

        // return {
        //     personalCollectionId: okResponse.personalCollectionId,
        //     personalGroupId: okResponse.personalGroupId,
        // };
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

        this.keyVersion = 1;
        this.personalCollectionId = res.response.value.personalCollectionId;
        this.personalGroupId = res.response.value.personalGroupId;

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

    async getGroup(id: GroupId): Promise<Group | null> {
        const cachedGroup = this.cachedGroups.get(id);
        if (cachedGroup) {
            return cachedGroup;
        }

        const newGroup = new Group(this, id);
        this.cachedGroups.set(id, newGroup);
        await newGroup.refresh();
        return newGroup;
    }

    async getCollection(id: CollectionId) {
        const cachedCollection = this.cachedCollections.get(id);
        if (cachedCollection) {
            return cachedCollection;
        }

        const collection = new Collection(this, id);
        this.cachedCollections.set(id, collection);
        await collection.refresh();
        return collection;
    }

    // async getCollections(ids: CollectionId[]) {
    //     const res = await this.fetchProto("GET", "/collection", GetCollectionRequestSchema, GetCollectionResponseSchema, {
    //         ids: ids.map((e) => BigInt(e)),
    //     });

    //     const collections: Collection[] = [];
    //     for (const collectionRes of res.collections) {
    //         const collection = new Collection(this, collectionRes);
    //         this.cachedCollections.set(collectionRes.id, collection);
    //         collections.push(collection);
    //     }

    //     return collections;
    // }

    async getObjectRaw(tableName: string, id: ObjectId) {
        const res = await this.fetchProto("GET", "/object", GetObjectRequestSchema, GetObjectResponseSchema, {
            id: BigInt(id),
            tableName: tableName,
        });

        if (!res.object) {
            return null;
        }

        const encryptedKey = res.object.keys[0];
        if (!encryptedKey) {
            console.error("Object encryptedKey is empty");
            return null;
        }

        const collection = await this.getCollection(encryptedKey.collectionId);
        if (!collection) {
            console.error("Collection for object not found", id, encryptedKey);
            return;
        }

        const keyPair = await collection.getKey(encryptedKey.encryptedUsingKeyVersion);
        if (!keyPair) {
            console.error("Keypair for object not found", id, encryptedKey, collection);
            return;
        }

        const objectKey = naclBoxEphemeralOpen(encryptedKey.encryptedObjectKey, keyPair.public, keyPair.private);
        if (!objectKey) {
            console.error("Could not decrypt object key", id, encryptedKey, collection);
            return;
        }

        const privateDataBytes = nacl.secretbox.open(res.object.data, res.object.nonce, objectKey);
        if (!privateDataBytes) {
            console.error("Could not decrypt object data");
            return;
        }

        const privateData = fromBinary(PrivateObjectDataSchema, privateDataBytes);

        const publicData = protoObjectToObject(res.object.publicData);
        // TODO: verify private data

        return { publicData, privateData };
    }
}

export type CollectionId = number | bigint;
export type GroupId = number | bigint;
export type ObjectId = number | bigint;
