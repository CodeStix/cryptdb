import "dotenv/config";
import {
    // LoginRequestSchema,
    GetChallengeResponse,
    LoginResponse,
    RegisterRequestSchema,
    RegisterResponse,
    ChallengeVerificationStatus,
    deriveKey,
    naclBoxEphemeral,
    LoginRequestSchema,
    ErrorCode,
    LoginResponseSchema,
    GetChallengeResponseSchema,
    GetChallengeRequestSchema,
    RegisterResponseSchema,
    GetCollectionRequestSchema,
    GetCollectionResponseSchema,
    GetGroupRequestSchema,
    GetGroupResponseSchema,
    GetObjectResponseSchema,
    GetObjectRequestSchema,
} from "cryptdb-client";
import { GroupRole, PrismaClient, User } from "../prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import http from "http";
import * as z from "zod";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import console from "console";
import { createValidator } from "@bufbuild/protovalidate";
import { DescMessage, fromBinary, create, MessageShape, MessageInitShape, toBinary } from "@bufbuild/protobuf";
import { ToTuple } from "@prisma/client/runtime/client";

const JWT_EXPIRE_IN = 18 * 60 * 60;

type CryptToken = {
    uid: number;
    c: number; // counter
};

// class ValidationError extends Error {
//     constructor(...args: any[]) {
//         super(...args);
//         this.name = "ValidationError";
//     }
// }

class CryptServer {
    server: http.Server;
    prisma: PrismaClient;
    challengeSignKeyPair!: { publicKey: Uint8Array; secretKey: Uint8Array };
    // passwordSalt!: Buffer;
    jwtSecret!: string;
    publicGroupKeyPair!: { publicKey: Uint8Array; secretKey: Uint8Array };
    publicGroupId!: number;
    // validChallenges = new Map<string, Uint8Array>();

    constructor() {
        this.server = http.createServer(this.handleHttpRequest.bind(this));

        console.log("Connecting to database", process.env.DATABASE_URL);
        const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
        this.prisma = new PrismaClient({
            adapter: adapter,
        });
    }

    public async initialize() {
        // Regenerate challenge sign key pair each time
        this.challengeSignKeyPair = nacl.sign.keyPair();

        // this.publicGroupKeyPair = nacl.box.keyPair();

        // this.challengeSignKeyPair = {
        //     secretKey: Buffer.from(
        //         "b3ef038196ccf34c5f5bef2b70848455dcd5d499068e227a69ba05c43f7efa7acc79c23b712f5d3a4aaa419eed3798ceda8f848ef74150365d386d4b4c863724",
        //         "hex"
        //     ),
        //     publicKey: Buffer.from("cc79c23b712f5d3a4aaa419eed3798ceda8f848ef74150365d386d4b4c863724", "hex"),
        // };

        this.publicGroupKeyPair = {
            secretKey: Buffer.from("6b60a2c2b1bdc5f488af2ef3622256f6796db9fa9f853874e4728819d3e197e9", "hex"),
            publicKey: Buffer.from("0aec6bbab98ea4a5bde9617846b1351d757048abdcd736a8721a2023d3033a17", "hex"),
        };

        // console.log("this.challengeSignKeyPair", {
        //     secretKey: Buffer.from(this.challengeSignKeyPair.secretKey).toString("hex"),
        //     publicKey: Buffer.from(this.challengeSignKeyPair.publicKey).toString("hex"),
        // });

        // console.log("this.publicGroupKeyPair", {
        //     secretKey: Buffer.from(this.publicGroupKeyPair.secretKey).toString("hex"),
        //     publicKey: Buffer.from(this.publicGroupKeyPair.publicKey).toString("hex"),
        // });

        // this.challengeSignKeyPair = await generateSignKeypair();
        // this.publicGroupKeyPair = await generateRsaKeypair();
        // this.passwordSalt = Buffer.from("d0f38af4d1226fcefec23573b6c19094", "hex");
        this.jwtSecret = "d0e58258db29e06243aa24738ff97496";

        let publicGroup = await this.prisma.group.findFirst({
            where: {
                name: "Public",
            },
        });
        if (!publicGroup) {
            // const groupKeyPair = nacl.box.keyPair();

            // console.log("Creating public group", {
            //     secretKey: Buffer.from(groupKeyPair.secretKey).toString("hex"),
            //     publicKey: Buffer.from(groupKeyPair.publicKey).toString("hex"),
            // });

            publicGroup = await this.prisma.group.create({
                data: {
                    name: "Public",
                    // publicKey: Buffer.from(groupKeyPair.publicKey),
                    // exposedPrivateKey: Buffer.from(groupKeyPair.secretKey),
                    canCreateCollections: false,
                },
            });
        }

        this.publicGroupId = Number(publicGroup.id);
        // this.publicGroupKeyPair = {
        //     publicKey: groupKeyPair.publicKey,
        //     secretKey: publicGroup.exposedPrivateKey!,
        // };

        console.log("Starting server");

        const port = 8080;
        this.server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }

    private async parseBodyProtoValidated<Desc extends DescMessage>(req: http.IncomingMessage, schema: Desc): Promise<MessageShape<Desc>> {
        const validator = createValidator();

        const buffer = await this.parseBodyBytes(req);

        console.log("===>", buffer.toString("hex"), buffer.length);

        const msg = fromBinary(schema, buffer);

        const result = validator.validate(schema, msg);
        if (result.kind !== "valid") {
            console.log("Validation failed", result);
            throw new Error("Validation failed");
        }

        return msg;
    }

    private respondWithProto<Desc extends DescMessage>(res: http.ServerResponse, schema: Desc, msg: MessageInitShape<Desc>) {
        const m = create(schema, msg);
        const buffer = Buffer.from(toBinary(schema, m));
        console.log("<===", buffer.toString("hex"), buffer.length);
        res.end(buffer);
    }

    // private async serializeMessage<Desc extends DescMessage>(schema: Desc, msg: MessageInitShape<Desc>) {
    //     const m = create(schema, msg);
    //     return Buffer.from(toBinary(schema, m));
    // }

    // private async parseBodyJsonValidated<T extends z.ZodType>(req: http.IncomingMessage, schema: T): Promise<z.infer<T>> {
    //     const json = await this.parseBodyJson(req);
    //     console.log("json", json);
    //     return await schema.parseAsync(json);
    // }

    private async parseBodyBytes(req: http.IncomingMessage) {
        const contentType = req.headers["content-type"] || "";
        if (!contentType.startsWith("application/octet-stream")) {
            throw new Error("Unsupported Content-Type");
        }

        const chunks = [] as Buffer[];

        const MAX_BODY = 1 * 1024 * 1024;
        let totalSize = 0;

        return new Promise<Buffer>((resolve, reject) => {
            req.on("data", (chunk: Buffer) => {
                totalSize += chunk.length;
                if (totalSize > MAX_BODY) {
                    req.destroy();
                    reject(new Error("Body too large"));
                    return;
                }
                chunks.push(chunk);
            });

            req.on("end", () => {
                if (req.destroyed) return;
                resolve(Buffer.concat(chunks));
            });

            req.on("error", (err) => {
                reject(err);
            });
        });
    }

    // private async parseBodyJson(req: http.IncomingMessage) {
    //     const contentType = req.headers["content-type"] || "";
    //     if (!contentType.startsWith("application/json")) {
    //         throw new Error("Unsupported Content-Type");
    //     }

    //     const MAX_BODY = 1 * 1024 * 1024;

    //     return new Promise<any>((resolve, reject) => {
    //         let chunks = [] as Buffer[];
    //         let received = 0;

    //         req.on("data", (chunk: Buffer) => {
    //             received += chunk.length;

    //             if (received > MAX_BODY) {
    //                 req.destroy();
    //                 reject(new Error("Request too large"));
    //                 return;
    //             }

    //             chunks.push(chunk);
    //         });

    //         req.on("end", () => {
    //             try {
    //                 const str = Buffer.concat(chunks).toString("utf8");
    //                 resolve(JSON.parse(str));
    //             } catch (ex) {
    //                 reject(ex);
    //             }
    //         });

    //         req.on("error", (error) => {
    //             console.error("Request error:", error.message);
    //             reject(new Error("Request error"));
    //         });
    //     });
    // }

    private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
        console.log("Req", req.url);

        try {
            const url = new URL(req.url!, "http://localhost");
            await this.handleUrl(url, req, res);

            // if (typeof bufferRes !== "undefined") {
            //     console.log("Response", bufferRes);
            //     res.end(bufferRes);
            //     // res.end(JSON.stringify(bufferRes));
            // } else {
            //     console.log("Response open-ended");
            // }
        } catch (ex) {
            console.error("Error while handling request", req.url, ex);

            res.writeHead(400);
            res.end();
        }
    }

    private ensureHttpMethod(req: http.IncomingMessage, method: string) {
        if (req.method !== method) {
            throw new Error("Unsupported HTTP method");
        }
    }

    private async handleUrl(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
        switch (url.pathname) {
            case "/get-challenge": {
                this.ensureHttpMethod(req, "GET");
                this.respondWithProto(res, GetChallengeResponseSchema, await this.handleGetChallenge(url, req, res));
                break;
            }

            case "/login": {
                this.ensureHttpMethod(req, "POST");
                this.respondWithProto(res, LoginResponseSchema, await this.handleLogin(url, req, res));
                break;
            }

            case "/register": {
                this.ensureHttpMethod(req, "POST");
                this.respondWithProto(res, RegisterResponseSchema, await this.handleRegister(url, req, res));
                break;
            }

            case "/group": {
                this.ensureHttpMethod(req, "POST");
                this.respondWithProto(res, GetGroupResponseSchema, await this.handleGetGroup(url, req, res));
                break;
            }

            case "/collection": {
                this.ensureHttpMethod(req, "POST");
                this.respondWithProto(res, GetCollectionResponseSchema, await this.handleGetCollection(url, req, res));
                break;
            }

            case "/object": {
                this.ensureHttpMethod(req, "POST");
                this.respondWithProto(res, GetObjectResponseSchema, await this.handleGetObject(url, req, res));
                break;
            }

            default: {
                res.writeHead(404);
                res.end("Not found");
                break;
            }
        }
    }

    private async handleRegister(
        url: URL,
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): Promise<MessageInitShape<typeof RegisterResponseSchema>> {
        const data = await this.parseBodyProtoValidated(req, RegisterRequestSchema);

        console.log("data", data);

        const keys = data.method.value!.keys!;

        let publicGroupEncryptedPrivateKey: Uint8Array;
        try {
            publicGroupEncryptedPrivateKey = naclBoxEphemeral(this.publicGroupKeyPair.secretKey, keys.publicDataKey);
        } catch (ex) {
            console.error("Invalid data public key", data);
            return {
                response: {
                    case: "error",
                    value: {
                        errorCode: ErrorCode.INVALID_PUBLIC_DATA_KEY,
                    },
                },
            };
        }

        if (data.method.case === "password") {
            // ...
        } else if (data.method.case === "publicKey") {
            const clientServerSignedChallenge = data.method.value.clientServerSignedChallenge;
            const publicChallengeKey = data.method.value.publicKey;

            const verificationError = await this.verifyChallenge(clientServerSignedChallenge, publicChallengeKey);
            if (verificationError !== undefined) {
                return {
                    response: {
                        case: "error",
                        value: {
                            errorCode: verificationError,
                        },
                    },
                };
            }
        }

        const user = await this.prisma.$transaction(async (prisma) => {
            const group = await prisma.group.create({
                data: {
                    name: "PersonalGroup",
                    canCreateCollections: false,
                },
            });

            const collection = await prisma.collection.create({
                data: {
                    name: "PersonalCollection",
                },
            });

            const user = await prisma.user.create({
                data: {
                    personalGroupId: group.id,
                    personalCollectionId: collection.id,
                },
                select: {
                    id: true,
                    tokenCounter: true,
                },
            });

            await prisma.groupUserKey.create({
                data: {
                    version: 1,
                    encryptedUsingKeyVersion: 1,
                    encryptedPrivateKey: keys.groupEncryptedPrivateKey as Uint8Array<ArrayBuffer>,
                    publicKey: keys.groupPublicKey as Uint8Array<ArrayBuffer>,
                    groupId: group.id,
                    userId: user.id,
                },
            });
            await prisma.groupUser.create({
                data: {
                    groupId: group.id,
                    userId: user.id,
                    role: "Reader", // Do not allow adding other users to personal group
                },
            });

            await prisma.groupUserKey.create({
                data: {
                    version: 1, // TODO: include public group key version
                    encryptedUsingKeyVersion: 1,
                    encryptedPrivateKey: publicGroupEncryptedPrivateKey as Uint8Array<ArrayBuffer>,
                    publicKey: this.publicGroupKeyPair.publicKey as Uint8Array<ArrayBuffer>,
                    groupId: this.publicGroupId,
                    userId: user.id,
                },
            });
            await prisma.groupUser.create({
                data: {
                    userId: user.id,
                    groupId: this.publicGroupId,
                    role: "Reader", // Do not allow adding other users to public group
                },
            });

            await prisma.groupCollection.create({
                data: {
                    collectionId: collection.id,
                    groupId: group.id,
                    canAdd: true,
                    // canRead: true,
                    canRemove: true,
                    canWrite: true,
                    canModerate: false, // Do not allow sharing the personal collection
                },
            });
            await prisma.groupCollectionKey.create({
                data: {
                    version: 1,
                    encryptedUsingKeyVersion: 1,
                    encryptedPrivateKey: keys.collectionEncryptedPrivateKey as Uint8Array<ArrayBuffer>,
                    publicKey: keys.collectionPublicKey as Uint8Array<ArrayBuffer>,
                    groupId: group.id,
                    collectionId: collection.id,
                },
            });

            if (data.method.case === "password") {
                const password = data.method.value.password;

                const passwordSalt = crypto.getRandomValues(new Uint8Array(32));
                const hashedPassword = await this.hashPassword(password, passwordSalt);

                console.log("identifier", data.method.value.identifier);

                await prisma.userKey.create({
                    data: {
                        // encryptedMasterKey: keys.encryptedMasterKey as Uint8Array<ArrayBuffer>,
                        // encryptedMasterKeyNonce: keys.encryptedMasterKeyNonce as Uint8Array<ArrayBuffer>,
                        version: 1,
                        publicSignKey: keys.publicSignKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateSignKey: keys.encryptedPrivateSignKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateSignKeyNonce: keys.encryptedPrivateSignKeyNonce as Uint8Array<ArrayBuffer>,
                        publicDataKey: keys.publicDataKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateDataKey: keys.encryptedPrivateDataKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateDataKeyNonce: keys.encryptedPrivateDataKeyNonce as Uint8Array<ArrayBuffer>,

                        identifier: data.method.value.identifier,
                        method: "password",
                        passwordHash: hashedPassword as Uint8Array<ArrayBuffer>,
                        passwordSalt: passwordSalt,
                        user: {
                            connect: {
                                id: user.id,
                            },
                        },
                    },
                });
            } else if (data.method.case === "publicKey") {
                await prisma.userKey.create({
                    data: {
                        version: 1,
                        publicSignKey: keys.publicSignKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateSignKey: keys.encryptedPrivateSignKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateSignKeyNonce: keys.encryptedPrivateSignKeyNonce as Uint8Array<ArrayBuffer>,
                        publicDataKey: keys.publicDataKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateDataKey: keys.encryptedPrivateDataKey as Uint8Array<ArrayBuffer>,
                        encryptedPrivateDataKeyNonce: keys.encryptedPrivateDataKeyNonce as Uint8Array<ArrayBuffer>,

                        identifier: data.method.value.identifier,
                        method: "publicKey",
                        publicKey: data.method.value.publicKey as Uint8Array<ArrayBuffer>,
                        // userId: user.id,
                        user: {
                            connect: {
                                id: user.id,
                            },
                        },
                    },
                });
            }

            return user;
        });

        const token = this.createAccessToken(user.id, user.tokenCounter);

        console.log("Registered user", token);

        return {
            response: {
                case: "ok",
                value: {
                    token: token,
                },
            },
        };
    }

    private async hashPassword(password: Uint8Array, salt: Uint8Array) {
        return await deriveKey(password, salt, 32, 100000);
    }

    private async verifyChallenge(clientServerSignedChallenge: Uint8Array, clientPublicKey: Uint8Array): Promise<ErrorCode | undefined> {
        const serverSignedChallenge = nacl.sign.open(clientServerSignedChallenge, clientPublicKey);
        if (!serverSignedChallenge) {
            console.log("Invalid client signature");
            return ErrorCode.INVALID_CLIENT_SIGNATURE;
        }

        const challenge = nacl.sign.open(serverSignedChallenge, this.challengeSignKeyPair.publicKey);
        if (!challenge) {
            console.log("Invalid server signature");
            return ErrorCode.INVALID_SERVER_SIGNATURE;
        }

        const challengeView = new DataView(challenge.buffer);
        const challengeExpireTime = challengeView.getUint32(0);
        const now = new Date().getTime() / 1000;
        if (challengeExpireTime < now) {
            console.log("Challenge expired by", now - challengeExpireTime, "seconds");
            return ErrorCode.CHALLENGE_EXPIRED;
        }

        return undefined;
    }

    private createAccessToken(userId: number | bigint, tokenCounter: number) {
        return jwt.sign(
            {
                uid: Number(userId),
                c: tokenCounter,
            } as CryptToken,
            this.jwtSecret,
            {
                expiresIn: JWT_EXPIRE_IN,
            }
        );
    }

    private async handleLogin(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<MessageInitShape<typeof LoginResponseSchema>> {
        const data = await this.parseBodyProtoValidated(req, LoginRequestSchema);

        const credential = await this.prisma.userKey.findUnique({
            where: {
                identifier: data.method.value!.identifier,
            },
            include: {
                user: {
                    include: {
                        personalGroup: true,
                        personalCollection: true,
                    },
                },
            },
        });
        if (!credential) {
            return {
                response: {
                    case: "error",
                    value: {
                        errorCode: ErrorCode.UNKNOWN_CREDENTIAL,
                    },
                },
            };
        }

        if (credential.method === "publicKey" && data.method.case === "publicKey") {
            const clientServerSignedChallenge = data.method.value.clientServerSignedChallenge;
            const publicKey = credential.publicKey!;

            const verificationError = await this.verifyChallenge(clientServerSignedChallenge, publicKey);
            if (verificationError !== undefined) {
                return {
                    response: {
                        case: "error",
                        value: {
                            errorCode: verificationError,
                        },
                    },
                };
            }
        } else if (credential.method === "password" && data.method.case === "password") {
            const password = data.method.value.password;

            const hashedPassword = new Uint8Array(await this.hashPassword(password, credential.passwordSalt!));

            if (Buffer.compare(credential.passwordHash!, hashedPassword) != 0) {
                return { response: { case: "error", value: { errorCode: ErrorCode.WRONG_PASSWORD } } };
            }
        } else {
            return { response: { case: "error", value: { errorCode: ErrorCode.INVALID_METHOD } } };
        }

        const token = this.createAccessToken(credential.userId, credential.user.tokenCounter);

        return {
            response: {
                case: "ok",
                value: {
                    token: token,

                    // encryptedMasterKey: credential.encryptedMasterKey,
                    // encryptedMasterKeyNonce: credential.encryptedMasterKeyNonce,

                    version: credential.version,

                    publicSignKey: credential.publicSignKey,
                    encryptedPrivateSignKey: credential.encryptedPrivateSignKey,
                    encryptedPrivateSignKeyNonce: credential.encryptedPrivateSignKeyNonce,

                    publicDataKey: credential.publicDataKey,
                    encryptedPrivateDataKey: credential.encryptedPrivateDataKey,
                    encryptedPrivateDataKeyNonce: credential.encryptedPrivateDataKeyNonce,

                    personalCollectionId: credential.user.personalCollectionId,
                    personalGroupId: credential.user.personalGroupId,
                },
            },
        };
    }

    private async ensureUser(req: http.IncomingMessage, url: URL) {
        let token: string | null;
        if (req.method === "POST") {
            const auth = req.headers["authorization"];
            token = auth ? auth.slice("Bearer ".length) : null;
        } else {
            token = url.searchParams.get("token");
        }

        console.log("Found token", token);

        if (!token) {
            throw new Error("Not authenticated");
        }

        const user = await this.getUserForToken(token);
        if (!user) {
            throw new Error("Invalid token");
        }

        return user;
    }

    private async getUserForToken(token: string) {
        let data: CryptToken;
        try {
            data = jwt.verify(token, this.jwtSecret) as CryptToken;
        } catch (ex) {
            console.error("Could not verify jwt", ex);
            return null;
        }

        const user = await this.prisma.user.findUnique({
            where: {
                id: data.uid,
            },
        });
        if (!user) {
            console.error("Could not find user from token", data);
            return null;
        }
        if (user.tokenCounter !== data.c) {
            console.error("Token counter doesn't match", user.tokenCounter, "!=", data.c);
            return null;
        }

        return user;
    }

    private async handleGetChallenge(
        url: URL,
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): Promise<MessageInitShape<typeof GetChallengeResponseSchema>> {
        // const _data = await this.parseBodyProtoValidated(req, GetChallengeRequestSchema);

        const MAX_CHALLENGE_SOLVE_TIME = 15;

        const challengeExpireTime = new Date().getTime() / 1000 + MAX_CHALLENGE_SOLVE_TIME;

        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const dataView = new DataView(challenge.buffer);
        dataView.setUint32(0, challengeExpireTime);

        const signedChallenge = nacl.sign(challenge, this.challengeSignKeyPair.secretKey);

        return {
            response: {
                case: "ok",
                value: {
                    serverSignedChallenge: signedChallenge,
                },
            },
        };
    }

    private async handleGetGroup(
        url: URL,
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): Promise<MessageInitShape<typeof GetGroupResponseSchema>> {
        const data = await this.parseBodyProtoValidated(req, GetGroupRequestSchema);
        const user = await this.ensureUser(req, url);

        const group = await this.prisma.group.findUnique({
            where: {
                id: data.id,
                users: {
                    some: {
                        userId: user.id,
                    },
                },
            },
            select: {
                id: true,
                name: true,
                canCreateCollections: true,
                keys: {
                    where: {
                        userId: user.id,
                    },
                    select: {
                        userId: true,
                        version: true,
                        encryptedUsingKeyVersion: true,
                        encryptedPrivateKey: true,
                        publicKey: true,
                    },
                },
                users: {
                    where: {
                        userId: user.id,
                    },
                    select: {
                        userId: true,
                        role: true,
                    },
                },
            },
        });

        if (!group) {
            return {};
        }

        return {
            group: {
                id: group.id,
                name: group.name,
                canCreateCollections: group.canCreateCollections,
                users: group.users.map((e) => ({
                    role: e.role,
                    userId: e.userId,
                })),
                keys: group.keys.map((e) => ({
                    encryptedPrivateKey: e.encryptedPrivateKey,
                    encryptedUsingKeyVersion: e.encryptedUsingKeyVersion,
                    userId: e.userId,
                    publicKey: e.publicKey,
                    version: e.version,
                })),
            },
        };
    }

    private async handleGetCollection(
        url: URL,
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): Promise<MessageInitShape<typeof GetCollectionResponseSchema>> {
        const data = await this.parseBodyProtoValidated(req, GetCollectionRequestSchema);
        const user = await this.ensureUser(req, url);

        const collection = await this.prisma.collection.findUnique({
            where: {
                id: data.id,
                groups: {
                    some: {
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                    },
                },
            },
            select: {
                id: true,
                name: true,
                groups: {
                    where: {
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                    },
                    select: {
                        canAdd: true,
                        canModerate: true,
                        canRemove: true,
                        canShare: true,
                        canWrite: true,
                        groupId: true,
                        group: {
                            select: {
                                name: true,
                            },
                        },
                    },
                },
                keys: {
                    where: {
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                    },
                    select: {
                        publicKey: true,
                        groupId: true,
                        encryptedPrivateKey: true,
                        encryptedUsingKeyVersion: true,
                        version: true,
                    },
                },
            },
        });

        if (!collection) {
            return {};
        }

        return {
            collection: {
                id: collection.id,
                name: collection.name,
                groups: collection.groups.map((e) => ({
                    canAdd: e.canAdd,
                    canRemove: e.canRemove,
                    canModerate: e.canModerate,
                    canShare: e.canShare,
                    canWrite: e.canWrite,
                    groupId: e.groupId,
                    groupName: e.group.name,
                })),
                keys: collection.keys.map((e) => ({
                    encryptedPrivateKey: e.encryptedPrivateKey,
                    encryptedUsingKeyVersion: e.encryptedUsingKeyVersion,
                    groupId: e.groupId,
                    publicKey: e.publicKey,
                    version: e.version,
                })),
            },
        };
    }

    private async handleGetObject(
        url: URL,
        req: http.IncomingMessage,
        res: http.ServerResponse
    ): Promise<MessageInitShape<typeof GetObjectResponseSchema>> {
        const data = await this.parseBodyProtoValidated(req, GetObjectRequestSchema);
        const user = await this.ensureUser(req, url);

        const object = await this.prisma.object.findUnique({
            where: {
                id: data.id,
                collections: {
                    some: {
                        collection: {
                            groups: {
                                some: {
                                    group: {
                                        users: {
                                            some: {
                                                userId: user.id,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            select: {
                id: true,
                data: true,
                nonce: true,
                publicData: true,
                tableName: true,
                collections: {
                    where: {
                        collection: {
                            groups: {
                                some: {
                                    group: {
                                        users: {
                                            some: {
                                                userId: user.id,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    select: {
                        encryptedObjectKey: true,
                        encryptedUsingKeyVersion: true,
                        collectionId: true,
                    },
                },
            },
        });

        if (!object) {
            return {};
        }

        return {
            object: {
                id: object.id,
                data: object.data,
                nonce: object.nonce,
                publicJson: JSON.stringify(object.publicData),
                keys: object.collections.map((e) => ({
                    collectionId: e.collectionId,
                    encryptedObjectKey: e.encryptedObjectKey,
                    encryptedUsingKeyVersion: e.encryptedUsingKeyVersion,
                })),
            },
        };
    }
}

const server = new CryptServer();

server.initialize().then(() => {
    console.log("server initialized");
});
