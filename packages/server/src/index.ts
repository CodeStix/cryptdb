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
} from "cryptdb-client";
import { PrismaClient, User } from "../prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import http from "http";
import * as z from "zod";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import console from "console";
import { createValidator } from "@bufbuild/protovalidate";
import { DescMessage, fromBinary, create, MessageShape, MessageInitShape, toBinary } from "@bufbuild/protobuf";

const JWT_EXPIRE_IN = 18 * 60 * 60;

type CryptToken = {
    uid: number;
    c: number; // counter
};

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

        // this.publicGroupKeyPair = {
        //     secretKey: Buffer.from("6b60a2c2b1bdc5f488af2ef3622256f6796db9fa9f853874e4728819d3e197e9", "hex"),
        //     publicKey: Buffer.from("0aec6bbab98ea4a5bde9617846b1351d757048abdcd736a8721a2023d3033a17", "hex"),
        // };

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
                exposedPrivateKey: {
                    not: null,
                },
            },
        });
        if (!publicGroup) {
            const groupKeyPair = nacl.box.keyPair();

            console.log("Creating public group", {
                secretKey: Buffer.from(groupKeyPair.secretKey).toString("hex"),
                publicKey: Buffer.from(groupKeyPair.publicKey).toString("hex"),
            });

            publicGroup = await this.prisma.group.create({
                data: {
                    name: "Public",
                    publicKey: Buffer.from(groupKeyPair.publicKey),
                    exposedPrivateKey: Buffer.from(groupKeyPair.secretKey),
                    canCreateCollections: false,
                },
            });
        }

        this.publicGroupId = Number(publicGroup.id);
        this.publicGroupKeyPair = {
            publicKey: publicGroup.publicKey,
            secretKey: publicGroup.exposedPrivateKey!,
        };

        console.log("Starting server");

        const port = 8080;
        this.server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }

    private async parseBodyProtoValidated<Desc extends DescMessage>(req: http.IncomingMessage, schema: Desc): Promise<MessageShape<Desc>> {
        const validator = createValidator();

        const buffer = await this.parseBodyBytes(req);

        const msg = fromBinary(schema, buffer);

        const result = validator.validate(schema, msg);
        if (result.kind !== "valid") {
            console.log("Validation failed", result);
            throw new Error("Validation failed");
        }

        return msg;
    }

    private async serializeMessage<Desc extends DescMessage>(schema: Desc, msg: MessageInitShape<Desc>) {
        const m = create(schema, msg);
        return Buffer.from(toBinary(schema, m));
    }

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
            const bufferRes = await this.handleUrl(url, req, res);

            if (typeof bufferRes !== "undefined") {
                console.log("Response", bufferRes);
                res.end(bufferRes);
                // res.end(JSON.stringify(bufferRes));
            } else {
                console.log("Response open-ended");
            }
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

    private async handleUrl(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<Buffer> {
        switch (url.pathname) {
            case "/get-challenge": {
                this.ensureHttpMethod(req, "GET");

                return this.serializeMessage(LoginRequestSchema, await this.handleGetChallenge(url, req, res));
            }

            case "/login": {
                this.ensureHttpMethod(req, "POST");
                return await this.handleLogin(url, req, res);
            }

            case "/register": {
                this.ensureHttpMethod(req, "POST");
                return await this.handleRegister(url, req, res);
            }

            default: {
                res.writeHead(404);
                res.end("Not found");
                break;
            }
        }
    }

    private async handleRegister(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<RegisterResponse> {
        const json = await this.parseBodyJsonValidated(req, RegisterRequestSchema);

        const encryptedMasterKey = Buffer.from(json.encryptedMasterKey, "base64");
        const encryptedMasterKeyNonce = Buffer.from(json.encryptedMasterKeyNonce, "base64");
        const publicSignKey = Buffer.from(json.publicSignKey, "base64");
        const encryptedPrivateSignKey = Buffer.from(json.encryptedPrivateSignKey, "base64");
        const encryptedPrivateSignKeyNonce = Buffer.from(json.encryptedPrivateSignKeyNonce, "base64");
        const publicDataKey = Buffer.from(json.publicDataKey, "base64");
        const encryptedPrivateDataKey = Buffer.from(json.encryptedPrivateDataKey, "base64");
        const encryptedPrivateDataKeyNonce = Buffer.from(json.encryptedPrivateDataKeyNonce, "base64");
        const groupPublicKey = Buffer.from(json.groupPublicKey, "base64");
        const groupEncryptedPrivateKey = Buffer.from(json.groupEncryptedPrivateKey, "base64");
        const collectionPublicKey = Buffer.from(json.collectionPublicKey, "base64");
        const collectionEncryptedPrivateKey = Buffer.from(json.collectionEncryptedPrivateKey, "base64");

        let publicGroupEncryptedPrivateKey: Uint8Array;
        try {
            publicGroupEncryptedPrivateKey = naclBoxEphemeral(this.publicGroupKeyPair.secretKey, publicDataKey);
        } catch (ex) {
            console.error("Invalid data public key", json);
            return { status: "invalid-public-data-key" };
        }

        if (json.method === "password") {
            // ...
        } else if (json.method === "publickey") {
            const clientServerSignedChallenge = Buffer.from(json.clientServerSignedChallenge, "base64");
            const publicChallengeKey = Buffer.from(json.publicKey, "base64");

            const verificationStatus = await this.verifyChallenge(clientServerSignedChallenge, publicChallengeKey);
            if (verificationStatus !== "ok") {
                return { status: verificationStatus };
            }
        }

        const user = await this.prisma.$transaction(async (prisma) => {
            const group = await prisma.group.create({
                data: {
                    publicKey: groupPublicKey,
                    name: "PersonalGroup",
                    canCreateCollections: false,
                },
            });

            const collection = await prisma.collection.create({
                data: {
                    name: "PersonalCollection",
                    publicKey: collectionPublicKey,
                },
            });

            const user = await prisma.user.create({
                data: {
                    publicSignKey: publicSignKey,
                    encryptedPrivateSignKey: encryptedPrivateSignKey,
                    encryptedPrivateSignKeyNonce: encryptedPrivateSignKeyNonce,
                    publicDataKey: publicDataKey,
                    encryptedPrivateDataKey: encryptedPrivateDataKey,
                    encryptedPrivateDataKeyNonce: encryptedPrivateDataKeyNonce,

                    personalGroupId: group.id,
                    personalCollectionId: collection.id,
                },
                select: {
                    id: true,
                    tokenCounter: true,
                },
            });

            await prisma.groupUser.create({
                data: {
                    encryptedGroupPrivateKey: groupEncryptedPrivateKey,
                    groupId: group.id,
                    userId: user.id,
                    role: "Reader", // Do not allow adding other users to personal group
                },
            });

            await prisma.groupUser.create({
                data: {
                    encryptedGroupPrivateKey: Buffer.from(publicGroupEncryptedPrivateKey),
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
                    encryptedCollectionPrivateKey: collectionEncryptedPrivateKey,
                },
            });

            if (json.method === "password") {
                const password = Buffer.from(json.password, "base64");

                const passwordSalt = crypto.getRandomValues(new Uint8Array(32));
                const hashedPassword = Buffer.from(await this.hashPassword(password, passwordSalt));

                await prisma.userKey.create({
                    data: {
                        encryptedMasterKey: encryptedMasterKey,
                        encryptedMasterKeyNonce: encryptedMasterKeyNonce,
                        identifier: json.identifier,
                        method: json.method,
                        passwordHash: hashedPassword,
                        passwordSalt: passwordSalt,
                        userId: user.id,
                    },
                });
            } else if (json.method === "publickey") {
                const publicKey = Buffer.from(json.publicKey, "base64");
                await prisma.userKey.create({
                    data: {
                        encryptedMasterKey: encryptedMasterKey,
                        encryptedMasterKeyNonce: encryptedMasterKeyNonce,
                        identifier: json.identifier,
                        method: json.method,
                        publicKey: publicKey,
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
            status: "ok",
            token: token,
        };
    }

    private async hashPassword(password: Uint8Array, salt: Uint8Array) {
        return await deriveKey(password, salt, 32, 100000);
    }

    private async verifyChallenge(clientServerSignedChallenge: Uint8Array, clientPublicKey: Uint8Array): Promise<ChallengeVerificationStatus> {
        const serverSignedChallenge = nacl.sign.open(clientServerSignedChallenge, clientPublicKey);
        if (!serverSignedChallenge) {
            console.log("Invalid client signature");
            return "invalid-client-signature";
        }

        const challenge = nacl.sign.open(serverSignedChallenge, this.challengeSignKeyPair.publicKey);
        if (!challenge) {
            console.log("Invalid server signature");
            return "invalid-server-signature";
        }

        const challengeView = new DataView(challenge.buffer);
        const challengeExpireTime = challengeView.getUint32(0);
        const now = new Date().getTime() / 1000;
        if (challengeExpireTime < now) {
            console.log("Challenge expired by", now - challengeExpireTime, "seconds");
            return "challenge-expired";
        }

        return "ok";
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

    private async handleLogin(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<LoginResponse> {
        const json = await this.parseBodyJsonValidated(req, LoginRequestSchema);

        const credential = await this.prisma.userKey.findUnique({
            where: {
                identifier: json.identifier,
            },
            include: {
                user: true,
            },
        });
        if (!credential) {
            return { status: "unknown-credential" };
        }

        if (credential.method === "publickey" && json.method === "publickey") {
            const clientServerSignedChallenge = Buffer.from(json.clientServerSignedChallenge, "base64");
            const publicKey = credential.publicKey!;

            const verificationStatus = await this.verifyChallenge(clientServerSignedChallenge, publicKey);
            if (verificationStatus !== "ok") {
                return { status: verificationStatus };
            }
        } else if (credential.method === "password" && json.method === "password") {
            const password = Buffer.from(json.password, "base64");

            const hashedPassword = new Uint8Array(await this.hashPassword(password, credential.passwordSalt!));

            if (Buffer.compare(credential.passwordHash!, hashedPassword) != 0) {
                return { status: "wrong-password" };
            }
        } else {
            return { status: "invalid-method" };
        }

        const token = this.createAccessToken(credential.userId, credential.user.tokenCounter);

        return {
            status: "ok",
            token: token,

            encryptedMasterKey: Buffer.from(credential.encryptedMasterKey).toString("base64"),
            encryptedMasterKeyNonce: Buffer.from(credential.encryptedMasterKeyNonce).toString("base64"),

            publicSignKey: Buffer.from(credential.user.publicSignKey).toString("base64"),
            encryptedPrivateSignKey: Buffer.from(credential.user.encryptedPrivateSignKey).toString("base64"),
            encryptedPrivateSignKeyNonce: Buffer.from(credential.user.encryptedPrivateSignKeyNonce).toString("base64"),

            publicDataKey: Buffer.from(credential.user.publicDataKey).toString("base64"),
            encryptedPrivateDataKey: Buffer.from(credential.user.encryptedPrivateDataKey).toString("base64"),
            encryptedPrivateDataKeyNonce: Buffer.from(credential.user.encryptedPrivateDataKeyNonce).toString("base64"),
        };
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

    private async handleGetChallenge(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<GetChallengeResponse> {
        // const json = await this.parseBodyJsonValidated(req, GetChallengeRequestSchema);

        const MAX_CHALLENGE_SOLVE_TIME = 15;

        const challengeExpireTime = new Date().getTime() / 1000 + MAX_CHALLENGE_SOLVE_TIME;

        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const dataView = new DataView(challenge.buffer);
        dataView.setUint32(0, challengeExpireTime);

        const signedChallenge = nacl.sign(challenge, this.challengeSignKeyPair.secretKey);

        return {
            serverSignedChallenge: Buffer.from(signedChallenge).toString("base64"),
        };
    }
}

const server = new CryptServer();

server.initialize().then(() => {
    console.log("server initialized");
});
