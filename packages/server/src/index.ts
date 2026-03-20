import {
    encodeBase64,
    generateSignKeypair,
    LoginRequestSchema,
    sign,
    GetChallengeResponse,
    LoginResponse,
    verifySignature,
    importSignPublicKey,
    sha256,
    deriveKey,
    exportRawKey,
    RegisterRequestSchema,
    generateRsaKeypair,
    encryptAes,
    encryptRsa,
    exportRsaPrivateKey,
    importRsaPublicKey,
    RegisterResponse,
    ChallengeVerificationStatus,
} from "cryptdb-client";
import { PrismaClient, User } from "../prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import http from "http";
import * as z from "zod";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";

const JWT_EXPIRE_IN = 18 * 60 * 60;

type CryptToken = {
    uid: number;
    c: number; // counter
};

class CryptServer {
    server: http.Server;
    prisma: PrismaClient;
    challengeSignKeyPair!: CryptoKeyPair;
    // passwordSalt!: Buffer;
    jwtSecret!: string;
    publicGroupKeyPair!: CryptoKeyPair;
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
        this.challengeSignKeyPair = await generateSignKeypair();
        this.publicGroupKeyPair = await generateRsaKeypair();
        // this.passwordSalt = Buffer.from("d0f38af4d1226fcefec23573b6c19094", "hex");
        this.jwtSecret = "d0e58258db29e06243aa24738ff97496";

        this.publicGroupId = 1;

        console.log("Starting server");

        const port = 8080;
        this.server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }

    private async parseBodyJsonValidated<T extends z.ZodType>(req: http.IncomingMessage, schema: T): Promise<z.infer<T>> {
        const json = await this.parseBodyJson(req);
        return await schema.parseAsync(json);
    }

    private async parseBodyJson(req: http.IncomingMessage) {
        const contentType = req.headers["content-type"] || "";
        if (!contentType.startsWith("application/json")) {
            throw new Error("Unsupported Content-Type");
        }

        const MAX_BODY = 1 * 1024 * 1024;

        return new Promise<any>((resolve, reject) => {
            let chunks = [] as Buffer[];
            let received = 0;

            req.on("data", (chunk: Buffer) => {
                received += chunk.length;

                if (received > MAX_BODY) {
                    req.destroy();
                    reject(new Error("Request too large"));
                    return;
                }

                chunks.push(chunk);
            });

            req.on("end", () => {
                try {
                    const str = Buffer.concat(chunks).toString("utf8");
                    resolve(JSON.parse(str));
                } catch (ex) {
                    reject(ex);
                }
            });

            req.on("error", (error) => {
                console.error("Request error:", error.message);
                reject(new Error("Request error"));
            });
        });
    }

    private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
        console.log("Req", req.url);

        try {
            const url = new URL(req.url!, "http://localhost");
            const jsonRes = await this.handleUrl(url, req, res);

            if (typeof jsonRes !== "undefined") {
                res.end(JSON.stringify(jsonRes));
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

    private async handleUrl(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<unknown> {
        switch (url.pathname) {
            case "/get-challenge": {
                this.ensureHttpMethod(req, "GET");
                return await this.handleGetChallenge(url, req, res);
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
        const encryptedMasterKeyIV = Buffer.from(json.encryptedMasterKeyIV, "base64");
        const publicSignKey = Buffer.from(json.publicSignKey, "base64");
        const encryptedPrivateSignKey = Buffer.from(json.encryptedPrivateSignKey, "base64");
        const encryptedPrivateSignKeyIV = Buffer.from(json.encryptedPrivateSignKeyIV, "base64");
        const publicDataKey = Buffer.from(json.publicDataKey, "base64");
        const encryptedPrivateDataKey = Buffer.from(json.encryptedPrivateDataKey, "base64");
        const encryptedPrivateDataKeyIV = Buffer.from(json.encryptedPrivateDataKeyIV, "base64");
        const groupPublicKey = Buffer.from(json.groupPublicKey, "base64");
        const groupEncryptedPrivateKey = Buffer.from(json.groupEncryptedPrivateKey, "base64");
        const collectionPublicKey = Buffer.from(json.collectionPublicKey, "base64");
        const collectionEncryptedPrivateKey = Buffer.from(json.collectionEncryptedPrivateKey, "base64");

        let publicGroupEncryptedPrivateKey: ArrayBuffer;
        try {
            publicGroupEncryptedPrivateKey = await encryptRsa(
                await exportRsaPrivateKey(this.publicGroupKeyPair.privateKey),
                await importRsaPublicKey(publicDataKey)
            );
        } catch (ex) {
            console.error("Invalid data public key", json);
            return { status: "invalid-public-data-key" };
        }

        if (json.method === "password") {
            // ...
        } else if (json.method === "publickey") {
            const challenge = Buffer.from(json.challenge, "base64");
            const serverSignature = Buffer.from(json.serverSignature, "base64");
            const clientSignature = Buffer.from(json.clientSignature, "base64");

            let publicChallengeKey: CryptoKey;
            try {
                publicChallengeKey = await importRsaPublicKey(Buffer.from(json.publicKey, "base64"));
            } catch (ex) {
                console.error("Invalid publicChallengeKey", ex);
                return { status: "invalid-public-challenge-key" };
            }

            const verificationStatus = await this.verifyChallenge(challenge, serverSignature, clientSignature, publicChallengeKey);
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
                    encryptedPrivateSignKeyIV: encryptedPrivateSignKeyIV,
                    publicDataKey: publicDataKey,
                    encryptedPrivateDataKey: encryptedPrivateDataKey,
                    encryptedPrivateDataKeyIV: encryptedPrivateDataKeyIV,

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
                const hashedPassword = new Uint8Array(await this.hashPassword(password, passwordSalt));

                await this.prisma.userKey.create({
                    data: {
                        encryptedMasterKey: encryptedMasterKey,
                        encryptedMasterKeyIV: encryptedMasterKeyIV,
                        identifier: json.identifier,
                        method: json.method,
                        passwordHash: hashedPassword,
                        passwordSalt: passwordSalt,
                        userId: user.id,
                    },
                });
            } else if (json.method === "publickey") {
                const publicKey = Buffer.from(json.publicKey, "base64");
                await this.prisma.userKey.create({
                    data: {
                        encryptedMasterKey: encryptedMasterKey,
                        encryptedMasterKeyIV: encryptedMasterKeyIV,
                        identifier: json.identifier,
                        method: json.method,
                        publicKey: publicKey,
                        userId: user.id,
                    },
                });
            }

            return user;
        });

        const token = this.createAccessToken(user.id, user.tokenCounter);

        return {
            status: "ok",
            token: token,
        };
    }

    private async hashPassword(password: BufferSource, salt: BufferSource) {
        return await exportRawKey(await deriveKey(password, salt, 100000));
    }

    private async verifyChallenge(
        challenge: Buffer,
        serverSignature: Buffer,
        clientSignature: Buffer,
        clientPublicKey: CryptoKey
    ): Promise<ChallengeVerificationStatus> {
        if (!(await verifySignature(challenge, serverSignature, this.challengeSignKeyPair.publicKey))) {
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

        if (!(await verifySignature(challenge, clientSignature, clientPublicKey))) {
            console.log("Invalid client signature");
            return "invalid-client-signature";
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
            const challenge = Buffer.from(json.challenge, "base64");
            const serverSignature = Buffer.from(json.serverSignature, "base64");
            const clientSignature = Buffer.from(json.clientSignature, "base64");
            const publicKey = await importSignPublicKey(credential.publicKey!);

            const verificationStatus = await this.verifyChallenge(challenge, serverSignature, clientSignature, publicKey);
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
            encryptedMasterKeyIV: Buffer.from(credential.encryptedMasterKeyIV).toString("base64"),

            publicSignKey: Buffer.from(credential.user.publicSignKey).toString("base64"),
            encryptedPrivateSignKey: Buffer.from(credential.user.encryptedPrivateSignKey).toString("base64"),
            encryptedPrivateSignKeyIV: Buffer.from(credential.user.encryptedPrivateSignKeyIV).toString("base64"),

            publicDataKey: Buffer.from(credential.user.publicDataKey).toString("base64"),
            encryptedPrivateDataKey: Buffer.from(credential.user.encryptedPrivateDataKey).toString("base64"),
            encryptedPrivateDataKeyIV: Buffer.from(credential.user.encryptedPrivateDataKeyIV).toString("base64"),
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

        const signedChallenge = await sign(challenge.buffer, this.challengeSignKeyPair.privateKey);

        return {
            challenge: Buffer.from(challenge).toString("base64"),
            serverSignature: Buffer.from(signedChallenge).toString("base64"),
        };
    }
}

const server = new CryptServer();
