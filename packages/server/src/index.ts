import {
    GetKeyRequestSchema,
    GetKeyResponse,
    encodeBase64,
    generateSignKeypair,
    LoginRequestSchema,
    sign,
    GetChallengeResponse,
    GetChallengeRequestSchema,
    LoginResponse,
    verifySignature,
    importSignPublicKey,
    ChallengeData,
} from "cryptdb-client";
import { PrismaClient, User } from "../prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import http from "http";
import * as z from "zod";
import * as bcrypt from "bcrypt";
import * as jsonwebtoken from "jsonwebtoken";
import assert from "assert";

class CryptServer {
    server: http.Server;
    prisma: PrismaClient;
    // serverSignKeyPair!: CryptoKeyPair;
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
        // this.serverSignKeyPair = await generateSignKeypair();

        console.log("Starting server");

        assert.notEqual(process.env.TOKEN_SECRET, null);

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
            case "/get-key": {
                this.ensureHttpMethod(req, "GET");
                return await this.handleGetKey(url, req, res);
            }

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

                const json = await this.parseBodyJsonValidated(req, LoginRequestSchema);

                break;
            }

            default: {
                res.writeHead(404);
                res.end("Not found");
                break;
            }
        }
    }

    private async handleLogin(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<LoginResponse> {
        const json = await this.parseBodyJsonValidated(req, LoginRequestSchema);

        const challenge = Buffer.from(json.challenge, "base64");

        let token: ChallengeData;
        try {
            token = jsonwebtoken.verify(challenge.toString("utf-8"), process.env.TOKEN_SECRET!, {
                jwtid: "challenge",
            }) as ChallengeData;
        } catch (ex) {
            console.error("Could not verify login challenge jwt", ex);
            res.statusCode = 400;
            return { status: "expired" };
        }

        const user = await this.prisma.user.findUnique({
            where: {
                id: token.uid,
            },
        });
        if (!user) {
            console.error("User doesn't exist in challenge jwt");
            res.statusCode = 400;
            return { status: "expired" };
        }

        const userPublicKey = await importSignPublicKey(user.publicSignKey);
        const signature = Buffer.from(json.signature);

        if (!(await verifySignature(challenge, signature, userPublicKey))) {
            console.warn("Invalid signature during login", json);
            res.statusCode = 400;
            return { status: "invalid-signature" };
        }

        const accessToken = jsonwebtoken.sign(
            {
                uid: Number(user.id),
            } as ChallengeData,
            process.env.TOKEN_SECRET!,
            {
                expiresIn: 60 * 60 * 18,
                jwtid: "access",
            }
        );

        return { status: "ok", token: accessToken };
    }

    private async handleGetChallenge(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<GetChallengeResponse> {
        const json = await this.parseBodyJsonValidated(req, GetChallengeRequestSchema);

        const user = await this.prisma.user.findUnique({
            where: {
                userName: json.userName,
            },
        });

        if (!user) {
            return { status: "user-not-found" };
        }

        const challengeJwt = jsonwebtoken.sign(
            {
                uid: Number(user.id),
            } as ChallengeData,
            process.env.TOKEN_SECRET!,
            {
                expiresIn: 20,
                jwtid: "challenge",
            }
        );

        return {
            status: "ok",
            challenge: Buffer.from(challengeJwt, "utf-8").toString("base64"),
        };
    }

    private async handleGetKey(url: URL, req: http.IncomingMessage, res: http.ServerResponse): Promise<GetKeyResponse> {
        const json = await this.parseBodyJsonValidated(req, GetKeyRequestSchema);

        const userKey = await this.prisma.userKey.findFirst({
            where: {
                method: json.method,
                user: {
                    userName: json.userName,
                },
            },
            include: {
                user: true,
            },
        });

        if (!userKey) {
            console.error("Invalid username", json);
            res.statusCode = 400;
            return { status: "invalid-username" };
        }

        if (!(await bcrypt.compare(json.password, userKey.passwordHash))) {
            console.error("Invalid password", json);
            res.statusCode = 400;
            return { status: "invalid-password" };
        }

        return {
            status: "ok",
            encryptedMasterKey: Buffer.from(userKey.encryptedMasterKey).toString("base64"),

            publicSignKey: Buffer.from(userKey.user.publicSignKey).toString("base64"),
            encryptedPrivateSignKey: Buffer.from(userKey.user.encryptedPrivateSignKey).toString("base64"),
            encryptedPrivateSignKeyIV: Buffer.from(userKey.user.encryptedPrivateSignKeyIV).toString("base64"),

            publicDataKey: Buffer.from(userKey.user.publicDataKey).toString("base64"),
            encryptedPrivateDataKey: Buffer.from(userKey.user.encryptedPrivateDataKey).toString("base64"),
            encryptedPrivateDataKeyIV: Buffer.from(userKey.user.encryptedPrivateDataKeyIV).toString("base64"),
        };
    }
}

const server = new CryptServer();
