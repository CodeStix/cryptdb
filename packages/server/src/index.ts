import { LoginRequestSchema } from "cryptdb-client";
import { User } from "../prisma/prisma/client";
import http from "http";
import * as z from "zod";

console.log("starting server");

class CryptServer {
    constructor() {
        const server = http.createServer(this.handleHttpRequest.bind(this));

        const port = 8080;
        server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    }

    async parseBodyJsonValidated<T extends z.ZodType>(req: http.IncomingMessage, schema: T): Promise<z.infer<T>> {
        const json = await this.parseBodyJson(req);
        return await schema.parseAsync(json);
    }

    async parseBodyJson(req: http.IncomingMessage) {
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

    async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
        console.log("Req", req.url);

        try {
            const url = new URL(req.url!, "http://localhost");
            await this.handleUrl(url, req, res);
        } catch (ex) {
            console.error("Error while handling request", req.url, ex);

            res.writeHead(400);
            res.end();
        }
    }

    ensureHttpMethod(req: http.IncomingMessage, method: string) {
        if (req.method !== method) {
            throw new Error("Unsupported HTTP method");
        }
    }

    async handleUrl(url: URL, req: http.IncomingMessage, res: http.ServerResponse) {
        switch (url.pathname) {
            case "/login": {
                this.ensureHttpMethod(req, "POST");

                const json = await this.parseBodyJsonValidated(req, LoginRequestSchema);

                res.writeHead(200);
                res.end(JSON.stringify({ user: json.userName }, null, 2));
                break;
            }

            default: {
                res.writeHead(404);
                res.end("Not found");
                break;
            }
        }
    }
}

const server = new CryptServer();
