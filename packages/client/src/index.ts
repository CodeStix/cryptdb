import z from "zod";
import { LoginRequestSchema } from "./types";

export * from "./types";

export class CryptClient {
    url: string;

    constructor(url: string) {
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

    async login(userName: string) {
        const res = await this.fetchJson<z.infer<typeof LoginRequestSchema>, { user: string }>("POST", "/login", { userName });

        console.log("Login:", res);
    }
}
