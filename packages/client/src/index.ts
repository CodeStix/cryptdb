import z from "zod";
import { LoginRequestSchema } from "./types";
import { deriveKey, encodeBase64, exportAesKey, textToBytes } from "./crypto";

export * from "./types";
export * from "./crypto";

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

        const salt = new Uint8Array(32);
        salt.fill(124);
        // crypto.getRandomValues(salt);

        console.time("derivedKey");
        const derivedKey = await exportAesKey(await deriveKey(textToBytes(res.user), salt));
        console.timeEnd("derivedKey");

        console.log("salt", encodeBase64(salt));
        console.log("key", encodeBase64(derivedKey), derivedKey.length);
        console.log("Login:", res);
    }
}
