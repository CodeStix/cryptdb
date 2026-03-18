import * as z from "zod";

export const GetKeyRequestSchema = z.object({
    userName: z.string(),
    method: z.string(), // can be password/recovery-code
    password: z.string(),
});

export type GetKeyResponse =
    | {
          status: "ok";
          encryptedMasterKey: string; // base64

          // All private keys are encrypted with encryptedMasterKey
          publicSignKey: string; // base64
          encryptedPrivateSignKey: string; // base64
          encryptedPrivateSignKeyIV: string; // base64
          publicDataKey: string; // base64
          encryptedPrivateDataKey: string; // base64
          encryptedPrivateDataKeyIV: string; // base64
      }
    | {
          status: "invalid-password";
      }
    | {
          status: "invalid-username";
      };

export const GetChallengeRequestSchema = z.object({
    userName: z.string(),
});

export type GetChallengeResponse =
    | {
          // challengeId: string;
          status: "ok";
          challenge: string; // base64
          // challengeServerSignature: string; // base64
      }
    | { status: "user-not-found" };

export const LoginRequestSchema = z.object({
    // publicKey: z.base64(),
    // challengeId: z.string(),
    challenge: z.base64(),
    signature: z.base64(),
});

export type LoginResponse =
    | {
          status: "ok";
          token: string;
      }
    | {
          status: "expired";
      }
    | {
          status: "invalid-signature";
      };

export type ChallengeData = { uid: number };
