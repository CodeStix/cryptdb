import * as z from "zod";

export type ChallengeVerificationStatus = "ok" | "invalid-server-signature" | "challenge-expired" | "invalid-client-signature";

export const RegisterRequestSchema = z.xor([
    z.object({
        method: z.literal("publickey"),
        identifier: z.string(),

        publicKey: z.base64(),
        clientSignature: z.base64(),
        serverSignature: z.base64(),
        challenge: z.base64(),

        encryptedMasterKey: z.base64(),
        publicSignKey: z.base64(),
        encryptedPrivateSignKey: z.base64(),
        encryptedPrivateSignKeyIV: z.base64(),
        publicDataKey: z.base64(),
        encryptedPrivateDataKey: z.base64(),
        encryptedPrivateDataKeyIV: z.base64(),
        groupPublicKey: z.base64(),
        groupEncryptedPrivateKey: z.base64(),
        collectionPublicKey: z.base64(),
        collectionEncryptedPrivateKey: z.base64(),
    }),
    z.object({
        method: z.literal("password"),
        identifier: z.string(),

        password: z.string(),

        encryptedMasterKey: z.base64(),
        publicSignKey: z.base64(),
        encryptedPrivateSignKey: z.base64(),
        encryptedPrivateSignKeyIV: z.base64(),
        publicDataKey: z.base64(),
        encryptedPrivateDataKey: z.base64(),
        encryptedPrivateDataKeyIV: z.base64(),
        groupPublicKey: z.base64(),
        groupEncryptedPrivateKey: z.base64(),
        collectionPublicKey: z.base64(),
        collectionEncryptedPrivateKey: z.base64(),
    }),
]);

export type RegisterResponse =
    | {
          status: "ok";
          token: string;
      }
    | {
          status: "invalid-public-data-key";
      }
    | {
          status: "invalid-public-challenge-key";
      }
    | {
          status: Exclude<ChallengeVerificationStatus, "ok">;
      };

// export const GetChallengeRequestSchema = z.object({
//     // userName: z.string(),
// });

export type GetChallengeResponse = {
    //   status: "ok";
    //   challengeId: string;
    challenge: string; // base64
    serverSignature: string; // base64
};

export const LoginRequestSchema = z.xor([
    z.object({
        method: z.literal("publickey"),
        identifier: z.string(),
        clientSignature: z.base64(),
        serverSignature: z.base64(),
        challenge: z.base64(),
    }),
    z.object({
        method: z.literal("password"),
        identifier: z.string(),
        // password is actually derived from                PBKDF2(password, salt: username + "random pepper 1")
        // the real master key is actually encrypted with   PBKDF2(password, salt: username + "random pepper 2")
        password: z.string(),
    }),
]);

export type LoginResponse =
    | {
          status: "ok";
          token: string;

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
          status: "unknown-credential";
      }
    | {
          status: Exclude<ChallengeVerificationStatus, "ok">;
      }
    | {
          status: "wrong-password";
      }
    | {
          status: "invalid-method";
      };
