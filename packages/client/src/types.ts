import * as z from "zod";
import nacl from "tweetnacl";
import { NACL_EPHEMERAL_BOX_OVERHEAD } from "./crypto";
import { decodeBase64 } from "tweetnacl-util";

export type ChallengeVerificationStatus = "ok" | "invalid-server-signature" | "challenge-expired" | "invalid-client-signature";

function base64Length(byteCount: number): number {
    return Math.ceil(byteCount / 3) * 4;
}

// function base64LengthNoPadding(byteCount: number): number {
//     return Math.ceil((byteCount * 4) / 3);
// }

function specificBase64(minBytes: number, maxBytes?: number) {
    return z
        .base64()
        .min(base64Length(minBytes))
        .max(base64Length(maxBytes ?? minBytes));
}

export const RegisterRequestSchema = z.xor([
    z.object({
        method: z.literal("publickey"),
        identifier: z.string(),

        publicKey: specificBase64(nacl.sign.publicKeyLength),
        clientServerSignedChallenge: specificBase64(16, 128),

        encryptedMasterKey: specificBase64(nacl.box.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedMasterKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        publicSignKey: specificBase64(nacl.sign.publicKeyLength),
        encryptedPrivateSignKey: specificBase64(nacl.sign.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedPrivateSignKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        publicDataKey: specificBase64(nacl.sign.publicKeyLength),
        encryptedPrivateDataKey: specificBase64(nacl.box.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedPrivateDataKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        groupPublicKey: specificBase64(nacl.sign.publicKeyLength),
        groupEncryptedPrivateKey: specificBase64(nacl.box.secretKeyLength + nacl.box.overheadLength + NACL_EPHEMERAL_BOX_OVERHEAD),
        collectionPublicKey: specificBase64(nacl.sign.publicKeyLength),
        collectionEncryptedPrivateKey: specificBase64(nacl.box.secretKeyLength + nacl.box.overheadLength + NACL_EPHEMERAL_BOX_OVERHEAD),
    }),
    z.object({
        method: z.literal("password"),
        identifier: z.string(),

        password: z.string(),

        encryptedMasterKey: specificBase64(nacl.box.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedMasterKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        publicSignKey: specificBase64(nacl.sign.publicKeyLength),
        encryptedPrivateSignKey: specificBase64(nacl.sign.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedPrivateSignKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        publicDataKey: specificBase64(nacl.sign.publicKeyLength),
        encryptedPrivateDataKey: specificBase64(nacl.box.secretKeyLength + nacl.secretbox.overheadLength),
        encryptedPrivateDataKeyNonce: specificBase64(nacl.secretbox.nonceLength),
        groupPublicKey: specificBase64(nacl.sign.publicKeyLength),
        groupEncryptedPrivateKey: specificBase64(nacl.box.secretKeyLength + nacl.box.overheadLength + NACL_EPHEMERAL_BOX_OVERHEAD),
        collectionPublicKey: specificBase64(nacl.sign.publicKeyLength),
        collectionEncryptedPrivateKey: specificBase64(nacl.box.secretKeyLength + nacl.box.overheadLength + NACL_EPHEMERAL_BOX_OVERHEAD),
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
    serverSignedChallenge: string; // base64
};

export const LoginRequestSchema = z.discriminatedUnion("method", [
    z.object({
        method: z.literal("publickey"),
        identifier: z.string().min(8).max(64),
        clientServerSignedChallenge: specificBase64(16, 128),
    }),
    z.object({
        method: z.literal("password"),
        identifier: z.string().min(8).max(64),
        // password is actually derived from                PBKDF2(password, salt: username + "random pepper 1")
        // the real master key is actually encrypted with   PBKDF2(password, salt: username + "random pepper 2")
        password: z.string().min(8).max(64),
    }),
]);

export const LoginResponseSchema = z.discriminatedUnion("status", [
    z.object({
        status: z.literal("ok"),
        encryptedMasterKey: z.base64().transform((e) => decodeBase64(e)),
    }),
    z.object({
        status: z.literal("unknown-credential"),
    }),
]);

export type LoginResponse =
    | {
          status: "ok";
          token: string;

          encryptedMasterKey: string; // base64
          encryptedMasterKeyNonce: string; // base64

          // All private keys are encrypted with encryptedMasterKey
          publicSignKey: string; // base64
          encryptedPrivateSignKey: string; // base64
          encryptedPrivateSignKeyNonce: string; // base64
          publicDataKey: string; // base64
          encryptedPrivateDataKey: string; // base64
          encryptedPrivateDataKeyNonce: string; // base64
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
