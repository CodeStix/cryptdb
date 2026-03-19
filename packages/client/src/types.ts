import * as z from "zod";

export const GetMasterKeyRequestSchema = z.object({
    identifier: z.string(),
});

// export type GetMasterKeyResponse =
//     | {
//           status: "ok";
//           encryptedMasterKey: string; // base64
//       }
//     | {
//           status: "unknown-credential";
//       };

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
          status: "invalid-client-signature";
      }
    | {
          status: "invalid-server-signature";
      }
    | {
          status: "challenge-expired";
      }
    | {
          status: "wrong-password";
      }
    | {
          status: "invalid-method";
      };
