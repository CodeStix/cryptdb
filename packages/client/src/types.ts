import * as z from "zod";

export const LoginRequestSchema = z.object({
    userName: z.string(),
});
