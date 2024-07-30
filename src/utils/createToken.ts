import { Users } from "@prisma/client";
import { sign } from "jsonwebtoken";

export const createToken = (user: Users) => {
  const payload = {
    userId: user.id,
    tokenVersion: user.tokenVersion,
  };

  const accessToken = sign(payload, process.env.ACCESS_TOKEN_SECRET!, {
    expiresIn: "15m",
  });

  const refreshToken = sign(payload, process.env.REFRESH_TOKEN_SECRET!, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};
