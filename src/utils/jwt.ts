import jwt from "jsonwebtoken";

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

export interface AccessTokenPayload {
  userId: string;
}

export interface RefreshTokenPayload {
  userId: string;
  sessionId: string;
}

export function createAccessToken(userId: string) {
  return jwt.sign(
    {
      userId,
    },
    ACCESS_SECRET,
    {
      expiresIn: "15m",
    },
  );
}

export function createRefreshToken(userId: string, sessionId: string) {
  return jwt.sign(
    {
      userId,
      sessionId,
    },
    REFRESH_SECRET,
    {
      expiresIn: "7d",
    },
  );
}

export function verifyAccessToken(Token: string) {
  return jwt.verify(Token, ACCESS_SECRET) as AccessTokenPayload;
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, REFRESH_SECRET) as RefreshTokenPayload;
}
