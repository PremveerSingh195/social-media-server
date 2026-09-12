import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { prisma } from "../lib/prisma.js";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import { hashToken } from "../utils/hash.js";
import { clearAuthCookies, setAuthCookies } from "../utils/cookies.js";

export async function register(req: Request, res: Response) {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password is required",
      });
    }

    const existingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name,
      },
    });

    const session = await prisma.refreshSession.create({
      data: {
        userId: user.id,
        tokenHash: "temporary",
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id, session.id);

    await prisma.refreshSession.update({
      where: {
        id: session.id,
      },
      data: {
        tokenHash: hashToken(refreshToken),
      },
    });

    setAuthCookies(res, accessToken, refreshToken);

    return res.status(201).json({
      message: "Registration Successfull",
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function login(req : Request , res : Response) {
    try {
        const { email , password } = req.body

        const user = await prisma.user.findUnique({
            where : {
                email
            }
        })

        if (!user) {
            return res.status(401).json({
                message : "User not found"
            })
        }

        const passwordValid = await bcrypt.compare(
            password ,
            user?.passwordHash
        ) 

        if (!passwordValid) {
            return res.status(401).json({
                message : "Invalid Email or password"
            })
        }

        const session = await prisma.refreshSession.create({
            data : {
                userId : user.id,
                tokenHash : "temporary",
                expiresAt : new Date(
                    Date.now() + 7 * 24 * 60 * 60 * 1000
                )
            }
        })

        const accessToken = createAccessToken(user.id)

        const refreshToken = createRefreshToken(
            user.id,
            session.id
        )

        await prisma.refreshSession.update({
            where : {
                id : session.id
            },
            data : {
                tokenHash : hashToken(refreshToken)
            }
        })

        setAuthCookies(res , accessToken , refreshToken)

        return res.json({
            message : "Login Successfull",
            user : {
                id : user.id,
                email : user.email,
                name : user.name
            }
        })

    } catch (error) {
        console.error(error)

        return res.status(500).json({
            message : "Internal server error"
        })
    }
}