import type { NextFunction , Request , Response } from "express"
import {verifyAccessToken} from "../utils/jwt.js"

export interface AuthRequest extends Request {
    userId? : string
}