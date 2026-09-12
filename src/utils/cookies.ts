import type { Response } from "express";

const isProduction = process.env.NODE_ENV === "production";

export function setAuthCookies(
  res: Response,
  accessToken: string,
  refreshToken: string,
) {
  res.cookie("access_Token", accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    path: "/",
    maxAge: 15 * 60 * 1000,
  });

  res.cookie("refresh_Token", refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    path: "/auth",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}


export function clearAuthCookies(res:Response) {
     res.clearCookie("access_Token" , {
        httpOnly : true,
        secure : isProduction,
        sameSite : "lax",
        path : "/"
     })

     res.clearCookie("refresh_Token" , {
        httpOnly : true , 
        secure : isProduction,
        sameSite : "lax",
        path : "/auth"
     } )
}