import jwt, { type SignOptions } from "jsonwebtoken";
import { config } from "../config/env.js";

export enum JwtTokenType {
  ACCESS_TOKEN = 1,
  REFRESH_TOKEN = 2,
}

export type JwtPayload = {
  id: string;
  roles: string[];
};

const jwtHelper = {
  async generateToken(
    type: JwtTokenType,
    payload: JwtPayload,
  ): Promise<string> {
    switch (type) {
      case JwtTokenType.ACCESS_TOKEN:
        const accessOptions: SignOptions = { expiresIn: config.JWT_EXPIRES_IN };
        return jwt.sign(payload, config.JWT_SECRET, accessOptions);
      case JwtTokenType.REFRESH_TOKEN:
        const refreshOptions: SignOptions = {
          expiresIn: config.JWT_REFRESH_EXPIRES_IN,
        };
        return jwt.sign(payload, config.JWT_REFRESH_SECRET, refreshOptions);
    }
  },
  async verifyToken(
    type: JwtTokenType = JwtTokenType.ACCESS_TOKEN,
    token: string,
  ): Promise<JwtPayload> {
    switch (type) {
      case JwtTokenType.ACCESS_TOKEN:
        return jwt.verify(token, config.JWT_SECRET as string) as JwtPayload;
      case JwtTokenType.REFRESH_TOKEN:
        return jwt.verify(token, config.JWT_REFRESH_SECRET) as JwtPayload;
    }
  },
};

export default jwtHelper;
