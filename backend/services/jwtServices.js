import { ACCESS_TOKEN, REFRESH_TOKEN } from "../config/index.js";
import RefreshToken from "../models/token.js";
import jwt from "jsonwebtoken";

class JwtServices {
  //sign AccessToken
  static signAccessToken(payload, expiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN, { expiresIn: expiryTime });
  }
  //sign RefreshToken

  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN, { expiresIn: expiryTime });
  }
  //verify AccessToken
  static verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_TOKEN);
  }
  //verify RefreshToken
  static verifyRefreshToken(token) {
    return jwt.verify(token, REFRESH_TOKEN);
  }
  //Store RefreshToken
  static async storeRefreshToken(userId, token) {
    try {
      const newToken = new RefreshToken({
        userId,
        token,
      });
      await newToken.save();
    } catch (error) {
      return error;
    }
  }
}
export default JwtServices;
