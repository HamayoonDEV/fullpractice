import JwtServices from "../services/jwtServices.js";
import User from "../models/user.js";

const auth = async (req, res, next) => {
  //fetch tokens from the cookies
  const { accessToken, refreshToken } = req.cookies;

  if (!accessToken || !refreshToken) {
    const error = {
      status: 401,
      message: "unAuthorized!",
    };
    return next(error);
  }
  //verify accessToken
  let id;
  try {
    id = await JwtServices.verifyAccessToken(accessToken).id;
  } catch (error) {
    return next(error);
  }
  let user;
  try {
    user = await User.findOne({ _id: id });
    if (!user) {
      const error = {
        status: 404,
        message: "user not Found!",
      };
      return next(error);
    }
  } catch (error) {
    return next(error);
  }
  req.user = user;
  next();
};

export default auth;
