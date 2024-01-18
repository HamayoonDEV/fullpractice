import Joi from "joi";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import JwtServices from "../services/jwtServices.js";
import RefreshToken from "../models/token.js";

const passwordPattren =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[ -/:-@\[-`{-~]).{6,64}$/;

const authController = {
  async userRegister(req, res, next) {
    const userRegisterSchema = Joi.object({
      name: Joi.string().max(30).required(),
      username: Joi.string().min(5).max(30).required(),
      email: Joi.string().email().required(),
      password: Joi.string().pattern(passwordPattren).required(),
    });
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { name, username, email, password } = req.body;

    //password hashing
    const hashedPassword = await bcrypt.hash(password, 10);
    //handle email and username conflict

    try {
      const emailInUse = await User.exists({ email });
      const usernameInUser = await User.exists({ username });

      if (emailInUse) {
        const error = {
          status: 409,
          message: "Email Already In Use!",
        };
        return next(error);
      }
      if (usernameInUser) {
        const error = {
          status: 409,
          message: "username already taken!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    //saving in database
    let user;
    try {
      const userToRegister = new User({
        name,
        username,
        email,
        password: hashedPassword,
      });
      user = await userToRegister.save();
    } catch (error) {
      return next(error);
    }
    const accessToken = JwtServices.signAccessToken({ id: user._id }, "30m");
    const refreshToken = JwtServices.signRefreshToken({ id: user._id }, "60m");
    //store RefreshToken to the database
    await JwtServices.storeRefreshToken(user._id, refreshToken);
    //sending tokens to the cookies
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });

    //sending response
    res.status(201).json({ user, auth: true });
  },
  // user login method
  async userLogin(req, res, next) {
    const userLoginSchema = Joi.object({
      username: Joi.string().min(5).max(30).required(),
      password: Joi.string().pattern(passwordPattren).required(),
    });
    const { error } = userLoginSchema.validate(req.body);
    if (error) {
      return next(error);
    }
    const { username, password } = req.body;

    //matching username and password with database credentials
    let user;
    try {
      user = await User.findOne({ username });
      if (!user) {
        const error = {
          status: 401,
          message: "invalid username!",
        };
        return next(error);
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        const error = {
          status: 401,
          message: "invalid password!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    const accessToken = JwtServices.signAccessToken({ id: user._id }, "30m");
    const refreshToken = JwtServices.signRefreshToken({ id: user._id }, "60m");
    //update tokens to the database
    try {
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        { token: refreshToken },
        { upsert: true }
      );
    } catch (error) {
      return next(error);
    }
    //sending tokens to the cookies
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });

    //sending response
    res.status(200).json({ user, auth: true });
  },
  //logout method
  async logout(req, res, next) {
    const { refreshToken } = req.cookies;
    try {
      await RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }
    //clear tokens from the cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    //sending response
    res.status(200).json({ user: null, auth: false });
  },
  //refreshToken method
  async refreshToken(req, res, next) {
    const orginalRefreshToken = req.cookies.refreshToken;

    //verify refreshToken
    let _id;
    try {
      _id = await JwtServices.verifyRefreshToken(orginalRefreshToken).id;
    } catch (error) {
      const e = {
        status: 401,
        message: "unAuthorized!",
      };
      return next(e);
    }

    //match refreshToken to the database
    try {
      const match = await RefreshToken.findOne({
        _id: _id,
        token: orginalRefreshToken,
      });
      if (!match) {
        const error = {
          status: 401,
          message: "unAuthorized!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }

    //genratint new tokens
    const accessToken = JwtServices.signAccessToken({ id: _id }, "30m");
    const refreshToken = JwtServices.signRefreshToken({ id: _id }, "60m");
    //update refreshToken to the database
    await RefreshToken.updateOne({ _id: _id }, { token: refreshToken });
    //sending tokens to the cookies;
    res.cookie("accessToken", accessToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    res.cookie("refreshToken", refreshToken, {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    });
    let user;
    try {
      user = await User.findOne({ _id: _id });
      if (!user) {
        const error = {
          status: 404,
          message: "user not found!",
        };
        return next(error);
      }
    } catch (error) {
      return next(error);
    }
    //sending response
    res.status(200).json({ user, auth: true });
  },
};

export default authController;
