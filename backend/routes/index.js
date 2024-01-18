import express from "express";
import authController from "../controller/authController.js";
import auth from "../middleWare/auth.js";

const router = express.Router();

router.post("/register", authController.userRegister);
router.post("/login", authController.userLogin);
router.post("/logout", auth, authController.logout);
router.get("/refresh", authController.refreshToken);

export default router;
