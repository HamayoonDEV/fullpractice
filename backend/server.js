import express from "express";
import { PORT } from "./config/index.js";
import connectDb from "./database/index.js";
import router from "./routes/index.js";
import errorHandler from "./middleWare/errorHandler.js";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());

app.use(express.json({ limit: "50mb" }));
app.use(router);
connectDb();
app.use(errorHandler);
app.listen(PORT, console.log(`server is running on port:${PORT}`));
