import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRoutes from "../src/routes/auth.routes.js";

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  }),
);

app.use(express.json());

app.use(cookieParser());

app.use("/auth", authRoutes);

app.get("/health", (_, res) => {
  res.json({
    status: "ok",
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
