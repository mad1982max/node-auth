require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const router = require("./routers/index");
const errorMiddleware = require("./middlewares/error.middleware");

const { dbOptions } = require("./options");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use("/api", router);
app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;

const start = async () => {
  try {
    await mongoose.connect(process.env.DB_URL, dbOptions);
    app.listen(PORT, () => {
      console.log(`...app is running on port: ${PORT}`);
    });
  } catch (err) {
    console.log("--err--", err);
  }
};

start();
