console.log(" Backend project started");

const path = require("path");
const dotenv = require("dotenv");
const express = require("express");
const connectDB = require("./config/database");
const cookieParser = require("cookie-parser");
const cors = require("cors");


const env = process.env.NODE_ENV || "development";


dotenv.config({
  path: path.resolve(__dirname, `../.env.${env}`)
});




const app = express();

const corsOptions = {
  origin: process.env.FRONTEND_URL,
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());


const authRouter = require("./routes/auth");
app.use("/", authRouter);


connectDB()
  .then(() => {
    console.log(" MongoDB connection established");
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(` Server listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error(" Database connection failed:", err.message);
  });
