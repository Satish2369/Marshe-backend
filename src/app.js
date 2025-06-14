console.log("backend project started")
require("dotenv").config();
const express = require('express');
const connectDB =  require("./config/database")
const app = express();
const cookieParser = require('cookie-parser');
const cors = require("cors");





// Use cookie-parser middleware
//express.json() converts the json object to a  js object which can now be readable

const corsOptions = {
    origin: "https://marshe.vercel.app/",
    credentials: true,
   
};
app.use(cors(corsOptions));
app.use(express.json()); 
app.use(cookieParser());

const authRouter = require("./routes/auth");

app.use("/",authRouter);
   
   
 

connectDB().then(()=>{
    console.log("connection established")
app.listen(process.env.PORT,()=>{
 
console.log("Server is successfully listening on port on 5000");
})
}).catch(err=>console.error("database cannot be connected"));
















