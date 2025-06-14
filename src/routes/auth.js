const express = require("express");
const bcrypt = require("bcrypt"); 
const User = require("../models/user");
const validator = require("validator");
const {validateSignUpData} = require("../utils/validation")
const authRouter = express.Router();
const {userAuth} = require("../../middlewares/auth");

authRouter.post('/signup', async (req,res)=>{

    try {
 //validation of the data
   validateSignUpData(req);


 //Encrypt the password
   
  const {password,name,emailId}=req.body;


 const passwordHash = await bcrypt.hash(password,10);
//    console.log(passwordHash);



// creating a new instance of the new user model
    const user = new User({
        name,emailId,password:passwordHash
    });


   const savedUser =   await user.save();

   const token = await savedUser.getJWT();
 
 
     //Add the token to cookie and send the respons e to the server       
     res.cookie("token",token,{
        expires:new Date(Date.now() + 8*3600000)
     });  



    res.json({message : "user saved successfully",
        data:savedUser
    })
}
catch (err) {
    res.status(400).send("Error: " + err.message)
}

})

authRouter.post("/login",async(req,res)=>{
   
    try{
     const{password,emailId} = req.body;
     
     if(!validator.isEmail(emailId)){
            throw new Error("Invalid emailId");
     }
 
     const user = await User.findOne({emailId:emailId});
 
     if(!user){
         throw new Error("Invalid credentials");
     }
 
     const isPasswordValid = await user.validatePassword(password);
 
 
    if(isPasswordValid){
    
     //Create a JWt Token
 
    const token = await user.getJWT();
 
 
     //Add the token to cookie and send the respons e to the server       
     res.cookie("token",token,{
        expires:new Date(Date.now() + 8*3600000)
     });  
 
      res.status(200).json({
        message:"Login successful",
        data:{
            name:user.name,
            emailId:user.emailId
        }});



    }
    else{
     throw new Error("Invalid credentials")
    } 
 
    }
    catch(err){
 
     res.status(400).send("ERROR :" + err.message)
    }
 
 })








  authRouter.post("/logout", (req, res) => {
  res.clearCookie("token"); 
  res.send("Logout successfully");
});

   


authRouter.get("/profile",userAuth,async(req,res)=>{

   
  try {
    const user = req.user; 
    const { name, emailId } = user;

    res.status(200).json({
      message: "User profile fetched successfully",
      data: {
        name,
        email: emailId,
        
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch profile", error: error.message });
  }
});





module.exports = authRouter;