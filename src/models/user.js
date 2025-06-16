

const mongoose = require('mongoose');
const validator = require('validator')
const bcrypt = require("bcrypt"); 
const jwt = require("jsonwebtoken");
const userSchema = new mongoose.Schema({


         name:{
            type:String,
            required:true,
            minlength:3,
            maxlength:45
         },
         
         emailId:{
            type:String,
            required:true,
            unique:true,
            lowercase:true,
            trim:true,
            validate(value){
               if(!validator.isEmail(value)){
                  throw new Error("Invalid email")
               }
            }
         },
         password:{
            type:String,
            required:true,
            // validate(value){
            //    if(!validator.isStrongPassword(value)){
            //       throw new Error("passsword is weak")
            //    }
            // }
         }
        




},{timestamps:true});

//never use a arrow function with this
userSchema.methods.getJWT = async function (){
  const user = this;
   const token = await jwt.sign({_id:this._id},process.env.JWT_SECRET,{expiresIn:"1d"});

    return token;
}



userSchema.methods.validatePassword= async function(passwordByUser){
    const user = this;
    const passwordHash = this.password;
     const isPasswordValid =await bcrypt.compare(passwordByUser,passwordHash);
    return isPasswordValid;
}



const UserModel= mongoose.model("User",userSchema)
module.exports = UserModel;