import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: String,
    email:  {
        type: String,
        unique: true
    },
   password: String,
   googleId: {
    type: String,  index: {
      unique: true,
      partialFilterExpression: {googleId: {$type: "string"}}
    }
   }
});

const User = mongoose.model("User", userSchema);

export default User;