import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
      },
    email:  {
        type: String,
        unique: true
    },
    password: {
        type: String,
        required: true
      }
});
const socialUserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
      },
    socialId:  {
        type: String,
        unique: true,
    },
});

const User = mongoose.model("User", userSchema);
export const SocialUser = mongoose.model("SocialUser", socialUserSchema);
export default User;