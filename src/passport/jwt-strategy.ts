//@ts-ignore
import passportJwt from 'passport-jwt'
import User, {SocialUser} from '../models/user'
import {DatabaseUserInterface, UserInterface, SocialUserInterface, DatabaseSocialUserInterface} from '../interfaces/user'
import config from '../config'

const JwtStrategy = passportJwt.Strategy
const ExtractJwt = passportJwt.ExtractJwt

const jwtStrategy = new JwtStrategy({ 
    secretOrKey: config.jwt.secret,
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    passReqToCallback: true
    //@ts-ignore
} ,(req,jwtPayload, done) => {
    User.findOne({ _id: jwtPayload.id }, (err: any, user: DatabaseUserInterface) => {
        if(user){
            const userInformation: UserInterface = {
            email: user.email,
            name: user.name,
            id: user._id
            };
            req.user = userInformation
           return done(null, userInformation);
        }else{
            SocialUser.findOne({ _id: jwtPayload.id }, (err: any, user: DatabaseSocialUserInterface) => {
            if(user){
            const userInformation: SocialUserInterface = {
                name: user.name,
                id: user._id
            };
            req.user=userInformation
            return done(null, userInformation);
            }else{
                return done(null, false)
            }
        });} 
        });
})

export default jwtStrategy