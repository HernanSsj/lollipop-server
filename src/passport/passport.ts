import googleStrategy from './google-strategy'
import twitterStategy from './twitter-strategy'
import facebookStrategy from './facebook-strategy'
import localStrategy from './local-strategy'
import jwtStrategy from './jwt-strategy'
import User, {SocialUser} from '../models/user'
import {DatabaseUserInterface, SocialUserInterface, UserInterface, DatabaseSocialUserInterface} from '../interfaces/user'


export default function passportConfig (passport:any) { 

        
    /*-------LOCAL STRATEGY-------- */ 

    passport.use('local', localStrategy);

    /*-------GOOGLE STRATEGY-------- */ 
        passport.use('google', googleStrategy);
        
    /*-------FACEBOOK STRATEGY-------- */ 

    passport.use('facebook', facebookStrategy);

    /*-------TWITTER STRATEGY-------- */ 

    passport.use('twitter', twitterStategy);

    /*-------JWT STRATEGY-------- */ 
    
    passport.use('jwt', jwtStrategy)

    /*-------SERIALIZE USER -------- */ 

    // passport.serializeUser((user: any, cb: Function) => {
    //     cb(null, user._id);
    // });
    
    /*-------DESERIALIZE USER -------- */ 
    
    // passport.deserializeUser((id: string, cb: Function) => {
    //    
    //     User.findOne({ _id: id }, (err: any, user: DatabaseUserInterface) => {
    //     if(user){
    //         const userInformation: UserInterface = {
    //         email: user.email,
    //         name: user.name,
    //         id: user._id
    //         };
    //         cb(err, userInformation);
    //     }else{
    //         SocialUser.findOne({ _id: id }, (err: any, user: DatabaseSocialUserInterface) => {
    
    //         if(user){
    //         const userInformation: SocialUserInterface = {
    //             name: user.name,
    //             id: user._id
    //         };
    //         cb(err, userInformation);
    //         }
    //     });}
        
    //     });
    
    // });
    passport.serializeUser(function (user:any, done:Function) {
        done(null, user);
    });
    
    passport.deserializeUser(function (user:any, done:Function) {
        done(null, user);
    });
};
