import passportGoogle from 'passport-google-oauth'
import config from '../config'
import {SocialUser} from '../models/user'
import {DatabaseSocialUserInterface} from '../interfaces/user'

const GoogleStrategy = passportGoogle.OAuth2Strategy;

const googleStrategy = new GoogleStrategy(
    {
      clientID: config.googleLogin.clientID,
      clientSecret: config.googleLogin.clientSecret,
      callbackURL: config.googleLogin.callbackURL
    },
    (accessToken, refreshToken, profile, done) => {
      
      SocialUser.findOne({socialId: profile._json?.sub}).then( async (currentUser: DatabaseSocialUserInterface)=>{
      
        if(currentUser){
          done(null, currentUser);
        } else{
             
            const newUser = new SocialUser({
              name: profile.name?.givenName,
              socialId: profile._json?.sub
            })
            await newUser.save()
            done(null, newUser);
         } 
         
      })
    })

export default googleStrategy