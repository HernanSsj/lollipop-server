import passportFacebook from 'passport-facebook'
import config from '../config'
import {SocialUser} from '../models/user'
import {DatabaseSocialUserInterface} from '../interfaces/user'

const FacebookStrategy = passportFacebook.Strategy;

const facebookStrategy = new FacebookStrategy({
    clientID: config.facebookLogin.FACEBOOK_APP_ID,
    clientSecret: config.facebookLogin.FACEBOOK_APP_SECRET ,
    callbackURL: config.facebookLogin.FacebookCallbackURL,
    profileFields: ['email', 'first_name', 'id']
  },
  function(accessToken, refreshToken, profile, done) {
    SocialUser.findOne({socialId: profile._json?.id}).then( async (currentUser: DatabaseSocialUserInterface)=>{
      if(currentUser){
        
        done(null, currentUser);
      } else{
        const newUser = new SocialUser({
          name: profile._json.first_name,
          socialId: profile._json?.id
        })
          await newUser.save()
          done(null, newUser);
       } 
       
    })
  
  }
)

export default facebookStrategy