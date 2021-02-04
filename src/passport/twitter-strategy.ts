import passportTwitter from 'passport-twitter'
import config from '../config'
import {SocialUser} from '../models/user'
import {DatabaseSocialUserInterface} from '../interfaces/user'

const TwitterStrategy = passportTwitter.Strategy

const twitterStrategy = new TwitterStrategy({
    consumerKey: config.twitterLogin.TWITTER_CONSUMER_KEY,
    consumerSecret: config.twitterLogin.TWITTER_CONSUMER_SECRET,
    callbackURL: config.twitterLogin.TwitterCallbackURL
  },
  function(token, tokenSecret, profile, done) {
    SocialUser.findOne({socialId: profile._json?.id}).then( async (currentUser:DatabaseSocialUserInterface)=>{
      if(currentUser){
        
        done(null, currentUser);
  
      } else{
          const newUser = new SocialUser({
            name: profile._json?.name,
            socialId: profile._json?.id,
          })
          await newUser.save()
          done(null, newUser);
       } 
    })}
  )

export default twitterStrategy