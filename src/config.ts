import dotenv from 'dotenv'
dotenv.config();
const config = {
    googleLogin: {
        clientID: process.env.clientId!,
        clientSecret: process.env.clientSecret!,
        callbackURL: process.env.callbackURL!
    },
    twitterLogin:{
        TWITTER_CONSUMER_KEY: process.env.TWITTER_CONSUMER_KEY!,
        TWITTER_CONSUMER_SECRET: process.env.TWITTER_CONSUMER_SECRET!,
        TwitterCallbackURL: process.env.TwitterCallbackURL!
    },
    facebookLogin:{
        FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID!,
        FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET!,
        FacebookCallbackURL: process.env.FacebookCallbackURL!
    },
    db:{
        CONECCTION_URL: process.env.CONECCTION_URL!,
        PARAMS: {
            useCreateIndex: true,
            useNewUrlParser: true,
            useUnifiedTopology: true
          }
    },
    app: {
        PORT: parseInt(process.env.PORT!) || 3000
      },
    jwt:{
            secret: process.env.jwtSecret!,
            permanent: process.env.jwtPermanent!,
            temporal:process.env.jwtTemporal!
    }
}




export default config 


