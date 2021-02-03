import mongoose from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import passportGoogle from 'passport-google-oauth'
import passportFacebook from 'passport-facebook'
import passportTwitter from 'passport-twitter'
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv'
import User from './models/user'
import {UserInterface, DatabaseUserInterface} from './interfaces/user'

const LocalStrategy = passportLocal.Strategy
const GoogleStrategy = passportGoogle.OAuth2Strategy;
const FacebookStrategy = passportFacebook.Strategy;
const TwitterStrategy = passportTwitter.Strategy;

dotenv.config();

const CONECCTION_URL:string = process.env.CONECCTION_URL!
const PORT = process.env.port || 5000
const clientID:string = process.env.clientId!
const clientSecret:string = process.env.clientSecret!
const callbackURL:string = process.env.callbackURL!
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID!
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET!
const FacebookCallbackURL = process.env.FacebookCallbackURL!
const TWITTER_CONSUMER_KEY = process.env.TWITTER_CONSUMER_KEY!
const TWITTER_CONSUMER_SECRET = process.env.TWITTER_CONSUMER_SECRET!
const TwitterCallbackURL = process.env.TwitterCallbackURL!
mongoose.connect(CONECCTION_URL, {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true
  }, (err) => {
    if (err) throw err;
    console.log("Connected To Mongo Database")
  });

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }))
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

//LOCAL STRATEGY
passport.use(new LocalStrategy({ usernameField: 'email',} ,(email: string, password: string, done) => {
  User.findOne({ email: email }, (err: any, user: DatabaseUserInterface) => {
    if (err) throw err;
    if (!user?.password) return done(null, false);
    bcrypt.compare(password, user.password, (err, result: boolean) => {
      if (err) throw err;
      if (result === true) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  });
})
);
/*/////////////////////////////////////////////////////////*/

//GOOGLE STRATEGY
passport.use(
  new GoogleStrategy(
    {
      clientID,
      clientSecret,
      callbackURL
    },
    (accessToken, refreshToken, profile, done) => {
      
      User.findOne({email: profile._json?.email}).then( async (currentUser: any)=>{
     
        if(currentUser){
          done(null, currentUser);
        } else{
             
            const newUser = new User({
              name: profile.name?.givenName,
              email: profile._json?.email,
            })
            await newUser.save()
            done(null, newUser);
         } 
         
      })
    })
  );
/* FACEBOOK STRATEGY */
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET ,
    callbackURL: FacebookCallbackURL,
    profileFields: ['email']
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOne({email: profile._json?.email}).then( async (currentUser: DatabaseUserInterface)=>{
      if(currentUser){
        
        done(null, currentUser);
      } else{
           
          const newUser = new User({
            name: profile.name?.givenName,
            email: profile._json?.email,
          })
          await newUser.save()
          done(null, newUser);
       } 
       
    })
  
  }
));

/* TWITTER STRATEGY */

passport.use(new TwitterStrategy({
  consumerKey: TWITTER_CONSUMER_KEY,
  consumerSecret: TWITTER_CONSUMER_SECRET,
  callbackURL: TwitterCallbackURL
},
function(token, tokenSecret, profile, done) {
  User.findOne({email: profile._json?.email}).then( async (currentUser: DatabaseUserInterface)=>{
    if(currentUser){
      
      done(null, currentUser);
    } else{
         
        const newUser = new User({
          name: profile.name?.givenName,
          email: profile._json?.email,
        })
        await newUser.save()
        done(null, newUser);
     } 
  })}
));

app.get('/auth/twitter',
  passport.authenticate('twitter', {scope: ["public_profile", "email"]}));

  app.get('/auth/twitter/callback', function(req, res, next) {
    passport.authenticate('twitter', function(err, user, info) {
      if (err) {return next(err);}
      if (!user) { 
        /* Envia el js para cerrar el pop up */
        let responseHTML = '<script>res = null; window.opener.postMessage(res, "*");window.close();</script>'
        return res.status(200).send(responseHTML); 
      }else{
         /* Envia el ok */
        req.logIn(user, function(err) {
          if (err) { return next(err); }
          let responseHTML = '<script>res = %value%; window.opener.postMessage(res, "*");window.close();</script>'
          responseHTML = responseHTML.replace('%value%', JSON.stringify({user: user._id}));
          return res.status(200).send(responseHTML);
        });
      }
    })(req, res, next);
  });

app.get('/auth/facebook',passport.authenticate("facebook",{scope: ["public_profile", "email"]}));

app.get('/auth/facebook/callback', function(req, res, next) {
  passport.authenticate('facebook', function(err, user, info) {
    if (err) {return next(err);}
    if (!user) { 
      
      /* Envia el js para cerrar el pop up */
      let responseHTML = '<script>res = null; window.opener.postMessage(res, "*");window.close();</script>'
      return res.status(200).send(responseHTML); 
    }else{
       /* Envia el ok */
      req.logIn(user, function(err) {
        if (err) { return next(err); }
        let responseHTML = '<script>res = %value%; window.opener.postMessage(res, "*");window.close();</script>'
        responseHTML = responseHTML.replace('%value%', JSON.stringify(user._id));
       
        return res.status(200).send(responseHTML);
      });
    }
  })(req, res, next);
});

passport.serializeUser((user: any, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err: any, user: any) => {
    const userInformation: UserInterface = {
      email: user.email,
      name: user.name,
      id: user._id
    };
    cb(err, userInformation);
  });
});

app.post('/register', async (req, res) => {
  const { name, email, password, repeated_password} = req?.body;

  if (!name || !email || !password || typeof email !== "string" || typeof password !== "string" || password !== repeated_password) {

    res.status(400).json({Message:"Invalid params"});

  }
  User.findOne({ email }, async (err: any, doc: DatabaseUserInterface) => {
    if (err) throw err;
    if (doc) res.status(400).json({Message: "User Already Exists"});
    if (!doc) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        name,
        email,
        password: hashedPassword,
      });
      await newUser.save();
      res.send("success")
    }
  })
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.sendStatus(401); }
    req.logIn(user, function(err) {
      if (err) { return next(err); }
      return res.status(200).json(user._id);
    });
  })(req, res, next);
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

app.get('/auth/google/redirect', function(req, res, next) {
  passport.authenticate('google', function(err, user, info) {
    if (err) {return next(err);}
    if (!user) { 
      
      /* Envia el js para cerrar el pop up */
      let responseHTML = '<script>res = null; window.opener.postMessage(res, "*");window.close();</script>'
      return res.status(200).send(responseHTML); 
    }else{
       /* Envia el ok */
      req.logIn(user, function(err) {
        if (err) { return next(err); }
        let responseHTML = '<script>res = %value%; window.opener.postMessage(res, "*");window.close();</script>'
        responseHTML = responseHTML.replace('%value%', JSON.stringify(user._id));
       
        return res.status(200).send(responseHTML);
      });
    }
  })(req, res, next);
});

app.get("/user", (req, res) => {
  
  if(req.user){
    res.json(req.user);
  }else{
    res.json(null)
  }
  
  
});

app.get("/logout", (req, res) => {
  req.logout();
  res.send("success")
});

app.listen(PORT, () => {
    console.log(`Server Started  Listening At Port: ${PORT}`);
  });

