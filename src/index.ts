import mongoose from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import User, {SocialUser} from './models/user'
import  passportConfig  from './passport/passport'
import config from './config'
import {UserInterface, SocialUserInterface, DatabaseUserInterface} from './interfaces/user'



mongoose.connect(config.db.CONECCTION_URL, config.db.PARAMS, (err) => {

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
passportConfig(passport)


app.get('/auth/twitter',passport.authenticate('twitter'));

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

app.listen(config.app.PORT, () => {
    console.log(`Server Started  Listening At Port: ${config.app.PORT}`);
  });

