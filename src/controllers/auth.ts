import passport from 'passport'
import User from '../models/user'
import bcrypt from 'bcryptjs'
import {DatabaseUserInterface} from '../interfaces/user'

export const socialAuth =(strategyName:any)=> function(req:any, res:any, next:any) {
    passport.authenticate(strategyName, function(err, user, info) {
      if (err) {return next(err);}
      if (!user) { 
        /* Envia el js para cerrar el pop up */
        let responseHTML = '<script>res = null; window.opener.postMessage(res, "*");window.close();</script>'
        return res.status(200).send(responseHTML); 
      }else{
         /* Envia el ok */
        req.logIn(user, function(err:any) {
          if (err) { return next(err); }
          let responseHTML = '<script>res = %value%; window.opener.postMessage(res, "*");window.close();</script>'
          responseHTML = responseHTML.replace('%value%', JSON.stringify({user: user._id}));
          return res.status(200).send(responseHTML);
        });
      }
    })(req, res, next);
}

export const register  = ()=> async (req:any, res:any) => {
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
}

export const login = ()=> function(req:any, res:any, next:any) {
    passport.authenticate('local', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.sendStatus(401); }
      req.logIn(user, function(err:any) {
        if (err) { return next(err); }
        return res.status(200).json(user._id);
      });
    })(req, res, next);
  }

export const logout = ()=>  (req:any, res:any) => {
    req.logout();
    res.send("success")
  }