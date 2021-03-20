import passport from 'passport'
import User from '../models/user'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import config from '../config'
import {DatabaseUserInterface} from '../interfaces/user'

function createToken(user:any, stayConnected:boolean) {

  const expireDate = stayConnected ? {expiresIn: config.jwt.permanent} : {expiresIn: config.jwt.temporal}

  return jwt.sign({ id: user.id, email: user.email }, config.jwt.secret, expireDate);
}

export const socialAuth =(strategyName:any)=> function(req:any, res:any, next:any) {
    passport.authenticate(strategyName, {session: false }, function(err, user, info) {
      if (err) {return next(err);}
      if (!user) { 
        /* Envia el js para cerrar el pop up */
        let responseHTML = '<script>res = null; window.opener.postMessage(res, "*");window.close();</script>'
        return res.status(200).send(responseHTML); 
      }else{
         /* Envia el token*/
         try {
          let responseHTML = '<script>res = %value%; window.opener.postMessage(res, "*");window.close();</script>'
          const token = createToken(user, true)
          responseHTML = responseHTML.replace('%value%', JSON.stringify(token));
          return res.status(200).send(responseHTML);
         } catch (error) {
          return next(error)
         }
      }
    })(req, res, next);
}

export const register  = async (req:any, res:any) => {
    const { name, email, password, repeated_password} = req?.body;
    
    if (!name || !email || !password || typeof email !== "string" || typeof password !== "string" || password !== repeated_password) {
  
      res.status(400).json({Message:"Invalid params"});
  
    }
    
    User.findOne({ email }, async (err: any, doc: DatabaseUserInterface) => {
      if (err) throw err;
      if (doc)  return res.status(409).json({Message: "User Already Exists"});
      if (!doc) {
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
          name,
          email,
          password: hashedPassword,
        });
        await newUser.save();
        
        return res.status(200).json({Message:"User created sucesfully"})
      }
    })
}

// export const login = (req:any, res:any, next:any) => {
//     passport.authenticate('local', function(err, user, info) {
//       if (err) { return next(err); }
//       if (!user) { return res.sendStatus(401); }
//       req.logIn(user, function(err:any) {
//         if (err) { return next(err); }
//         return res.status(200).json(user._id);
//       });
//     })(req, res, next);
//   }


export const login = (req:any, res:any) =>{
  const {email, password, stayConnected} = req.body
  if(!email || !password){
    return res.status(400).json({Message:"missing params"})
  }
  User.findOne({ email }, async (err: any, doc: DatabaseUserInterface) => {
    if (err) throw err;
    if (!doc) {
      return res.status(400).json({Message:"User not found"})
    }
    const match  = await bcrypt.compare(password, doc.password)
    if(match){
      return res.status(400).json({ token: createToken(doc, stayConnected) })
    }
    return res.status(400).json({msg: "incorrect email or password"});
  })
}

export const logout = (req:any, res:any) => {
    res.send("This does nothing delete the token")
  }