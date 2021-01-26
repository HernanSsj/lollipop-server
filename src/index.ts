import mongoose from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv'
import User from './models/user'
import {UserInterface, DatabaseUserInterface} from './interfaces/user'

const LocalStrategy = passportLocal.Strategy

dotenv.config();

const CONECCTION_URL:string = process.env.CONECCTION_URL!
const PORT = process.env.port || 5000

mongoose.connect(CONECCTION_URL, {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true
  }, (err) => {
    if (err) throw err;
    console.log("Connected To Mongo")
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

passport.use(new LocalStrategy({ usernameField: 'email',} ,(email: string, password: string, done) => {
  User.findOne({ email: email }, (err: any, user: DatabaseUserInterface) => {
    if (err) throw err;
    if (!user) return done(null, false);
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

passport.serializeUser((user: DatabaseUserInterface, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err: any, user: DatabaseUserInterface) => {
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
  console.log(req.body)
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

app.post("/login", passport.authenticate("local"), (req, res) => {

   res.send("success")
});

app.get("/user", (req, res) => {
  
  res.send(req.user);
  
});

app.get("/logout", (req, res) => {
  req.logout();
  res.send("success")
});

app.listen(PORT, () => {
    console.log(`Server Started  Listening At Port: ${PORT}`);
  });

