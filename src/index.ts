import mongoose from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import  passportConfig  from './passport/passport'
import config from './config'
import authRoutes from './routes/auth'
import userRoutes from './routes/user'

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

app.get('/', (req,res)=>{
  res.send('Lollipop server')
})
app.use('/auth', authRoutes)
app.use('/user', userRoutes)


app.listen(config.app.PORT, () => {
    console.log(`Server Started  Listening At Port: ${config.app.PORT}`);
  });

