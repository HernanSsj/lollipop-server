import passportLocal from 'passport-local'
import bcrypt from 'bcryptjs';
import User from '../models/user'
import {DatabaseUserInterface} from '../interfaces/user'


const LocalStrategy = passportLocal.Strategy

const localStrategy = new LocalStrategy({ usernameField: 'email',} ,(email: string, password: string, done) => {
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

  export default localStrategy