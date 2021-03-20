
import express from 'express';
import passport from 'passport'
import {getUser} from '../controllers/user'

const router = express.Router();

router.get("/", passport.authenticate('jwt'), getUser);



export default router;

  