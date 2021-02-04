import express from 'express';
import passport from 'passport'
import {socialAuth, register, login, logout} from '../controllers/auth'

const router = express.Router();

router.get("/twitter", passport.authenticate('twitter'));

router.get('/twitter/callback', socialAuth('twitter'));

router.get('/facebook', passport.authenticate("facebook",{scope: ["public_profile", "email"]}));

router.get('/facebook/callback', socialAuth('facebook'));

router.get("/google", passport.authenticate("google", {scope: ["profile", "email"]}));
  
router.get('/google/redirect', socialAuth('google'));

router.post('/register', register());
  
router.post('/login', login());
  
router.get("/logout", logout());
  

export default router;