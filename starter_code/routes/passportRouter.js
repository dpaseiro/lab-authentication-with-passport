const express        = require("express");
const router         = express.Router();
// User model
const User           = require("../models/user");
// Bcrypt to encrypt passwords
const bcrypt         = require("bcrypt");
const bcryptSalt     = 10;
const ensureLogin = require("connect-ensure-login");
const passport      = require("passport");



// SIGNUP
router.get("/signup", (req, res, next) => {
  res.render("passport/signup");
});

router.post('/signup', (req, res, next)=>{
  const thePassword   = req.body.password;
  const theUsername   = req.body.username;
  
  if(thePassword === "" || theUsername === ""){
      res.render('passport/signup', {errorMessage: 'Please fill in both '});
      return;
  }

User.findOne({username: theUsername})
.then((responseFromDB)=>{
  if(responseFromDB !== null){
      res.render('passport/signup', {errorMessage: ` Someone already has ${theUsername}`})
      return;
  }
  
  
  const salt          = bcrypt.genSaltSync(10);
  const hashPassword  = bcrypt.hashSync(thePassword, salt);
      User.create({username: theUsername, password: hashPassword})
      .then((response)=>{
          res.redirect('/login')
      })
      .catch((err)=>{
          next(err)
      });
  })
});

// LOGIN
router.get('/login', (req, res, next)=>{
  res.render('passport/login', { message: req.flash("error") });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/private",
  failureRedirect: "/signup",
  failureFlash: true,
  passReqToCallback: true
}));

// PRIVATE
router.get("/private", (req, res, next) => {
  res.render("passport/private", {user: req,user});
});




// LOGOUT
router.get("/logout", (req, res, next) => {
    req.logout();
    res.redirect("/passport/login");
});


module.exports = router;