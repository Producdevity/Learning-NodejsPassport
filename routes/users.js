var express = require('express');
var router = express.Router();

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/User');

/* GET Register. */
router.get('/register', ensureAuthenticated, function(req, res) {
  res.render('register', { title: 'Register' });
});

/* GET Login */
router.get('/login', ensureAuthenticated, function(req, res) {
  res.render('login', { title: 'Login' });
});

/* POST Register User */
router.post('/register', function(req, res) {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;
  var password2 = req.body.password2;

  //  Validation
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'Email is required').notEmpty();
  req.checkBody('email', 'Email is not a valid').isEmail();
  req.checkBody('password', 'Password is required').notEmpty();
  req.checkBody('password', 'Password requires 4 to 20 characters').len(4, 20);
  req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

  var errors = req.validationErrors();

  if(errors){
    res.render('register', {errors: errors});
  } else {
    var newUser = new User({
      name: name,
      email:email,
      password: password
    });

    User.createUser(newUser, function(err, user){
      if(err) throw err;
      console.log(user);
    });

    req.flash('success_msg', 'You are registered and can now login');
    res.redirect('/users/login');
  }

});

passport.use(new LocalStrategy({usernameField: 'email'},
  function(username, password, done){
    User.getUserByEmail(username, function(err, user){
      console.log(username);
      if(err) throw err;
      if(!user){
        return done(null, false, { message: 'Incorrect email.' });
      }
      User.comparePassword(password, user.password, function(err, isMatch){
        if(err) throw err;
        if(isMatch){
          console.log('isMatch'+user);
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    console.log('getUserById '+user);
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/users/login',
    failureFlash: true
  }),
  function(req, res) {
    // If this function gets called, authentication was successful.
    // `req.user` contains the authenticated user.
    // res.redirect('/users/' + req.user.username);
    console.log(req.user);
    res.redirect('/');
  });

router.get('/logout', function(req, res){
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

router.get('/me', function(req, res){
  res.send(req.isAuthenticated());
});

function ensureAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    res.redirect('/');
  } else {
    return next();
  }
}

module.exports = router;
