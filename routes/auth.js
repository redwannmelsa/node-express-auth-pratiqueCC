// Importing necessary modules
var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var LocalStrategy = require('passport-local');
var GoogleStrategy = require('passport-google-oidc');
var FacebookStrategy = require('passport-facebook')
var OpenIdConnectStrategy = require('passport-openidconnect')
var db = require('../db');
require('dotenv').config()

// local strategy
passport.use(new LocalStrategy(function verify(username, password, cb) {
  db.get('SELECT * FROM users WHERE username = ?', [username], function (err, row) {
    if (err) {
      return cb(err);
    }
    if (!row) {
      return cb(null, false, { message: 'Incorrect username or password' });
    }
    crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
      if (err) {
        return cb(err);
      }
      if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
        return cb(null, false, { message: 'Incorrect username or password' });
      }
      return cb(null, row);
    });
  });
}));

// Google auth strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/oauth2/redirect/google',
  scope: ['openid', 'profile', 'email']
}, function verify(issuer, profile, cb) {
  console.log(`google login process: issuer=${JSON.stringify(issuer)} profile=${JSON.stringify(profile)}`)
  db.get('SELECT * FROM federated_credentials WHERE provider = ? and subject = ?',
    [issuer, profile.id], function (err, row) {
      if (err) { return next(err) }
      if (!row) {
        db.run('INSERT INTO users (name) VALUES (?)', [profile.displayName], function (err) {
          if (err) return cb(err)
          var id = this.lastID
          db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)',
            [id, issuer, profile.id], function (err) {
              if (err) return cb(null)
              var user = { id: id, name: profile.displayName }
              return cb(null, user);
            })
        });
      } else {
        db.get('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, row) {
          if (err) {
            return cb(err);
          }
          if (!row) {
            return cb(null, false);
          }
          return cb(null, row);
        });
      }
    });
}));

// Facebook auth strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FAECBOOK_CLIENT_SECRET,
  callbackURL: '/oauth2/redirect/facebook',
  state: true
}, function verify(accessToken, refreshToken, profile, cb) {
  db.get('SELECT * FROM federated_credentials WHERE provider = ? and subject = ?',
    ['https://www.facebook.com', profile.id],
    function (err, row) {
      if (err) { return cb(err); }
      if (!row) {
        db.run('INSERT INTO users (name) VALUES (?)', [profile.displayName], function (err) {
          if (err) return cb(err);
          var id = this.lastID;
          db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)',
            [id, 'https://www.facebook.com', profile.id], function (err) {
              if (err) return cb(err);
              var user = { id: id, name: profile.displayName };
              return cb(null, user);
            });
        });
      } else {
        db.get('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, row) {
          if (err) {
            return cb(err);
          }
          if (!row) {
            return cb(null, false);
          }
          return cb(null, row);
        });
      }
    });
}));

// openidconnect strategy
passport.use(new OpenIdConnectStrategy({
  issuer: 'https://' + process.env.AUTH0_DOMAIN + '/',
  authorizationURL: 'https://' + process.env.AUTH0_DOMAIN + '/authorize',
  tokenURL: 'https://' + process.env.AUTH0_DOMAIN + '/oauth/token',
  userInfoURL: 'https://' + process.env.AUTH0_DOMAIN + '/userinfo',
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/oauth2/redirect',
  scope: ['profile']
}, function verify(issuer, profile, cb) {
  return cb(null, profile)
}))

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});


// Routes
router.get('/signup', function (req, res, next) {
  res.render('signup');
});

// router.get('/login', function (req, res, next) {
//   res.render('login');
// });

// google
router.get('/login/federated/google', passport.authenticate('google'));
router.get('/oauth2/redirect/google', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login'
}))

// facebook
router.get('/login/federated/facebook', passport.authenticate('facebook'));
router.get('/oauth2/redirect/facebook', passport.authenticate('facebook', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

// auth0
router.get('/login', passport.authenticate('openidconnect'))
router.get('/oauth2/redirect', passport.authenticate('openidconnect', {
  successRedirect: '/',
  failureRedirect: '/login'
}))

router.post('/signup', function (req, res, next) {
  var salt = crypto.randomBytes(16);

  crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function (err, hashedPassword) {
    if (err) {
      return next(err);
    }

    db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)',
      [req.body.username, hashedPassword, salt],
      function (err) {
        if (err) {
          return next(err);
        }

        var user = {
          id: this.lastID,
          username: req.body.username
        };

        req.login(user, function (err) {
          if (err) {
            return next(err);
          }
          res.redirect('/');
        });
      });
  });
});


router.post('/login/password', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

router.post('/logout', function (req, res, next) {
  debug('route post /logout');
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
      res.status(500).send('Internal Server Error');
    } else {
      console.log('Logout ok: redirect to "/"');
      // Redirect or respond as needed after session destruction
      res.redirect('/'); // Redirect to the login page, for example
    }
  });
});


module.exports = router;
