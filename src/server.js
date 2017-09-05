const bodyParser = require('body-parser');
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const User = require('./user');

const server = express();

// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(cors());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
  resave: true,
  saveUninitialized: false
}));


/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

// TODO: implement routes
server.post('/users', (req, res) => {
  // we need to have this check, user could end up signing up with no password
  const { username, password } = req.body;
  if (!password) {
    sendUserError('Must provide password', res);
    return;
  }
  // bcrypt already comes with salt, so don't need to provide that info
  bcrypt.hash(password, 11, (err, hash) => {
    if (err) {
      sendUserError('couldn\'t hash password', res);
      return;
    }

    // this will generate a user record with a hash password on it
    const user = new User({ username, password: hash });

    // this error is if the username is not unique
    user.save((err, user) => {
      if (err) {
        sendUserError(err, res);
        return;
      }
      res.json(user);
    });
  });
});

server.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username) {
    sendUserError('Must provide username', res);
    return;
  }
  if (!password) {
    sendUserError('Must provide password', res);
    return;
  }
  // looks for the user in the database
  User.findOne({ username }, (err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }
    if (!user) {
      sendUserError('Bad credentials', res);
      return;
    }
    // we take what password was given, bcrypt the new given password and compare
    // we hash the password and check if it matches
    bcrypt.compare(password, user.password, (compareErr, valid) => {
      if (compareErr) {
        sendUserError(compareErr, res);
        return;
      }
      if (!valid) {
        sendUserError('Bad credentials', res);
        return;
      }
      // if it matches we session the user and send back to the client
      req.session.username = user.username;
      res.json({ success: true });
    });
  });
});

server.post('/logout', (req, res) => {
  if (!req.session.username) {
    sendUserError('Must be logged in', res);
    return;
  }
  // keeps track when a user is logged in
  req.session.username = null;
  res.json({ success: true });
});

const ensureLoggedIn = (req, res, next) => {
  const { username } = req.session;
  if (!username) {
    sendUserError('Must be logged in', res);
    return;
  }

  User.findOne({ username }, (err, user) => {
    if (err) {
      sendUserError(err, res);
    } else if (!user) {
      sendUserError('Must be logged in', res);
    } else {
      req.user = user;
      next();
    }
  });
};

// this is the routes we want to protect
// TODO: add local middleware to this route to ensure the user is logged in
server.get('/me', ensureLoggedIn, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

server.get('/restricted/users', (req, res) => {
  User.find({})
    .exec()
    .then((users) => {
      res.json(users);
    })
    .catch((err) => {
      sendUserError(err, res);
    });
});

const checkRestricted = (req, res, next) => {
  const path = req.path;
  if (/restricted/.test(path)) {
    if (!req.session.username) {
      sendUserError('Must be logged in to access a restricted path', res);
    }
  }
  next();
};
// used as a middleware to check restricted paths
server.use(checkRestricted);

module.exports = { server };
