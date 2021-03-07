const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const usersRouter = require('express').Router();
const User = require('../models/user');
const logger = require('../utils/logger');

// this creates a new user
usersRouter.post('/', async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const body = req.body;
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(body.password, saltRounds);
  let admin = false;
  if (body.admin) {
    admin = true;
  };

  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }
  logger.info('received post to add new user');
  if (body.password.length < 3) {
    res.status(406).send ('too short password! need 3 chars min.');
  } else {
    // if password length ok, proceed
    const user = new User({
      username: body.username,
      name: body.name,
      passwordHash,
      admin: admin
    });
    const savedUser = await user.save();
    res.json(savedUser);
  }
});

// admin resets password of some other user
usersRouter.put('/reset', async (req, res) => {
  const saltRounds = 10;
  const newHash = await bcrypt.hash(req.body.newPsw, saltRounds);
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  let user = null;

  await User.findOne({username: req.body.user}, (err, doc) => {
    user = doc;
  });

  const adminRequesting = await User.findById(decodedToken.id);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }

  if (user === null ) {
    res.status(400).send('cant find user with that username');
  } else {
    if (adminRequesting) {
      // do it here
      await User.findByIdAndUpdate(user._id, { passwordHash: newHash }, (err, docs) => {
        if (err) {
          res.status(400).send(err);
        } else {
          res.status(200);
        }
      });
    }
  }
});

// user changes account password of own account
usersRouter.put('/:id', async (req, res) => {
  const saltRounds = 10;
  console.log('request to change account password!');
  const newHash = await bcrypt.hash(req.body.newPsw, saltRounds);
  const user = await User.findById(req.body.user);
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }
  if (req.body.user === decodedToken.id) {
    const passwordCorrect = user === null
      ? false
      : await bcrypt.compare(req.body.current, user.passwordHash);

    if (!(user && passwordCorrect)) {
      return res.status(401).json({
        error: 'invalid username or password'
      });
    }
    await User.findByIdAndUpdate(req.body.user, { passwordHash: newHash }, (err, docs) => {
      if (err) {
        console.log(err)
      } else {
        res.status(200);
      }
    });
  } else {
    return res.status(401).json({ error: 'not authorized to modificate' });
  }
});

module.exports = usersRouter;
