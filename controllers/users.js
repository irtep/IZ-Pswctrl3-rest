const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const usersRouter = require('express').Router();
const User = require('../models/user');
const logger = require('../utils/logger');

// this creates a new user
usersRouter.post('/', async (req, res) => {
  const body = req.body;
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(body.password, saltRounds);

  logger.info('received post to add new user');
  if (body.password.length < 3) {
    res.status(406).send ('too short password! need 3 chars min.');
  } else {
    // if password length ok, proceed
    const user = new User({
      username: body.username,
      name: body.name,
      passwordHash,
    });
    const savedUser = await user.save();
    res.json(savedUser);
  }
});

// user changes account password
usersRouter.put('/:id', async (req, res) => {
  const saltRounds = 10;
  console.log('request to change account password!', req.body);
  const newHash = await bcrypt.hash(req.body.newPsw, saltRounds);
  const user = await User.findById(req.body.user);
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }// check this...
  if (req.body.user === decodedToken.id) {
    const passwordCorrect = user === null
      ? false
      : await bcrypt.compare(req.body.current, user.passwordHash);

    if (!(user && passwordCorrect)) {
      return res.status(401).json({
        error: 'invalid username or password'
      });
    }
    // has req.body.newPsw first
    console.log('new hash: ', newHash);
    await User.findByIdAndUpdate(req.body.user, passwordHash, newHash);
    // check if current is same as hashed...if ok, do it, if false, wrong current.
    //logger.info('got password: ', password);
    //password[field] = newValue;
    // make the modification
    //await Password.findByIdAndUpdate(req.params.id, password, { new: true });
    res.json('all ok!');
  } else {
    return res.status(401).json({ error: 'not authorized to modificate' });
  }
});
/*
loginRouter.post('/', async (request, response) => {
  const body = request.body;
  const user = await User.findOne({ username: body.username });
  const passwordCorrect = user === null
    ? false
    : await bcrypt.compare(body.password, user.passwordHash);

  if (!(user && passwordCorrect)) {
    return response.status(401).json({
      error: 'invalid username or password'
    });
  }

  const userForToken = {
    username: user.username,
    id: user._id,
  };

  const token = jwt.sign(userForToken, process.env.SECRET);

  response
    .status(200)
    .send({ token, username: user.username, name: user.name, id: user._id });
});
*/
// show all users
/* disabled as not needed
//modificate any field
passwordsRouter.put('/:id', async (req, res) => {
  console.log('edit request!');
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const field = req.body.field;
  let newValue = req.body.newValue;
  if (req.body.field === 'password') {
    const iv = crypto.randomBytes(16);
    newValue = encrypt(req.body.newValue, iv);
  }
  const password = await Password.findById(req.params.id);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }
  if (password.user.toString() === decodedToken.id) {
    logger.info('got password: ', password);
    password[field] = newValue;
    // make the modification
    await Password.findByIdAndUpdate(req.params.id, password, { new: true });
    res.json(password);
  } else {
    return res.status(401).json({ error: 'not authorized to modificate' });
  }
});
*/
module.exports = usersRouter;
