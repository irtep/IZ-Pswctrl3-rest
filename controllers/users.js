const bcrypt = require('bcrypt');
const usersRouter = require('express').Router();
const User = require('../models/user');
const logger = require('../utils/logger');

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

// show all users
usersRouter.get('/', async (req, res) => {
  const user = await User
    .find({}).populate('notes');

  if (user) {
    res.json(user);
  } else {
    res.status(404).end();
  }
});
/*
usersRouter.get('/', async (request, response) => {
  const users = await User
    .find({}).populate('notes')

  response.json(users.map(u => u.toJSON()))
})
*/
module.exports = usersRouter;
