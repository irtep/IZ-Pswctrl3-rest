const passwordsRouter = require('express').Router();
const Password = require('../models/password');
const User = require('../models/user');
const logger = require('../utils/logger');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// show all passwords
passwordsRouter.get('/', async (req, res) => {
  const password = await Password
    .find({}).populate('user', { username: 1, name: 1 });
  if (password) {
    res.json(password);
  } else {
    res.status(404).end();
  }
});
/*
// delete password
passwordsRouter.delete('/:id', async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const password = await Password.findById(req.params.id);
  if (password.user.toString() === decodedToken.id) {
    await Password.findByIdAndRemove(req.params.id);
    res.status(204).end();
  } else {
    return res.status(401).json({ error: 'not authorized to delete' });
  }
});
*/
// add a password
passwordsRouter.post('/', async (req, res) => {
  const body = req.body;
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(body.password, saltRounds);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }
  const user = await User.findById(decodedToken.id);

  const password = new Password({
    page: body.page,
    username: body.username,
    password: passwordHash,
    user: user
  });

  const savedPassword = await password.save();
  user.notes = user.notes.concat(savedPassword._id);
  await user.save();
  res.json(savedPassword.toJSON());
});

// add a comment
passwordsRouter.post('/:id/comments', async (req, res) => {
  const comment = req.body.comment;
  // get password that user wants to edit
  const password = await Password.findById(req.params.id);
  password.comments.push(comment);
  logger.info('password now: ', password);

  // make the modification
  await Password.findByIdAndUpdate(req.params.id, password, { new: true });
  res.json(password);
});

// show a password with certain id
passwordsRouter.get('/:id', async (req, res) => {
  const password = await Password.findById(req.params.id);
  if (password) {
    res.json(password.toJSON());
  } else {
    res.status(404).end();
  }
});

// delete password
passwordsRouter.delete('/:id', async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const password = await Password.findById(req.params.id);
  if (password.user.toString() === decodedToken.id) {
    await Password.findByIdAndRemove(req.params.id);
    res.status(204).end();
  } else {
    return res.status(401).json({ error: 'not authorized to delete' });
  }
});

//modificate password
passwordsRouter.put('/:id', async (req, res) => {
  const field = req.body.field;
  const newValue = req.body.newValue;

  // get password that user wants to edit
  const password = await Password.findById(req.params.id);
  logger.info('got password: ', password);
  password[field] = newValue;

  // make the modification
  await Password.findByIdAndUpdate(req.params.id, password, { new: true });
  res.json(password);
});

module.exports = passwordsRouter;
