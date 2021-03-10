const passwordsRouter = require('express').Router();
const Password = require('../models/password');
const User = require('../models/user');
const logger = require('../utils/logger');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const key = Buffer.alloc(32, process.env.FORKEY);

function encrypt(text, iv) {
  let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
};

function decrypt(text) {
  let iv = Buffer.from(text.iv, 'hex');
  let encryptedText = Buffer.from(text.encryptedData, 'hex');
  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
};

// show all passwords
passwordsRouter.get('/', async (req, res) => {
  const algorithm = process.env.ALGO;
  const decodedToken = jwt.verify(req.token, process.env.SECRET);

  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }

  const passwords = await Password
    .find({}).populate('user', { username: 1, name: 1 });

  if (passwords) {
    const decryptPsws = passwords.map( psw => {
      const decrypted = decrypt(psw.password, key);
      psw.password = decrypted;
    });
    const onlyUsersPsws = passwords.filter( pswx => pswx.user.id === decodedToken.id);
    res.json(onlyUsersPsws);
  } else {
    res.status(404).end();
  }
});

// add a password
passwordsRouter.post('/', async (req, res) => {
  const algorithm = process.env.ALGO;
  const iv = crypto.randomBytes(16);
  const body = req.body;
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const encrypted = encrypt(body.password, iv);

  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }

  const user = await User.findById(decodedToken.id);

  const password = new Password({
    page: body.page,
    username: body.username,
    password: encrypted,
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
  const password = await Password.findById(req.params.id);

  password.comments.push(comment);
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

//modificate any field
passwordsRouter.put('/:id', async (req, res) => {
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
    password[field] = newValue;
    // make the modification
    await Password.findByIdAndUpdate(req.params.id, password, { new: true });
    res.json(password);
  } else {
    return res.status(401).json({ error: 'not authorized to modificate' });
  }
});

module.exports = passwordsRouter;
