const blogsRouter = require('express').Router();
const Blog = require('../models/blog');
const User = require('../models/user');
const logger = require('../utils/logger');
const jwt = require('jsonwebtoken');

// show all blogs
blogsRouter.get('/', async (req, res) => {
  const blog = await Blog
    .find({}).populate('user', { username: 1, name: 1 });
  if (blog) {
    res.json(blog);
  } else {
    res.status(404).end();
  }
});

// add a blog
blogsRouter.post('/', async (req, res) => {
  const body = req.body;
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  if (!req.token || !decodedToken.id) {
    return res.status(401).json({ error: 'token missing or invalid' });
  }
  const user = await User.findById(decodedToken.id);

  const blog = new Blog({
    title: body.title,
    author: body.author,
    url: body.url,
    likes: body.likes,
    user: user
  });

  const savedBlog = await blog.save();
  user.notes = user.notes.concat(savedBlog._id);
  await user.save();
  res.json(savedBlog.toJSON());
});

// add a comment
blogsRouter.post('/:id/comments', async (req, res) => {
  const comment = req.body.comment;
  // get blog that user wants to edit
  const blog = await Blog.findById(req.params.id);
  blog.comments.push(comment);
  logger.info('blog now: ', blog);

  // make the modification
  await Blog.findByIdAndUpdate(req.params.id, blog, { new: true });
  res.json(blog);
});

// show a blog with certain id
blogsRouter.get('/:id', async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (blog) {
    res.json(blog.toJSON());
  } else {
    res.status(404).end();
  }
});

// delete blog
blogsRouter.delete('/:id', async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.SECRET);
  const blog = await Blog.findById(req.params.id);
  if (blog.user.toString() === decodedToken.id) {
    await Blog.findByIdAndRemove(req.params.id);
    res.status(204).end();
  } else {
    return res.status(401).json({ error: 'not authorized to delete' });
  }
});

//modificate blog
blogsRouter.put('/:id', async (req, res) => {
  const field = req.body.field;
  const newValue = req.body.newValue;

  // get blog that user wants to edit
  const blog = await Blog.findById(req.params.id);
  logger.info('got blog: ', blog);
  blog[field] = newValue;

  // make the modification
  await Blog.findByIdAndUpdate(req.params.id, blog, { new: true });
  res.json(blog);
});

module.exports = blogsRouter;
