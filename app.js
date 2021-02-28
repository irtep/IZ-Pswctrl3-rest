const config = require('./utils/config');
const express = require('express');
const app = express();
require('express-async-errors');
const cors = require('cors'); // can enable for dev purposes
const usersRouter = require('./controllers/users');
const passwordsRouter = require('./controllers/passwords');
const loginRouter = require('./controllers/login');
const middleware = require('./utils/middleware');
const logger = require('./utils/logger');
const mongoose = require('mongoose');

logger.info('connecting to mongodb');

mongoose.connect(config.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, useCreateIndex: true })
  .then(() => {
    logger.info('connected to MongoDB');
  })
  .catch((error) => {
    logger.error('error connection to MongoDB:', error.message);
  });

app.use(cors()); // can enable for dev purposes
app.use(express.static('build'));
app.use(express.json());
app.use(middleware.requestLogger);
app.use(middleware.tokenExtractor);

app.use('/api/users', usersRouter);
app.use('/api/passwords', passwordsRouter);
app.use('/api/login', loginRouter);
app.get('/ping/', (req, res) => {
  console.log('someone pinged!');
  res.send('ping ok!');
});

if (process.env.NODE_ENV === 'test') {
  console.log('on test mode!');
  const testingRouter = require('./controllers/testing');
  app.use('/api/testing', testingRouter);
}

app.use(middleware.unknownEndpoint);
app.use(middleware.errorHandler);

module.exports = app;
