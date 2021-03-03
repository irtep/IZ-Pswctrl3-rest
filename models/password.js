const mongoose = require('mongoose');

const passwordSchema = mongoose.Schema({
  page: {
    type: String,
    minLength: 3,
    required: true },
  username: {
    type: String,
    minLength: 3,
    required: true },
  password: { type: Object,
    required: true },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
});
passwordSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString();
    delete returnedObject._id;
    delete returnedObject.__v;
  }
});
const Password = mongoose.model('Password', passwordSchema);

module.exports = Password;
