const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  userId: String,
  token: String,
  createdAt: { type: Date, default: Date.now, expires: '7d' } // auto delete after 7d
});

module.exports = mongoose.model('Token', tokenSchema);
