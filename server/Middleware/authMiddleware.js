const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ msg: 'No token' });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Invalid or expired access token' });
  }
};
