const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("Token not provided");
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log("Token verification failed", err);
      return res.sendStatus(401); // Unauthorized
    }
    req.user = user;
    next();
  });
}

module.exports = {
  authenticateToken,
};
