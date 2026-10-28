const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authorization.slice("Bearer ".length);

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "phase7-full-auth",
      audience: "phase7-api",
    });

    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
}

module.exports = { requireAuth, requireRole };