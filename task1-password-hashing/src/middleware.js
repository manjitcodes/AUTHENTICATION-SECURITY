
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      error: {
        message: "Authentication required",
        code: "Unauthorized",
      },
    });
  }

  next();
}

function requireRole(role) {
  return function (req, res, next) {
    // Always use the authenticated session, not client-supplied role data.
    const user = req.session?.user;

    if (!user) {
      return res.status(401).json({
        error: {
          message: "Authentication required",
          code: "Unauthorized",
        },
      });
    }

    if (user.role !== role) {
      return res.status(403).json({
        error: {
          message: "Insufficient permissions",
          code: "Forbidden",
        },
      });
    }

    next();
  };
}

module.exports = { requireAuth, requireRole };
