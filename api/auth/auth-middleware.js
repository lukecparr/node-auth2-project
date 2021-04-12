const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.autorization?.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        res.status(401).json({message: 'Token invalid'})
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    })
  } else {
    res.status(401).json({ message: 'Token required'})
  }
};

const only = (role_name) => (req, res, next) => {
  const tokenPayload = req.decodedToken.payload;
  
  if (tokenPayload.role_name === role_name) {
    next();
  } else {
    res.status(403).json({ message: 'This is not for you'})
  }
};


const checkUsernameExists = (req, res, next) => {
  const { username } = req.body;

  Users.findBy({username})
    .then((user) => {
      if (user) {
        next();
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    })
    .catch(next);
};


const validateRoleName = (req, res, next) => {
  const role = req.body.role_name.trim();

  if (!role) {
    req.body.role_name = 'student';
    next();
  }
  else if (role.length > 32) {
    res.status(422).json({message: "Role name can not be longer than 32 chars" })
  }
  else if (role === 'admin') {
    res.status(422).json({message: 'Role name can not be admin' })
  }
  else if (role !== 'student' || role !== 'instructor') {
    res.status(422).json({message: 'Not a valid role' })
  }
  else {
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
