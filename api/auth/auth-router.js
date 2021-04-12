const router = require("express").Router();
const Users = require('../users/users-model');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const JWT_SECRET = require("../secrets/index.js"); // use this secret!

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.post("/register", validateRoleName, (req, res, next) => {
  const newUser = req.body;

  const hash = bcrypt.hashSync(newUser.password, 8);
  newUser.password = hash;
  
  Users.add(newUser)
    .then((createdUser) => {
      const token = generateToken(createdUser);
      res.status(201).json({...createdUser, token})
    })
    .catch(next)

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  Users.findBy({username})
    .then((foundUser) => {
      if (foundUser && bcrypt.compareSync(password, foundUser.password)) {
        const token = generateToken(foundUser);
        res.status(200).json({
          message: `${foundUser.username} is back!`,
          token
        })
      } else {
        res.status(401).json({message: "Invalid credentials"})
      }
    })
    .catch(next);
});

const generateToken = (user) => {
  const options = {
    expiresIn: '1 day'
  };

  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };
  // const secret = JWT_SECRET;

  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
