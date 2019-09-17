const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth');
const { check, validationResult } = require('express-validator');

const User = require('../models/User');

// @route   GET api/auth
// @desc    Get logged in user
// @access  privtate
router.get('/', auth, async (req, res) => {
  try {
    // Send req.user.id into the payload from auth middleware function
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST api/auth
// @desc    Auth user and get token
// @access  private
router.post(
  '/',
  // Express Validator to check Login-Credentials
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
  ],
  async (req, res) => {
    // Throw Errors if Any of Above are true
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Destructure the Request Body
    const { email, password } = req.body;

    try {
      //See if User Exists
      let user = await User.findOne({ email: email });
      if (!user) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }

      // Use Bcrypt compare to see if password is correct
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }

      // Send JWT so that user is automatically logged in
      const payload = {
        user: {
          id: user.id
        }
      };

      // To generate a token, we have to "sign" it
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 360000
        },
        (err, token) => {
          if (err) throw err;
          // Return token if successful
          res.json({ token });
        }
      );
    } catch (err) {
      console.err(err.message);
      res.status(500).send({ msg: 'Server Error' });
    }
  }
);

module.exports = router;
