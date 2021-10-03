const authRouter = require('express').Router();
const User = require('../models/user');
const { generateToken } = require('../tools/authToken'); 

const WRONG_CREDENTIALS = 'Wrong credentials';

const checkCredentials = (req, res, next) => {
    const { email, password } = req.body;
    User.findCredentials(email)
      .then((authInfos) => {
          if(!authInfos) {
            return Promise.reject(new Error(WRONG_CREDENTIALS));
          }
          return User.verifyPassword(password, authInfos.hashedPassword);
      })
      .then((isVerified) => {
        if(!isVerified){
          return Promise.reject(new Error(WRONG_CREDENTIALS));
        }
        next();
      })
      .catch((err) => {
        if(err.message === WRONG_CREDENTIALS){
            res.status(401).json({ message: 'Unauthorized...'})
        } else {
            res.status(500).json({ message: `Error: ${err.message}`});
        }
      });
};

authRouter.post('/login', checkCredentials, (req, res) => {
    const { email } = req.body;
    res.status(200).json({ token: generateToken(email) });
});

module.exports = authRouter;