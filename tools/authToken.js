require('dotenv').config();
const crypto = require('crypto');

const PRIVATE_KEY = process.env.PRIVATE_KEY;

const generateToken = (userEmail) => {
    // TODO: replace md5 with another algo (?argon2.argon2id)
    return crypto.createHash('md5').update(userEmail, PRIVATE_KEY).digest('hex');
}

module.exports = {
    generateToken,
}