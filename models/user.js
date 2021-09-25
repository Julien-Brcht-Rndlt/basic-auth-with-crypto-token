const connection = require('../db-config');
const Joi = require('joi');
const argon2 = require('argon2');

const db = connection.promise();

const validate = (data, forCreation = true) => {
  const presence = forCreation ? 'required' : 'optional';
  return Joi.object({
    email: Joi.string().email().max(255).presence(presence),
    firstname: Joi.string().max(255).presence(presence),
    lastname: Joi.string().max(255).presence(presence),
    city: Joi.string().allow(null, '').max(255),
    language: Joi.string().allow(null, '').max(255),
    password: Joi.string().min(9).presence(presence),
  }).validate(data, { abortEarly: false }).error;
};

const findMany = ({ filters: { language } }) => {
  let sql = 'SELECT firstname, lastname, email, city, language FROM users';
  const sqlValues = [];
  if (language) {
    sql += ' WHERE language = ?';
    sqlValues.push(language);
  }

  return db.query(sql, sqlValues).then(([results]) => results);
};

const findOne = (id) => {
  return db
    .query('SELECT firstname, lastname, email, city, language FROM users WHERE id = ?', [id])
    .then(([results]) => results[0]);
};

const findByEmail = (email) => {
  return db
    .query('SELECT firstname, lastname, email, city, language FROM users WHERE email = ?', [email])
    .then(([results]) => results[0]);
};

const findByEmailWithDifferentId = (email, id) => {
  return db
    .query('SELECT firstname, lastname, email, city, language FROM users WHERE email = ? AND id <> ?', [email, id])
    .then(([results]) => results[0]);
};

const findCredentials = (email) => {
  return db
    .query('SELECT email, hashedPassword FROM users WHERE email = ?', [email])
    .then(([results]) => results[0]);
};

const create = (data) => {
  const { firstname, lastname, email, city, language, password } = data;
  return hashPassword(password)
    .then((hashedPassword) => db.query('INSERT INTO users SET ?', {
      firstname,
      lastname,
      email,
      city,
      language,
      hashedPassword,
    }))
    .then(([result]) => {
      const id = result.insertId;
      return { id, firstname, lastname, email, city, language };
    });
};

const update = (id, newAttributes) => {
  return db.query('UPDATE users SET ? WHERE id = ?', [newAttributes, id]);
};

const destroy = (id) => {
  return db
    .query('DELETE FROM users WHERE id = ?', [id])
    .then(([result]) => result.affectedRows !== 0);
};

/**
 * Hashing configuration
 */
 const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1
};

/**
 * Hash a given password
 * @param plainPassword
 */
const hashPassword = (plainPassword) => {
  return argon2.hash(plainPassword, hashingOptions);
};

/**
 * Verify a given password against a hash
 * @param {*} plainPassword 
 * @param {*} hashedPassword 
 * @returns 
 */
const verifyPassword = (plainPassword, hashedPassword) => {
  return argon2.verify(hashedPassword, plainPassword, hashingOptions);
};

module.exports = {
  findMany,
  findOne,
  validate,
  create,
  update,
  destroy,
  findByEmail,
  findByEmailWithDifferentId,
  findCredentials,
  hashPassword,
  verifyPassword,
};
