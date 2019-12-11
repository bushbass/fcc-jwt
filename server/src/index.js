require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken
} = require('./tokens');
const { fakeDB } = require('./fakeDB');

// 1. Register a user
// 2. Login a user
// 3. Logout a user
// 4. Setup a protected route
// 5. Get a new accesstoken with a refresh token

const server = express();

// use express middlware for easier cookie handling
server.use(cookieParser());

server.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true
  })
);

// Need to be able to read body data

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

// 1. Register a user
server.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. check if user exists
    const user = fakeDB.find(user => user.email === email);
    if (user) throw new Error('user already exists');
    // 2. if not user exists, hash the password
    const hashedPassword = await hash(password, 10);
    // 3. insert user in database
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword
    });
    res.send({ message: 'user created' });
    console.log(fakeDB);
  } catch (err) {
    res.send({
      error: `${err.message}`
    });
  }
});

// 2. Login a user
server.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. find user in database, if not exist send error
    const user = fakeDB.find(user => user.email === email);
    if (!user) throw new Error('user does not exist');
    // 2. compare encrypted password, send error if not
    const valid = await compare(password, user.password);
    if (!valid) throw new Error('password not correct');
    // 3. create refresh and access token
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    // 4. put refresh token in database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);
    // 5. send token, refreshtoken as a cookie and accesstoken as a reqular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(res, req, accesstoken);
  } catch (err) {
    res.send({ error: `${err.message}` });
  }
});

server.listen(process.env.PORT, () =>
  console.log(`Server listening on port ${process.env.PORT}`)
);
