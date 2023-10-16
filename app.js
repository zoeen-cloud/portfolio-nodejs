const express = require('express');
const session = require('express-session');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const ejs = require('ejs');
require('dotenv').config();

const app = express();

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

// Express session setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.redirect('/login');
  }

  // Check login credentials from the database
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) throw err;

    if (results.length === 1) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) throw err;

        if (isMatch) {
          req.session.user = user;
          res.redirect('/dashboard');
        } else {
          res.redirect('/login');
        }
      });
    } else {
      res.redirect('/login');
    }
  });
});

app.get('/dashboard', (req, res) => {
  if (req.session.user) {
    res.render('dashboard', { user: req.session.user });
  } else {
    res.redirect('/login');
  }
});

// Existing code...

app.get('/register', (req, res) => {
    res.render('register');
  });
  
  app.post('/register', (req, res) => {
    const { username, password, email, phone } = req.body;
  
    if (!username || !password || !email || !phone) {
      return res.redirect('/register');
    }
  
    // Check if the username is already taken
    const checkQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkQuery, [username], (err, results) => {
      if (err) throw err;
  
      if (results.length === 0) {
        // If the username is available, hash the password and insert the user into the database
        bcrypt.hash(password, 10, (err, hash) => {
          if (err) throw err;
          const insertQuery = 'INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)';
          db.query(insertQuery, [username, hash, email, phone], (err) => {
            if (err) throw err;
            res.redirect('/login');
          });
        });
      } else {
        // Username is already taken
        res.redirect('/register');
      }
    });
  });
  
  // Existing code...
  

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
