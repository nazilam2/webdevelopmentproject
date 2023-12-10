const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const path = require('path'); // Required for working with file paths

const app = express();
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Mysql123##',
  database: 'new_schema',
  authPlugin: 'mysql_native_password' ,
});

connection.connect();

// Registration Endpoint
// Registration Endpoint
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
  
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Save user to the database
    connection.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err, result) => {
      if (err) {
        res.status(500).json({ error: 'Failed to register' });
      } else {
        res.status(200).json({ message: 'User registered successfully' });
      }
    });
  });
  
// Login Endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Fetch user from the database by username
  connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) {
      res.status(401).json({ error: 'Invalid username or password' });
    } else {
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const token = jwt.sign({ userId: user.id }, 'your_secret_key', { expiresIn: '1h' }); // Create JWT token
        res.status(200).json({ token });
      } else {
        res.status(401).json({ error: 'Invalid username or password' });
      }
    }
  });
});

// Read all users Endpoint
app.get('/users', (req, res) => {
    connection.query('SELECT * FROM users', (err, results) => {
      if (err) {
        res.status(500).json({ error: 'Failed to fetch users' });
      } else {
        res.status(200).json(results);
      }
    });
  });



// Update user Endpoint
// Update user Endpoint
app.put('/update/:id', (req, res) => {
    const { username, email } = req.body;
    const userId = req.params.id;
  
    connection.query(
      'UPDATE users SET username = ?, email = ? WHERE id = ?',
      [username, email, userId],
      (err, result) => {
        if (err) {
          res.status(500).json({ error: 'Failed to update user' });
        } else {
          res.status(200).json({ message: 'User updated successfully' });
        }
      }
    );
  });


  // Delete user Endpoint
// Delete user by email Endpoint
app.delete('/delete/:email', (req, res) => {
  const userEmail = req.params.email;

  connection.query('DELETE FROM users WHERE email = ?', [userEmail], (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Failed to delete user' });
    } else if (result.affectedRows === 0) {
      res.status(404).json({ error: 'User not found' });
    } else {
      res.status(200).json({ message: 'User deleted successfully' });
    }
  });
});



// Middleware for JWT authentication
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1]; // Get token from header

  if (token == null) {
    return res.status(401).json({ error: 'Authentication token missing' });
  }

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user; // Set user in request object
    next();
  });
}

// Protected route example (requires authentication)
app.get('/profile', authenticateToken, (req, res) => {
  // Access user data from request object (req.user)
  res.json(req.user);
});


  

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the index.html file as the default route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
  });

// Define a route to serve the login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});