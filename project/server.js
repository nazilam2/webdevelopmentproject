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
// Update user Endpoint
// Update User Endpoint with Authentication
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




// Delete user by email Endpoint
app.delete('/delete/:email', authenticateToken, (req, res) => {
  const userEmail = req.params.email;
  const tokenUserId = req.user.userId; // Get the user ID from the token

  connection.query('SELECT id FROM users WHERE email = ?', [userEmail], (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Failed to delete user' });
    } else if (result.length === 0) {
      res.status(404).json({ error: 'User not found' });
    } else {
      const userId = result[0].id;

      // Check if the user ID from the token matches the user ID obtained from the email
      if (userId !== tokenUserId) {
        return res.status(401).json({ error: 'Unauthorized to delete this user' });
      }

      // Proceed with the deletion if the user is authorized
      connection.query('DELETE FROM users WHERE email = ?', [userEmail], (err, result) => {
        if (err) {
          res.status(500).json({ error: 'Failed to delete user' });
        } else if (result.affectedRows === 0) {
          res.status(404).json({ error: 'User not found' });
        } else {
          res.status(200).json({ message: 'User deleted successfully' });
        }
      });
    }
  });
});




// ... (rest of your code remains unchanged)




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


// Protected route for fetching users (requires authentication)
app.get('/users', authenticateToken, (req, res) => {
  // Access user data from request object (req.user)
  // Check if user is authenticated
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }

  // If the user is authenticated, proceed to fetch and return users
  // Code to fetch and return users goes here...
});

// Protected route example (requires authentication)
// Protected route for user profile (requires authentication)
app.get('/profile', authenticateToken, (req, res) => {
  // Access user data from request object (req.user)
  // Fetch the user's profile data based on req.user.userId
  const userId = req.user.userId; // Assuming this is how you store user ID in the token

  // Fetch and display the user's profile
  connection.query('SELECT * FROM users WHERE id = ?', [userId], (err, result) => {
    if (err || result.length === 0) {
      res.status(404).json({ error: 'User profile not found' });
    } else {
      const userProfile = result[0]; // Assuming it returns only one user

      // Send the user's profile data as JSON
      res.status(200).json(userProfile);
    }
  });
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