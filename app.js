const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware

app.use(cors());

app.use(express.json());

// MySQL connection setup (using XAMPP default credentials)
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',         // Default username for XAMPP
    password: '',         // Default password for XAMPP (blank)
    database: 'taskmanagementsystem',
  });

// Connect to the database
db.connect((err) => { 
  if (err) throw err;
  console.log('Connected to the MySQL database!');
});

// Routes

app.post('/signup', (req, res) => {
  console.log("Signup request received:", req.body);

  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    console.error("Signup error: Missing fields");
    return res.status(400).json({ message: 'All fields are required' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error("Error hashing password:", err);
      return res.status(500).json({ message: 'Error hashing password' });
    }

    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) {
        console.error("Database error during signup:", err);
        return res.status(500).json({ message: 'Error creating user' });
      }
      console.log("Signup successful for email:", email);
      res.status(200).json({ message: 'Signup successful' });
    });
  });
});


app.post('/login', (req, res) => {
  console.log("Login request received:", req.body);

  const { email, password } = req.body;
  if (!email || !password) {
    console.error("Login error: Missing email or password");
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error("Database error during login:", err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (results.length === 0) {
      console.warn("Login failed: User not found for email:", email);
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ message: 'Error comparing passwords' });
      }
      if (!isMatch) {
        console.warn("Login failed: Invalid credentials for email:", email);
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign({ user_id: user.user_id }, 'yourSecretKey', { expiresIn: '1h' });

      console.log("Login successful for email:", email);
      res.status(200).json({ success: true, token });
    });
  });
});




const authenticateToken = (req, res, next) => {
  const authHeader = req.header('Authorization'); // Get token from header

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1]; // Extract token

  try {
      const decoded = jwt.verify(token, 'yourSecretKey'); // Verify token
      req.user_id = decoded.user_id; // Attach user_id to request
      next();
  } catch (error) {
      res.status(400).json({ message: 'Invalid token' });
  }
};


app.post('/add-project', authenticateToken, (req, res) => {
  const { name, description } = req.body;
  const owner_id = req.user_id; // Extract from JWT

  if (!name || !owner_id) {
      return res.status(400).json({ message: "Project name and owner are required" });
  }

  const query = 'INSERT INTO projects (name, description, owner_id) VALUES (?, ?, ?)';
  db.query(query, [name, description, owner_id], (err, result) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: 'Error inserting project' });
      }

      const project_id = result.insertId;

      // Add owner as a project member
      const memberQuery = 'INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)';
      db.query(memberQuery, [project_id, owner_id, 'Owner'], (err) => {
          if (err) {
              console.error("Error adding owner as project member:", err);
              return res.status(500).json({ message: 'Error assigning owner to project' });
          }

          // Fetch the newly created project to return complete data
          const fetchProjectQuery = 'SELECT * FROM Projects WHERE project_id = ?';
          db.query(fetchProjectQuery, [project_id], (err, projectResult) => {
              if (err) {
                  console.error("Error fetching new project:", err);
                  return res.status(500).json({ message: 'Error fetching project details' });
              }

              res.status(200).json(projectResult[0]); // Send full project details
          });
      });
  });
});


app.get('/projects', authenticateToken, (req, res) => {
  const user_id = req.user_id; // Extract user ID from JWT

  const query = 'SELECT p.* FROM projects p JOIN project_members pm ON p.project_id = pm.project_id WHERE pm.user_id = ?';

  db.query(query, [user_id], (err, results) => {
      if (err) return res.status(500).json({ message: "Database error", error: err });

      res.json(results); // Send projects as JSON response
  });
});

app.get('/projects/:projectId', authenticateToken, (req, res) => {
  const { projectId } = req.params; // Get project ID from params
  const query = 'SELECT * FROM projects WHERE project_id = ?'; // Search by ID instead of name

  db.query(query, [projectId], (err, result) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: 'Error fetching project' });
      }

      if (result.length === 0) {
          return res.status(404).json({ message: 'Project not found' });
      }

      res.json(result[0]); // Send the project details
  });
});




const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
