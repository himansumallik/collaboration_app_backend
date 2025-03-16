const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const { Server } = require("socket.io");
const http = require("http");

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

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






// WebSocket connection event
io.on("connection", (socket) => {
  console.log("New client connected:", socket.id);

  // User joins their own "room" based on email
  socket.on("join", (userEmail) => {
      socket.join(userEmail);
      console.log(`${userEmail} joined room`);
  });

  // Handle user disconnect
  socket.on("disconnect", () => {
      console.log("Client disconnected:", socket.id);
  });
});

// Function to send a real-time notification to a specific user
const sendNotification = (userEmail, message) => {
  io.to(userEmail).emit("newNotification", { message });
};

// Start the server
server.listen(5001, () => {
  console.log("WebSocket server running on port 5001");
});

// Export sendNotification so we can use it elsewhere
module.exports = { sendNotification };






// Routes

app.post('/signup', (req, res) => {
  console.log(req.body); // Log the incoming data

  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    const query = 'INSERT INTO Users (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) return res.status(500).json({ message: 'Error creating user' });
      res.status(200).json({ message: 'Signup successful' });
    });
  });
});


// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM Users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ message: 'Error comparing passwords' });
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

      // Generate JWT token
      const token = jwt.sign({ user_id: user.user_id }, 'yourSecretKey', { expiresIn: '1h' });

      res.status(200).json({ success: true, token });
    });
  });
});




const authenticateToken = (req, res, next) => {
  const authHeader = req.header('Authorization'); 

  console.log("Authorization Header:", authHeader); // Debugging step

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1]; 

  try {
      const decoded = jwt.verify(token, 'yourSecretKey'); 

      console.log("Decoded Token:", decoded); // Debugging step

      req.user_id = decoded.user_id; // Ensure user_id exists in the token

      next();
  } catch (error) {
      console.error("JWT Verification Error:", error); // Debugging step
      res.status(400).json({ message: 'Invalid token' });
  }
};

app.post('/add-project', authenticateToken, (req, res) => {
  const { name, description } = req.body;
  const owner_id = req.user_id; // Extract from JWT

  if (!name || !owner_id) {
      return res.status(400).json({ message: "Project name and owner are required" });
  }

  const query = 'INSERT INTO Projects (name, description, owner_id) VALUES (?, ?, ?)';
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

app.get('/projects/:projectId/members', authenticateToken, (req, res) => {
  const { projectId } = req.params;

  const query = `
      SELECT u.user_id, u.name, pm.role 
      FROM project_members pm
      JOIN users u ON pm.user_id = u.user_id
      WHERE pm.project_id = ?`;

  db.query(query, [projectId], (err, results) => {
      if (err) {
          console.error("Database error:", err);
          return res.status(500).json({ message: 'Error fetching project members' });
      }

      res.json(results); // Send list of members
  });
});

app.get("/users/search", (req, res) => {
  console.log("Received request to /users/search"); // Debugging
  const { query } = req.query;

  if (!query || query.trim().length < 1) {
    return res.json([]); // Return empty array if query is empty
  }

  const searchQuery = `SELECT email FROM users WHERE email LIKE ? LIMIT 10`;
  db.query(searchQuery, [`%${query}%`], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(results.map(user => user.email)); // Return email array
  });
});

app.post("/invite", async (req, res) => {
  const { projectId, userEmail } = req.body;
  const senderId = req.user_id; // Assume you get this from JWT
  
  console.log(req.body); // Add this before line 247
console.log(req.user_id); // Check if it's undefined

  try {
      // Insert invitation logic (if not exists)
      db.query("INSERT INTO invitations (project_id, user_email) VALUES (?, ?)", [projectId, userEmail]);

      // Insert notification into notifications table
      db.query(
      "INSERT INTO notifications (user_email, message, sent_by) VALUES (?, ?, ?)",
      [userEmail, `You have been invited to project ${projectId}`, senderId]
    );

      // Send real-time notification using WebSocket
      sendNotification(userEmail, `You have been invited to project ${projectId}`);
  } catch (error) {
      console.error("Error adding member:", error);
      res.status(500).json({ message: "Error adding member" });
  }
});




const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});