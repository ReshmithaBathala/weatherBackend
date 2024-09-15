// Import required libraries
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

// Initialize express app
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Secret key for JWT
const JWT_SECRET = "mysecretkey";

// Connect to SQLite Database (it will create the database if not exists)
const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    console.log("Connected to SQLite database.");
  }
});

// User Registration Endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  // Hash the password before storing it
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "Username already exists" });
      }
      res.json({ message: "User registered successfully!" });
    }
  );
});

// User Login Endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    // Compare password hash
    const isValid = bcrypt.compareSync(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  });
});

// Middleware for authenticating JWT
function authenticate(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ error: "Failed to authenticate token" });
    req.userId = decoded.userId;
    next();
  });
}

// Fetch Weather Data
app.post("/weather", authenticate, async (req, res) => {
  const { location } = req.body;
  const apiKey = process.env.REACT_APP_WEATHER_API_KEY; // Replace with your OpenWeatherMap API key

  try {
    const response = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${location}&appid=${apiKey}`
    );
    const weatherData = await response.json();

    if (weatherData.cod !== 200) {
      return res.status(400).json({ error: weatherData.message });
    }

    // Store the search history
    const timestamp = new Date().toISOString();
    db.run(
      "INSERT INTO search_history (user_id, location, weather_data, timestamp) VALUES (?, ?, ?, ?)",
      [req.userId, location, JSON.stringify(weatherData), timestamp],
      function (err) {
        if (err) {
          return res
            .status(500)
            .json({ error: "Failed to store search history" });
        }
        res.json({ weather: weatherData, message: "Search saved to history" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error fetching weather data" });
  }
});
// Get User's Search History
app.get("/history", authenticate, (req, res) => {
  db.all(
    "SELECT * FROM search_history WHERE user_id = ?",
    [req.userId],
    (err, rows) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Failed to retrieve search history" });
      }
      res.json({ history: rows });
    }
  );
});

// Delete Specific Search Entry
app.delete("/history/:id", authenticate, (req, res) => {
  const { id } = req.params;

  db.run(
    "DELETE FROM search_history WHERE id = ? AND user_id = ?",
    [id, req.userId],
    function (err) {
      if (err || this.changes === 0) {
        return res
          .status(400)
          .json({ error: "Failed to delete or entry not found" });
      }
      res.json({ message: "Search entry deleted" });
    }
  );
});

app.get("/", (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to fetch users" });
    }
    // Send the retrieved users as JSON
    res.json({ users: rows });
  });
});
// Update User Profile (Username)
app.put("/profile", authenticate, (req, res) => {
  const { username } = req.body;

  db.run(
    "UPDATE users SET username = ? WHERE id = ?",
    [username, req.userId],
    function (err) {
      if (err) {
        return res.status(500).json({ error: "Failed to update profile" });
      }
      res.json({ message: "Profile updated successfully!" });
    }
  );
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
