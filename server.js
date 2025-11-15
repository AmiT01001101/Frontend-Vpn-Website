// server/server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json()); // Allow server to accept JSON data
app.use(cors()); // Allow cross-origin requests (from your frontend)

// --- Database Connection ---
// !! Replace with your actual MongoDB Atlas connection string !!
const MONGO_URI = "mongodb+srv://amitchourasia2005_db_user:yjERMVmr7psqBhfz@cluster0.up66b43.mongodb.net/?appName=Cluster0";

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- User Model ---
// This defines the structure of the user data in the database
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true, // No two users can have the same email
    trim: true, // Removes whitespace
    lowercase: true
  },
  password: {
    type: String,
    required: true
  }
});

// This is a "pre-save hook". Before any user is saved,
// it will automatically hash their password.
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', UserSchema);

// --- API Routes ---

// 1. Register Route
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Create new user (password will be hashed by the 'pre-save' hook)
    user = new User({
      email,
      password
    });

    await user.save();

    res.status(201).json({ msg: 'User registered successfully' });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// 2. Login Route
// 2. Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Attempting login for:", email ,password); // Log the email

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      console.log("Login failed: User not found");
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // Compare submitted password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);
    
    // Check if password is correct
    if (!isMatch) {
      console.log("Login failed: Incorrect password");
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // --- Password is correct ---
    console.log("Login success: Passwords match");

    // Passwords match! Create a JSON Web Token (JWT)
    const payload = {
      user: {
        id: user.id // We'll use the user's database ID in the token
      }
    };

    // !! Create a secret key and store it securely (e.g., in an .env file) !!
    const JWT_SECRET = 'mysecretkey12345'; // Replace with a strong, random key

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '1h' }, // Token expires in 1 hour
      (err, token) => {
        if (err) throw err;
        
        // Send success message and token back to the client
        res.json({ 
          msg: 'Login successful', 
          token: token 
        });
      }
    );

    res.status(200).json({status:200, msg: 'User login successfully' });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// --- Start Server ---
const PORT = 5000;
app.listen(PORT, () => console.log(`Server started on http://localhost:${PORT}`));