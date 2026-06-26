const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for frontend requests
app.use(cors({
  origin: '*', // In production, replace with specific origins like GitHub Pages URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Increase body parser limit to support Base64 image uploads
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/product-catalog';
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Successfully connected to MongoDB.');
    seedAdminUser();
  })
  .catch(err => {
    console.error('Error connecting to MongoDB:', err.message);
  });

// Schemas & Models
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true }
});

const productSchema = new mongoose.Schema({
  images: [{ type: String, required: true }], // Array of Base64 Data URL strings
  code: { type: String, required: true, unique: true, trim: true },
  name: { type: String, required: true, trim: true },
  price: { type: Number, required: true },
  description: { type: String, required: true, trim: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// Helper function to seed admin user if none exists
async function seedAdminUser() {
  try {
    const adminExists = await User.findOne({ email: process.env.ADMIN_EMAIL || 'admin@example.com' });
    if (!adminExists) {
      const email = process.env.ADMIN_EMAIL || 'admin@example.com';
      const rawPassword = process.env.ADMIN_PASSWORD || 'admin123';
      const hashedPassword = await bcrypt.hash(rawPassword, 10);
      
      const admin = new User({
        email: email,
        password: hashedPassword
      });
      await admin.save();
      console.log('--------------------------------------------------');
      console.log('Seeded Default Admin Account:');
      console.log(`Email: ${email}`);
      console.log(`Password: ${rawPassword}`);
      console.log('IMPORTANT: Please change these environment variables in production.');
      console.log('--------------------------------------------------');
    }
  } catch (error) {
    console.error('Error seeding admin user:', error);
  }
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ message: 'Access denied. Token missing.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key_12345', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
};

// API ROUTES

// 1. Auth Endpoint: Admin Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback_secret_key_12345',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful.',
      token,
      email: user.email
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

// 2. Auth Endpoint: Verify Token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, email: req.user.email });
});

// 3. Products Endpoint: Get All Products (Public)
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch products.', error: error.message });
  }
});

// 3.1. Public Endpoint: Get raw image at index (Useful for WhatsApp previews)
app.get('/api/products/:id/images/:index', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    const index = parseInt(req.params.index);
    if (isNaN(index) || index < 0 || index >= product.images.length) {
      return res.status(404).json({ message: 'Image index not found.' });
    }
    const base64Data = product.images[index];
    const matches = base64Data.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) {
      return res.status(400).json({ message: 'Invalid image format.' });
    }
    const contentType = matches[1];
    const imageBuffer = Buffer.from(matches[2], 'base64');
    res.setHeader('Content-Type', contentType);
    res.send(imageBuffer);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

// 4. Products Endpoint: Get Single Product (Public)
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

// 5. Products Endpoint: Add New Product (Admin Only)
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { images, code, name, price, description } = req.body;

    if (!images || !Array.isArray(images) || images.length === 0 || !code || !name || !price || !description) {
      return res.status(400).json({ message: 'All fields are required. At least one image is required.' });
    }

    // Check unique code
    const existingProduct = await Product.findOne({ code: code.trim() });
    if (existingProduct) {
      return res.status(400).json({ message: `Product code "${code}" already exists.` });
    }

    const newProduct = new Product({
      images,
      code: code.trim(),
      name: name.trim(),
      price: Number(price),
      description: description.trim()
    });

    await newProduct.save();
    res.status(201).json({ message: 'Product added successfully.', product: newProduct });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create product.', error: error.message });
  }
});

// 6. Products Endpoint: Edit Product (Admin Only)
app.put('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { images, code, name, price, description } = req.body;

    if (!images || !Array.isArray(images) || images.length === 0 || !code || !name || !price || !description) {
      return res.status(400).json({ message: 'All fields are required. At least one image is required.' });
    }

    // Find the product
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }

    // Check if new code conflicts with another product
    const codeConflict = await Product.findOne({ code: code.trim(), _id: { $ne: req.params.id } });
    if (codeConflict) {
      return res.status(400).json({ message: `Product code "${code}" is already in use by another product.` });
    }

    // Update fields
    product.images = images;
    product.code = code.trim();
    product.name = name.trim();
    product.price = Number(price);
    product.description = description.trim();

    await product.save();
    res.json({ message: 'Product updated successfully.', product });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update product.', error: error.message });
  }
});

// 7. Products Endpoint: Delete Product (Admin Only)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    res.json({ message: 'Product deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete product.', error: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});