import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { OAuth2Client } from 'google-auth-library';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { addDummyData, getAllData } from './firebase/database.js';
import { createUser, getAllUsers, getUserById, updateUser, deleteUser } from './firebase/userOperations.js';
import { createProduct, getAllProducts, getProductById, updateProduct, deleteProduct } from './firebase/productOperations.js';
import { createOrder, getAllOrders, getOrderById, updateOrder, deleteOrder, getOrdersByUserId } from './firebase/orderOperations.js';
import { createContactMessage, getAllContactMessages, getContactMessageById, updateContactMessageStatus, deleteContactMessage, getUnreadContactMessages } from './firebase/contactOperations.js';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key'; // In production, use environment variable
const API_KEY = process.env.API_KEY || 'your-api-key'; // In production, use environment variable
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'your-google-client-id';

// Configure multer for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads/products'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'));
        }
    }
});

// Configure multer for profile image upload
const profileImageStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'uploads/profiles');
        // Create directory if it doesn't exist
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const uploadProfileImage = multer({
    storage: profileImageStorage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'));
        }
    }
});

// Serve static files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Initialize Google OAuth client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Mock API keys (use a database in production)
const validApiKeys = [API_KEY];

// Store active tokens (in production, use Redis or similar)
const activeTokens = {
    admin: new Set(),
    user: new Set()
};

app.use(express.json());
app.use(cors());

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }

        // Check if token is still active
        const tokenType = user.role === 'admin' ? 'admin' : 'user';
        if (!activeTokens[tokenType].has(token)) {
            return res.status(401).json({ message: 'Token has been revoked or expired' });
        }

        req.user = user;
        req.authType = 'jwt';
        next();
    });
};

// Middleware to verify API key
const authenticateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key']; // Expecting API key in header

    if (!apiKey || !validApiKeys.includes(apiKey)) {
        return res.status(401).json({ message: 'Invalid or missing API key' });
    }

    req.authType = 'api-key'; // Indicate API key auth
    req.user = { role: 'api-client' }; // Assign a default role for API clients
    next();
};

// Combined authentication middleware (supports both JWT and API key)
const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const apiKey = req.headers['x-api-key'];

    if (authHeader) {
        // Get token from header (might be authToken or adminToken)
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired token' });
            }

            // Check if token is still active
            // User can be admin or regular user
            const tokenType = user.role === 'admin' ? 'admin' : 'user';
            
            // For development, we'll be more lenient with token validation
            // In production, you should strictly check token validity
            const isTokenValid = activeTokens[tokenType].has(token) || process.env.NODE_ENV === 'development';
            
            if (!isTokenValid) {
                return res.status(401).json({ message: 'Token has been revoked or expired' });
            }

            req.user = user;
            req.authType = 'jwt';
            next();
        });
    } else if (apiKey) {
        authenticateApiKey(req, res, next);
    } else {
        return res.status(401).json({ message: 'Authentication required' });
    }
};

// Middleware to check if user is admin (JWT only)
const requireAdmin = (req, res, next) => {
    if (req.authType !== 'jwt' || req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required (JWT only)' });
    }
    next();
};

// Admin login endpoint
app.post('/api/admin/login', async(req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const users = await getAllUsers();
        const user = users.find(u => u.email === email && u.role === 'admin');

        if (!user) {
            return res.status(401).json({ message: 'Email not found' });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role },
            SECRET_KEY, { expiresIn: '24h' }
        );

        // Store the admin token with expiration
        activeTokens.admin.add(token);
        
        // Set token expiration
        setTimeout(() => {
            activeTokens.admin.delete(token);
            console.log('Admin token expired:', token);
        }, 24 * 60 * 60 * 1000); // 24 hours in milliseconds

        res.json({
            message: 'Admin login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                name: user.name,
                firstName: user.firstName || '',
                lastName: user.lastName || '',
                profileImage: user.profileImage
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User login endpoint
app.post('/api/user/login', async(req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const users = await getAllUsers();
        const user = users.find(u => u.email === email && u.role !== 'admin');

        if (!user) {
            return res.status(401).json({ message: 'Email not found' });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role },
            SECRET_KEY, { expiresIn: '24h' }
        );

        // Store the user token with expiration
        activeTokens.user.add(token);
        
        // Set token expiration
        setTimeout(() => {
            activeTokens.user.delete(token);
            console.log('User token expired:', token);
        }, 24 * 60 * 60 * 1000); // 24 hours in milliseconds

        res.json({
            message: 'User login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                name: user.name,
                firstName: user.firstName || '',
                lastName: user.lastName || '',
                phone: user.phone || '',
                address: user.address || '',
                city: user.city || '',
                state: user.state || '',
                pincode: user.pincode || '',
                profileImage: user.profileImage || ''
            }
        });
    } catch (error) {
        console.error('User login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User registration endpoint
app.post('/api/register', async(req, res) => {
    try {
        const { 
            email, 
            password, 
            firstName, 
            lastName, 
            phone, 
            address, 
            city, 
            state, 
            pincode 
        } = req.body;

        // Validate required fields
        if (!email || !password || !firstName || !lastName || !phone || !address || !city || !state || !pincode) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Validate password strength
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Validate phone number (basic validation)
        if (!/^\d{10}$/.test(phone)) {
            return res.status(400).json({ message: 'Invalid phone number format. Must be 10 digits' });
        }

        // Validate pincode (basic validation for Indian pincode)
        if (!/^\d{6}$/.test(pincode)) {
            return res.status(400).json({ message: 'Invalid pincode format. Must be 6 digits' });
        }

        // Check if user already exists
        const users = await getAllUsers();
        const existingUser = users.find(u => u.email === email);

        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user with all provided fields
        const userData = {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            name: `${firstName} ${lastName}`,
            phone,
            address,
            city,
            state,
            pincode,
            role: 'user',
            createdAt: new Date().toISOString(),
            status: 'active'
        };

        const newUser = await createUser(userData);

        // Generate token for automatic login after registration
        const token = jwt.sign(
            { 
                id: newUser.id, 
                email: newUser.email, 
                role: newUser.role 
            },
            SECRET_KEY, 
            { expiresIn: '1h' }
        );

        // Store the user token
        activeTokens.user.add(token);

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: newUser.id,
                email: newUser.email,
                role: newUser.role,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                name: newUser.name,
                phone: newUser.phone,
                address: newUser.address,
                city: newUser.city,
                state: newUser.state,
                pincode: newUser.pincode
            }
        });
    } catch (error) {
        console.error('User registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticate, async(req, res) => {
    try {
        const token = req.headers['authorization'].split(' ')[1];
        const tokenType = req.user.role === 'admin' ? 'admin' : 'user';

        // Remove the token from active tokens
        activeTokens[tokenType].delete(token);

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout all sessions endpoint
app.post('/api/logout-all', authenticate, async(req, res) => {
    try {
        const tokenType = req.user.role === 'admin' ? 'admin' : 'user';

        // Clear all tokens for the user type
        activeTokens[tokenType].clear();

        res.json({ message: 'Logged out from all sessions successfully' });
    } catch (error) {
        console.error('Logout all error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Protected user endpoint
app.get('/api/user', authenticate, async(req, res) => {
    try {
        if (req.authType === 'jwt') {
            const user = await getUserById(req.user.id);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            const userData = {
                id: user.id,
                email: user.email,
                role: user.role,
                name: user.name
            };
            return res.json(userData);
        } else if (req.authType === 'api-key') {
            return res.json({ message: 'API key authenticated', role: req.user.role });
        }
    } catch (error) {
        console.error('User endpoint error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get current user endpoint
app.get('/api/users/me', authenticate, async(req, res) => {
    try {
        if (req.authType !== 'jwt') {
            return res.status(401).json({ message: 'JWT authentication required' });
        }

        const user = await getUserById(req.user.id);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Return user data without sensitive information
        const userData = {
            id: user.id,
            email: user.email,
            role: user.role,
            name: user.name,
            firstName: user.firstName,
            lastName: user.lastName,
            phone: user.phone,
            address: user.address,
            city: user.city,
            state: user.state,
            pincode: user.pincode,
            profileImage: user.profileImage
        };
        
        return res.json(userData);
    } catch (error) {
        console.error('Error fetching current user:', error);
        return res.status(500).json({ error: error.message });
    }
});

// Admin-only endpoint
app.get('/api/admin', authenticate, requireAdmin, async(req, res) => {
    try {
        const users = await getAllUsers();
        const allUsers = users.map(u => ({
            id: u.id,
            email: u.email,
            role: u.role,
            name: u.name
        }));
        res.json({ message: 'Welcome to the admin panel', allUsers });
    } catch (error) {
        console.error('Admin endpoint error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User CRUD endpoints
app.post('/api/users', async(req, res) => {
    try {
        const userData = req.body;
        const newUser = await createUser(userData);
        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/users', async(req, res) => {
    try {
        const users = await getAllUsers();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/users/:id', async(req, res) => {
    try {
        // Allow users to view their own profile or admins to view any profile
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            return res.status(403).json({ message: 'Access denied' });
        }
        const user = await getUserById(req.params.id);
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/users/:id', async(req, res) => {
    try {
        const allowedFields = [
            'firstName', 
            'lastName', 
            'email', 
            'phone', 
            'address', 
            'city', 
            'state', 
            'pincode', 
            'role', 
            'status'
        ];
        
        const schema = {
            firstName: v => typeof v === 'string' && v.length <= 50,
            lastName: v => typeof v === 'string' && v.length <= 50,
            email: v => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
            phone: v => typeof v === 'string' && /^\d{10}$/.test(v),
            pincode: v => typeof v === 'string' && /^\d{6}$/.test(v)
        };

        const updatesArray = req.body.updates || [];
        if (!Array.isArray(updatesArray) || updatesArray.length === 0) {
            return res.status(400).json({ message: 'No valid update data provided' });
        }

        const userData = updatesArray.reduce((obj, item) => {
            if (!allowedFields.includes(item.key)) {
                return obj;
            }
            if (schema[item.key] && !schema[item.key](item.value)) {
                throw new Error(`Invalid ${item.key} value`);
            }
            obj[item.key] = item.value;
            return obj;
        }, {});

        // If either firstName or lastName is updated, update the name field
        if (userData.firstName || userData.lastName) {
            const existingUser = await getUserById(req.params.id);
            if (existingUser) {
                userData.name = `${userData.firstName || existingUser.firstName} ${userData.lastName || existingUser.lastName}`;
            }
        }

        if (Object.keys(userData).length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        const updatedUser = await updateUser(req.params.id, userData);
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            message: 'User updated successfully',
            data: updatedUser
        });
    } catch (error) {
        const status = error.message.includes('Invalid') ? 400 :
            error.message === 'Authentication required' ? 401 : 500;
        res.status(status).json({
            message: error.message,
            ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
        });
    }
});

app.delete('/api/users/:id', async(req, res) => {
    try {
        await deleteUser(req.params.id);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Product CRUD endpoints
app.post('/api/products', upload.single('image'), async(req, res) => {
    try {
        const productData = req.body;
        if (req.file) {
            productData.imageUrl = `/uploads/products/${req.file.filename}`;
        }
        const newProduct = await createProduct(productData);
        res.status(201).json(newProduct);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products', async(req, res) => {
    try {
        const products = await getAllProducts();
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products/:id', async(req, res) => {
    try {
        const product = await getProductById(req.params.id);
        if (product) {
            res.json(product);
        } else {
            res.status(404).json({ message: 'Product not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/products/:id', upload.single('image'), async(req, res) => {
    try {
        const productData = req.body;
        
        // Get the existing product to check for old image
        const existingProduct = await getProductById(req.params.id);
        if (!existingProduct) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // If a new image is uploaded
        if (req.file) {
            // Delete the old image if it exists
            if (existingProduct.imageUrl) {
                const oldImagePath = path.join(__dirname, existingProduct.imageUrl);
                fs.unlink(oldImagePath, (err) => {
                    if (err) console.error('Error deleting old image file:', err);
                });
            }
            // Set the new image URL
            productData.imageUrl = `/uploads/products/${req.file.filename}`;
        }

        const updatedProduct = await updateProduct(req.params.id, productData);
        res.json(updatedProduct);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/products/:id', async(req, res) => {
    try {
        const product = await getProductById(req.params.id);
        if (product && product.imageUrl) {
            // Delete the image file
            const imagePath = path.join(__dirname, product.imageUrl);
            fs.unlink(imagePath, (err) => {
                if (err) console.error('Error deleting image file:', err);
            });
        }
        await deleteProduct(req.params.id);
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Validate stock endpoint
app.post('/api/products/validate-stock', async(req, res) => {
    try {
        console.log('Stock validation request received');
        const { items } = req.body;
        
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ 
                message: 'Invalid request. Items array is required.',
                valid: false 
            });
        }

        console.log(`Validating ${items.length} items`);
        
        // Get all products
        const products = await getAllProducts();
        
        // Find any items that exceed available stock
        const invalidItems = [];
        
        for (const item of items) {
            const { productId, quantity } = item;
            
            if (!productId) {
                invalidItems.push({
                    productId: null,
                    name: 'Unknown Product',
                    requested: quantity,
                    available: 0,
                    error: 'Missing product ID'
                });
                continue;
            }
            
            // Find product by ID
            const product = products.find(p => 
                p.id === productId || p._id === productId || p.productId === productId
            );
            
            if (!product) {
                invalidItems.push({
                    productId,
                    name: 'Product Not Found',
                    requested: quantity,
                    available: 0,
                    error: 'Product not found'
                });
                continue;
            }
            
            // Check if requested quantity exceeds available stock
            if (quantity > product.stock) {
                invalidItems.push({
                    productId,
                    name: product.name,
                    requested: quantity,
                    available: product.stock,
                    error: 'Insufficient stock'
                });
            }
        }
        
        // Return validation result
        if (invalidItems.length > 0) {
            return res.status(400).json({
                message: 'Some items have insufficient stock',
                valid: false,
                invalidItems
            });
        }
        
        return res.status(200).json({
            message: 'All items in stock',
            valid: true
        });
    } catch (error) {
        console.error('Stock validation error:', error);
        res.status(500).json({ 
            message: 'Error validating stock',
            error: error.message,
            valid: false
        });
    }
});

// Order CRUD endpoints
app.post('/api/orders', async(req, res) => {
    try {
        const orderData = req.body;
        console.log('Creating new order:', orderData);
        
        if (!orderData.items || !Array.isArray(orderData.items) || orderData.items.length === 0) {
            return res.status(400).json({ message: 'Order must contain at least one item' });
        }
        
        if (!orderData.userId) {
            return res.status(400).json({ message: 'User ID is required for order' });
        }
        
        // Validate payment method
        if (!orderData.paymentMethod) {
            return res.status(400).json({ message: 'Payment method is required' });
        }
        
        // Set initial order status and payment status based on payment method
        let initialStatus = 'pending';
        let paymentStatus = 'pending';
        
        if (orderData.paymentMethod === 'cod') {
            initialStatus = 'confirmed';
            paymentStatus = 'pending';
        } else if (orderData.paymentMethod === 'card') {
            // For card payments, check if payment is verified
            if (orderData.paymentDetails && orderData.paymentDetails.verified) {
                initialStatus = 'confirmed';
                paymentStatus = 'Paid';
            } else {
                initialStatus = 'awaiting_payment';
                paymentStatus = 'pending';
            }
        }
        
        // Add status and timestamps to order
        const enhancedOrderData = {
            ...orderData,
            status: initialStatus,
            paymentStatus: paymentStatus,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            orderNumber: `ORD-${Date.now()}-${Math.floor(Math.random() * 1000)}`
        };
        
        // Create new order
        const newOrder = await createOrder(enhancedOrderData);
        console.log('Order created successfully:', newOrder.id);
        
        // Update product stock for each item
        const products = await getAllProducts();
        const stockUpdates = [];
        
        for (const item of orderData.items) {
            const productId = item.productId;
            const quantity = item.quantity;
            
            // Find product
            const product = products.find(p => 
                p.id === productId || p._id === productId || p.productId === productId
            );
            
            if (product) {
                // Calculate new stock level
                const newStock = Math.max(0, product.stock - quantity);
                
                // Update product stock
                console.log(`Updating stock for product ${product.name} (${productId}): ${product.stock} -> ${newStock}`);
                
                await updateProduct(product.id, { 
                    stock: newStock,
                    updatedAt: new Date().toISOString(),
                    // Update status based on new stock level
                    status: newStock === 0 ? 'Out of Stock' : 
                           newStock <= 10 ? 'Low Stock' : 
                           'In Stock'
                });
                
                stockUpdates.push({
                    productId,
                    name: product.name,
                    oldStock: product.stock,
                    newStock: newStock,
                    difference: quantity
                });
            } else {
                console.warn(`Product not found for stock update: ${productId}`);
            }
        }
        
        // Return order with stock updates and payment status
        res.status(201).json({
            ...newOrder,
            stockUpdates: stockUpdates,
            paymentStatus: paymentStatus
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add endpoint to update payment status
app.put('/api/orders/:id/payment-status', authenticate, async(req, res) => {
    try {
        const { paymentStatus } = req.body;
        const orderId = req.params.id;

        // Validate payment status
        const validStatuses = ['pending', 'Paid', 'failed', 'refunded'];
        if (!validStatuses.includes(paymentStatus)) {
            return res.status(400).json({ message: 'Invalid payment status' });
        }

        // Get the order
        const order = await getOrderById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }

        // Check if user has permission to update this order
        if (req.user.role !== 'admin' && order.userId !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to update this order' });
        }

        // Update order with new payment status
        const updatedOrder = await updateOrder(orderId, {
            paymentStatus,
            status: paymentStatus === 'completed' ? 'confirmed' : 
                   paymentStatus === 'failed' ? 'cancelled' : 
                   paymentStatus === 'refunded' ? 'refunded' : 
                   order.status,
            updatedAt: new Date().toISOString()
        });

        res.json({
            message: 'Payment status updated successfully',
            order: updatedOrder
        });
    } catch (error) {
        console.error('Error updating payment status:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders', async(req, res) => {
    try {
        const orders = await getAllOrders();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/orders/:id', async(req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const order = await getOrderById(req.params.id);
        if (order) {
            // Check if the user is an admin or the order belongs to the user
            if (req.user.role === 'admin' || order.userId === req.user.id) {
                // Ensure all necessary fields are included in the response
                const orderWithDetails = {
                    ...order,
                    orderItems: order.items || [], // For backward compatibility
                    customer: order.deliveryAddress?.name || order.customer || 'Unknown Customer',
                    payment: order.paymentStatus || order.payment || 'Pending'
                };
                return res.json(orderWithDetails);
            } else {
                return res.status(403).json({ message: 'Access denied' });
            }
        } else {
            return res.status(404).json({ message: 'Order not found' });
        }
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

app.put('/api/orders/:id', authenticate, async(req, res) => {
    try {
        const orderId = req.params.id;
        const orderData = req.body;
        
        // Get the current order
        const existingOrder = await getOrderById(orderId);
        
        if (!existingOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        // Check if user has permission to update this order
        // Only the order owner or an admin can update it
        if (req.user.role !== 'admin' && existingOrder.userId !== req.user.id) {
            return res.status(403).json({ message: 'You do not have permission to update this order' });
        }
        
        // If order is being cancelled, handle stock restoration
        if (orderData.status === 'cancelled' && existingOrder.status !== 'cancelled') {
            console.log(`Order ${orderId} is being cancelled. Restoring stock...`);
            
            // Only restore stock for orders that were in 'pending' or 'processing' status
            const canRestoreStock = ['pending', 'processing', 'confirmed'].includes(existingOrder.status.toLowerCase());
            
            if (canRestoreStock && existingOrder.items && existingOrder.items.length > 0) {
                const products = await getAllProducts();
                const stockUpdates = [];
                
                // Restore stock for each item
                for (const item of existingOrder.items) {
                    const productId = item.productId;
                    const quantity = item.quantity;
                    
                    // Find product
                    const product = products.find(p => 
                        p.id === productId || p._id === productId || p.productId === productId
                    );
                    
                    if (product) {
                        // Increase stock by the order quantity
                        const newStock = product.stock + quantity;
                        
                        // Update product stock
                        console.log(`Restoring stock for product ${product.name} (${productId}): ${product.stock} -> ${newStock}`);
                        
                        await updateProduct(product.id, { 
                            stock: newStock,
                            updatedAt: new Date().toISOString(),
                            // Update status based on new stock level
                            status: newStock > 10 ? 'In Stock' : newStock > 0 ? 'Low Stock' : 'Out of Stock'
                        });
                        
                        stockUpdates.push({
                            productId,
                            name: product.name,
                            oldStock: product.stock,
                            newStock: newStock,
                            difference: quantity
                        });
                    } else {
                        console.warn(`Product not found for stock restoration: ${productId}`);
                    }
                }
                
                // Add stock updates to the order data
                orderData.stockRestorationUpdates = stockUpdates;
            }
            
            // Update payment status if order is cancelled
            orderData.paymentStatus = 'cancelled';
        }
        
        // Update the order
        orderData.updatedAt = new Date().toISOString();
        const updatedOrder = await updateOrder(orderId, orderData);
        
        res.json({
            ...updatedOrder,
            message: orderData.status === 'cancelled' ? 'Order cancelled successfully' : 'Order updated successfully'
        });
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/orders/:id', async(req, res) => {
    try {
        await deleteOrder(req.params.id);
        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get orders by user ID
app.get('/api/users/:userId/orders', async(req, res) => {
    try {
        // Allow users to view their own orders or admins to view any user's orders
        if (req.user.role !== 'admin' && req.user.id !== req.params.userId) {
            return res.status(403).json({ message: 'Access denied' });
        }
        const orders = await getOrdersByUserId(req.params.userId);
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Contact Message endpoints
app.post('/api/contact', async(req, res) => {
    try {
        const messageData = req.body;
        
        // Validate required fields
        if (!messageData.name || !messageData.email || !messageData.message) {
            return res.status(400).json({ 
                success: false,
                message: 'Name, email, and message are required fields' 
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(messageData.email)) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid email format' 
            });
        }
        
        // Add metadata
        const enhancedMessage = {
            ...messageData,
            status: messageData.status || 'unread',
            createdAt: messageData.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        const newMessage = await createContactMessage(enhancedMessage);
        
        res.status(201).json({
            success: true,
            message: 'Contact message sent successfully',
            data: newMessage
        });
    } catch (error) {
        console.error('Error creating contact message:', error);
        res.status(500).json({ 
            success: false,
            message: 'Server error while processing your message',
            error: error.message 
        });
    }
});

app.get('/api/contact', authenticate, requireAdmin, async(req, res) => {
    try {
        const messages = await getAllContactMessages();
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contact/:id', authenticate, requireAdmin, async(req, res) => {
    try {
        const message = await getContactMessageById(req.params.id);
        if (message) {
            res.json(message);
        } else {
            res.status(404).json({ message: 'Contact message not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/contact/:id/status', authenticate, requireAdmin, async(req, res) => {
    try {
        const { status } = req.body;
        const updatedMessage = await updateContactMessageStatus(req.params.id, status);
        res.json(updatedMessage);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/contact/:id', authenticate, requireAdmin, async(req, res) => {
    try {
        await deleteContactMessage(req.params.id);
        res.json({ message: 'Contact message deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contact/unread', authenticate, requireAdmin, async(req, res) => {
    try {
        const messages = await getUnreadContactMessages();
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update the path to ensure it doesn't conflict with the /:id pattern
app.get('/api/contact/count', authenticate, requireAdmin, async(req, res) => {
    try {
        const messages = await getAllContactMessages();
        
        // Count by status
        const counts = {
            total: messages.length,
            unread: messages.filter(m => m.status === 'unread').length,
            read: messages.filter(m => m.status === 'read').length,
            replied: messages.filter(m => m.status === 'replied').length,
            pending: messages.filter(m => m.status === 'pending').length
        };
        
        res.json(counts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Google authentication endpoint
app.post('/api/auth/google', async(req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: 'Google token is required' });
        }

        // Verify the Google token
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, picture } = payload;

        // Check if user exists
        const users = await getAllUsers();
        let user = users.find(u => u.email === email);

        if (!user) {
            // Create new user if doesn't exist
            const userData = {
                email,
                name,
                password: '', // No password for Google users
                role: 'user',
                googleId: payload.sub,
                picture
            };
            user = await createUser(userData);
        }

        // Generate JWT token
        const jwtToken = jwt.sign({ id: user.id, email: user.email, role: user.role },
            SECRET_KEY, { expiresIn: '1h' }
        );

        // Store the token
        activeTokens.user.add(jwtToken);

        res.json({
            message: 'Google login successful',
            token: jwtToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                name: user.name,
                picture: user.picture
            }
        });
    } catch (error) {
        console.error('Google authentication error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user profile endpoint
app.get('/api/user/profile', authenticate, async(req, res) => {
    try {
        const user = await getUserById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Return user data without sensitive information
        const userData = {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            phone: user.phone,
            address: user.address,
            city: user.city,
            state: user.state,
            pincode: user.pincode,
            profileImage: user.profileImage,
            role: user.role
        };

        res.json(userData);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user profile endpoint
app.put('/api/user/profile', authenticate, async(req, res) => {
    try {
        const { firstName, lastName, phone, address, city, state, pincode, profileImage } = req.body;

        // Validate required fields
        if (!firstName || !lastName) {
            return res.status(400).json({ message: 'First name and last name are required' });
        }

        // Validate phone number format
        if (phone && !/^\d{10}$/.test(phone)) {
            return res.status(400).json({ message: 'Invalid phone number format' });
        }

        // Validate pincode format
        if (pincode && !/^\d{6}$/.test(pincode)) {
            return res.status(400).json({ message: 'Invalid pincode format' });
        }

        const updateData = {
            firstName,
            lastName,
            phone: phone || '',
            address: address || '',
            city: city || '',
            state: state || '',
            pincode: pincode || '',
            profileImage: profileImage || ''
        };

        const updatedUser = await updateUser(req.user.id, updateData);
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: updatedUser.id,
                firstName: updatedUser.firstName,
                lastName: updatedUser.lastName,
                email: updatedUser.email,
                phone: updatedUser.phone,
                address: updatedUser.address,
                city: updatedUser.city,
                state: updatedUser.state,
                pincode: updatedUser.pincode,
                profileImage: updatedUser.profileImage
            }
        });
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user password endpoint
app.put('/api/user/password', authenticate, async(req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Validate required fields
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required' });
        }

        // Validate password strength
        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Get current user
        const user = await getUserById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify current password
        if (user.password !== currentPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Update password
        const updatedUser = await updateUser(req.user.id, { password: newPassword });
        if (!updatedUser) {
            return res.status(404).json({ message: 'Failed to update password' });
        }

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Upload profile image endpoint
app.post('/api/user/profile/image', authenticate, uploadProfileImage.single('profileImage'), async(req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No image file provided' });
        }

        const user = await getUserById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Delete old profile image if it exists
        if (user.profileImage) {
            const oldImagePath = path.join(__dirname, user.profileImage);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        // Update user with new image URL
        const imageUrl = `/uploads/profiles/${req.file.filename}`;
        const updatedUser = await updateUser(req.user.id, { profileImage: imageUrl });

        if (!updatedUser) {
            return res.status(500).json({ message: 'Failed to update profile image' });
        }

        res.json({
            message: 'Profile image uploaded successfully',
            imageUrl: imageUrl
        });
    } catch (error) {
        console.error('Error uploading profile image:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin profile endpoint
app.get('/api/admin/profile', authenticate, requireAdmin, async(req, res) => {
    try {
        const adminId = req.user.id;
       

        const user = await getUserById(adminId);
        if (!user) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        // Return admin data without sensitive information
        const adminData = {
            id: user.id,
            firstName: user.firstName || '',
            lastName: user.lastName || '',
            email: user.email || '',
            phone: user.phone || '',
            address: user.address || '',
            city: user.city || '',
            state: user.state || '',
            pincode: user.pincode || '',
            role: user.role || 'Administrator',
            profileImage: user.profileImage || null,
            joinDate: user.createdAt || new Date().toISOString(),
            lastLogin: user.lastLogin || new Date().toISOString(),
            security: {
                twoFactorAuth: user.twoFactorAuth || false,
                passwordLastChanged: user.passwordLastChanged || '',
                loginNotifications: user.loginNotifications || true,
                failedLoginAttempts: user.failedLoginAttempts || 0
            }
        };

       
        res.json(adminData);
    } catch (error) {
        console.error('Error fetching admin profile:', error);
        res.status(500).json({ message: 'Server error while fetching admin profile' });
    }
});

app.put('/api/admin/profile', authenticate, requireAdmin, async(req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            phone,
            address,
            city,
            state,
            pincode,
            password,
            security,
            notifications
        } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !phone || !address || !city || !state || !pincode) {
            return res.status(400).json({ message: 'All required fields must be provided' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Validate phone number format
        if (!/^\d{10}$/.test(phone)) {
            return res.status(400).json({ message: 'Invalid phone number format' });
        }

        // Validate pincode format
        if (!/^\d{6}$/.test(pincode)) {
            return res.status(400).json({ message: 'Invalid pincode format' });
        }

        // Check if email is already taken by another user
        const users = await getAllUsers();
        const existingUser = users.find(u => u.email === email && u.id !== req.user.id);
        if (existingUser) {
            return res.status(400).json({ message: 'Email is already in use' });
        }

        // Prepare update data
        const updateData = {
            firstName,
            lastName,
            email,
            phone,
            address,
            city,
            state,
            pincode,
            name: `${firstName} ${lastName}`,
            ...(password && { password }),
            ...(security && {
                twoFactorAuth: security.twoFactorAuth,
                passwordLastChanged: password ? new Date().toISOString() : undefined,
                loginNotifications: security.loginNotifications,
                failedLoginAttempts: security.failedLoginAttempts
            }),
            ...(notifications && {
                emailAlerts: notifications.emailAlerts,
                orderUpdates: notifications.orderUpdates,
                systemAlerts: notifications.systemAlerts,
                marketingEmails: notifications.marketingEmails
            })
        };

        // Update admin profile
        const updatedUser = await updateUser(req.user.id, updateData);
        if (!updatedUser) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        // Return updated admin data
        const adminData = {
            id: updatedUser.id,
            firstName: updatedUser.firstName,
            lastName: updatedUser.lastName,
            email: updatedUser.email,
            phone: updatedUser.phone,
            address: updatedUser.address,
            city: updatedUser.city,
            state: updatedUser.state,
            pincode: updatedUser.pincode,
            role: updatedUser.role,
            profileImage: updatedUser.profileImage,
            joinDate: updatedUser.createdAt,
            lastLogin: updatedUser.lastLogin,
            security: {
                twoFactorAuth: updatedUser.twoFactorAuth || false,
                passwordLastChanged: updatedUser.passwordLastChanged || '',
                loginNotifications: updatedUser.loginNotifications || true,
                failedLoginAttempts: updatedUser.failedLoginAttempts || 0
            },
            notifications: {
                emailAlerts: updatedUser.emailAlerts || true,
                orderUpdates: updatedUser.orderUpdates || true,
                systemAlerts: updatedUser.systemAlerts || true,
                marketingEmails: updatedUser.marketingEmails || false
            }
        };

        res.json(adminData);
    } catch (error) {
        console.error('Error updating admin profile:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin profile image upload endpoint
app.post('/api/admin/profile/image', authenticate, requireAdmin, uploadProfileImage.single('profileImage'), async(req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No image file provided' });
        }

        const adminId = req.user.id;
        console.log('Uploading profile image for admin ID:', adminId);

        const user = await getUserById(adminId);
        if (!user) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        // Delete old profile image if it exists
        if (user.profileImage) {
            const oldImagePath = path.join(__dirname, user.profileImage);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
                console.log('Deleted old profile image:', oldImagePath);
            }
        }

        // Update admin with new image URL
        const imageUrl = `/uploads/profiles/${req.file.filename}`;
        const updatedUser = await updateUser(adminId, { profileImage: imageUrl });

        if (!updatedUser) {
            return res.status(500).json({ message: 'Failed to update profile image' });
        }

        console.log('Profile image uploaded successfully:', imageUrl);
        res.json({
            message: 'Profile image uploaded successfully',
            imageUrl: imageUrl
        });
    } catch (error) {
        console.error('Error uploading admin profile image:', error);
        res.status(500).json({ message: 'Server error while uploading profile image' });
    }
});

// Admin password update endpoint
app.put('/api/admin/password', authenticate, requireAdmin, async(req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Validate required fields
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required' });
        }

        // Validate password strength
        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters long' });
        }

        // Get admin user
        const adminId = req.user.id;
        console.log('Updating password for admin ID:', adminId);

        const user = await getUserById(adminId);
        if (!user) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        // Verify current password
        if (user.password !== currentPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Check if new password is same as current password
        if (currentPassword === newPassword) {
            return res.status(400).json({ message: 'New password must be different from current password' });
        }

        // Update password
        const updatedUser = await updateUser(adminId, { 
            password: newPassword,
            passwordLastChanged: new Date().toISOString()
        });

        if (!updatedUser) {
            return res.status(500).json({ message: 'Failed to update password' });
        }

        console.log('Password updated successfully for admin:', adminId);
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating admin password:', error);
        res.status(500).json({ message: 'Server error while updating password' });
    }
});

// Admin dashboard endpoint
app.get('/api/admin/dashboard', authenticate, requireAdmin, async(req, res) => {
    try {
        // Get all necessary data
        const [users, products, orders] = await Promise.all([
            getAllUsers(),
            getAllProducts(),
            getAllOrders()
        ]);

        // Calculate total sales
        const totalSales = orders.reduce((sum, order) => sum + (order.total || 0), 0);

        // Get recent orders (last 5)
        const recentOrders = orders
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, 5)
            .map(order => ({
                id: order.id,
                customerName: order.customerName || order.deliveryAddress?.name || 'N/A',
                amount: Number(order.total || 0),
                status: order.status || 'pending',
                date: order.createdAt
            }));

        // Calculate sales analytics
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay());
        const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
        
        // Extract and format order dates for analytics
        const orderData = orders.map(order => ({
            date: new Date(order.createdAt),
            amount: Number(order.total || 0)
        }));
        
        // Generate daily data for the past 7 days
        const dailyData = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const dayStart = new Date(date.getFullYear(), date.getMonth(), date.getDate());
            const dayEnd = new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59, 999);
            
            const dayOrders = orderData.filter(order => 
                order.date >= dayStart && order.date <= dayEnd
            );
            const dayTotal = dayOrders.reduce((sum, order) => sum + order.amount, 0);
            
            dailyData.push({
                date: date.toISOString().split('T')[0],
                dayOfWeek: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()],
                sales: dayTotal,
                orders: dayOrders.length
            });
        }
        
        // Generate weekly data for the past 4 weeks
        const weeklyData = [];
        for (let i = 3; i >= 0; i--) {
            const weekStart = new Date(today);
            weekStart.setDate(today.getDate() - today.getDay() - (7 * i));
            const weekEnd = new Date(weekStart);
            weekEnd.setDate(weekStart.getDate() + 6);
            
            const weekOrders = orderData.filter(order => 
                order.date >= weekStart && order.date <= new Date(weekEnd.getFullYear(), weekEnd.getMonth(), weekEnd.getDate(), 23, 59, 59, 999)
            );
            const weekTotal = weekOrders.reduce((sum, order) => sum + order.amount, 0);
            
            weeklyData.push({
                weekStart: weekStart.toISOString().split('T')[0],
                weekEnd: weekEnd.toISOString().split('T')[0],
                week: `Week ${i+1}`,
                sales: weekTotal,
                orders: weekOrders.length
            });
        }
        
        // Generate monthly data for the past 12 months
        const monthlyData = [];
        for (let i = 11; i >= 0; i--) {
            const monthStart = new Date(today.getFullYear(), today.getMonth() - i, 1);
            const monthEnd = new Date(today.getFullYear(), today.getMonth() - i + 1, 0, 23, 59, 59, 999);
            
            const monthOrders = orderData.filter(order => 
                order.date >= monthStart && order.date <= monthEnd
            );
            const monthTotal = monthOrders.reduce((sum, order) => sum + order.amount, 0);
            
            monthlyData.push({
                month: monthStart.toISOString().split('T')[0].substring(0, 7),
                monthName: monthStart.toLocaleString('default', { month: 'short' }),
                sales: monthTotal,
                orders: monthOrders.length
            });
        }

        // Calculate sales totals
        const salesAnalytics = {
            daily: orderData
                .filter(order => order.date.toDateString() === today.toDateString())
                .reduce((sum, order) => sum + order.amount, 0),
            weekly: orderData
                .filter(order => order.date >= startOfWeek)
                .reduce((sum, order) => sum + order.amount, 0),
            monthly: orderData
                .filter(order => order.date >= startOfMonth)
                .reduce((sum, order) => sum + order.amount, 0),
            dailyData: dailyData,
            weeklyData: weeklyData,
            monthlyData: monthlyData
        };

        // Calculate growth compared to previous periods
        const previousMonthStart = new Date(today.getFullYear(), today.getMonth() - 1, 1);
        const previousMonthEnd = new Date(today.getFullYear(), today.getMonth(), 0, 23, 59, 59, 999);
        const previousMonthSales = orderData
            .filter(order => order.date >= previousMonthStart && order.date <= previousMonthEnd)
            .reduce((sum, order) => sum + order.amount, 0);
        
        const monthlyGrowth = previousMonthSales > 0 
            ? ((salesAnalytics.monthly - previousMonthSales) / previousMonthSales) * 100 
            : 0;

        // Prepare dashboard data
        const dashboardData = {
            totalSales,
            totalOrders: orders.length,
            totalProducts: products.length,
            totalCustomers: users.filter(user => user.role !== 'admin').length,
            recentOrders,
            salesAnalytics,
            growth: {
                monthly: monthlyGrowth.toFixed(1)
            },
            summary: {
                totalRevenue: totalSales,
                averageOrderValue: orders.length > 0 ? totalSales / orders.length : 0,
                totalCustomers: users.filter(user => user.role !== 'admin').length,
                totalProducts: products.length,
                lowStockProducts: products.filter(product => (product.stock || 0) < 10).length,
                pendingOrders: orders.filter(order => order.status === 'pending').length
            }
        };

        console.log('Dashboard data generated successfully');
        res.json(dashboardData);
    } catch (error) {
        console.error('Error generating dashboard data:', error);
        res.status(500).json({ message: 'Server error while generating dashboard data' });
    }
});

// Card verification endpoint
app.post('/api/verify-card', async(req, res) => {
    try {
        const { cardNumber, cardExpiry, cardCvv, cardName } = req.body;
        
        // Dummy card validation
        const validCards = [
            {
                number: '4111111111111111',
                expiry: '12/25',
                cvv: '123',
                name: 'John Doe',
                amount: 5000
            },
            {
                number: '5555555555554444',
                expiry: '03/24',
                cvv: '456',
                name: 'Jane Smith',
                amount: 3000
            },
            {
                number: '378282246310005',
                expiry: '06/26',
                cvv: '789',
                name: 'Mike Johnson',
                amount: 2000
            },
            {
                number: '6011111111111117',
                expiry: '09/25',
                cvv: '321',
                name: 'Sarah Wilson',
                amount: 4000
            },
            {
                number: '3530111333300000',
                expiry: '12/24',
                cvv: '654',
                name: 'David Brown',
                amount: 1500
            }
        ];

        const card = validCards.find(c => 
            c.number === cardNumber.replace(/\s/g, '') &&
            c.expiry === cardExpiry &&
            c.cvv === cardCvv &&
            c.name.toLowerCase() === cardName.toLowerCase()
        );

        if (!card) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid card details' 
            });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        
        // In a real application, you would send this OTP via SMS/email
        console.log('Generated OTP:', otp);

        res.json({
            success: true,
            message: 'Card verified successfully',
            otp: otp,
            cardDetails: {
                lastFour: card.number.slice(-4),
                amount: card.amount
            }
        });
    } catch (error) {
        console.error('Card verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error verifying card' 
        });
    }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async(req, res) => {
    try {
        const { otp, expectedOtp } = req.body;
        
        if (parseInt(otp) === parseInt(expectedOtp)) {
            res.json({
                success: true,
                message: 'OTP verified successfully'
            });
        } else {
            res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error verifying OTP' 
        });
    }
});

// Forgot password endpoint
app.post('/api/forgot-password', async(req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email is required' 
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid email format' 
            });
        }
        
        // Check if user exists
        const users = await getAllUsers();
        const user = users.find(u => u.email === email);
        
        // In development mode, be clear if email is not found
        if (!user) {
            if (process.env.NODE_ENV === 'development') {
                return res.status(404).json({
                    success: false,
                    message: 'No account found with this email address'
                });
            } else {
                // In production, don't reveal that the email doesn't exist
                return res.json({
                    success: true,
                    message: 'If your email is registered, you will receive password reset instructions'
                });
            }
        }
        
        // Generate a reset token
        const resetToken = jwt.sign(
            { id: user.id, email: user.email },
            SECRET_KEY,
            { expiresIn: '1h' }
        );
        
        // Store the reset token (in a real app, you'd store this in a database)
        // For this implementation, we'll simulate by updating the user
        await updateUser(user.id, {
            resetToken,
            resetTokenExpiry: new Date(Date.now() + 3600000).toISOString() // 1 hour from now
        });
        
        // In a real application, you would send an email with the reset link
        // For demo purposes, we'll just log it
        console.log('Password reset for:', email);
        console.log('Reset token:', resetToken);
        
        // Always return the reset token in development mode
        res.json({
            success: true,
            message: 'Password reset request successful',
            resetToken: process.env.NODE_ENV !== 'production' ? resetToken : undefined,
            // For development, include the user info
            user: process.env.NODE_ENV !== 'production' ? {
                id: user.id,
                email: user.email,
                name: user.name
            } : undefined
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error processing your request' 
        });
    }
});

// Reset password endpoint
app.post('/api/reset-password', async(req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Token and new password are required' 
            });
        }
        
        // Validate password strength
        if (newPassword.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters long' 
            });
        }
        
        // Verify token
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, SECRET_KEY);
        } catch (error) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        
        // Get user by ID from decoded token
        const user = await getUserById(decodedToken.id);
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Check if token matches and has not expired
        if (user.resetToken !== token || 
            !user.resetTokenExpiry || 
            new Date(user.resetTokenExpiry) < new Date()) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }
        
        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        
        // Update user's password and clear reset token
        await updateUser(user.id, {
            password: hashedPassword,
            resetToken: null,
            resetTokenExpiry: null,
            passwordLastChanged: new Date().toISOString()
        });
        
        res.json({
            success: true,
            message: 'Password has been reset successfully',
            // In development mode, include user info for auto-login
            user: process.env.NODE_ENV !== 'production' ? {
                id: user.id,
                email: user.email,
                name: user.name || `${user.firstName} ${user.lastName}`
            } : undefined
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error resetting password' 
        });
    }
});

// Add a specific endpoint for order cancellation
app.post('/api/orders/:id/cancel', authenticate, async(req, res) => {
    try {
        const orderId = req.params.id;
        const { cancellationReason } = req.body;
        
        // Get the current order
        const existingOrder = await getOrderById(orderId);
        
        if (!existingOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }
        
        // Check if user has permission to cancel this order
        if (req.user.role !== 'admin' && existingOrder.userId !== req.user.id) {
            return res.status(403).json({ message: 'You do not have permission to cancel this order' });
        }
        
        // Check if order can be cancelled
        if (!['pending', 'processing', 'confirmed'].includes(existingOrder.status.toLowerCase())) {
            return res.status(400).json({ 
                message: `Order cannot be cancelled in status: ${existingOrder.status}`,
                status: existingOrder.status
            });
        }
        
        // If order is already cancelled
        if (existingOrder.status.toLowerCase() === 'cancelled') {
            return res.status(400).json({ 
                message: 'Order is already cancelled',
                status: existingOrder.status
            });
        }
        
        console.log(`Order ${orderId} is being cancelled. Restoring stock...`);
        
        // Restore stock for order items
        if (existingOrder.items && existingOrder.items.length > 0) {
            const products = await getAllProducts();
            const stockUpdates = [];
            
            // Restore stock for each item
            for (const item of existingOrder.items) {
                const productId = item.productId;
                const quantity = item.quantity;
                
                // Find product
                const product = products.find(p => 
                    p.id === productId || p._id === productId || p.productId === productId
                );
                
                if (product) {
                    // Increase stock by the order quantity
                    const newStock = product.stock + quantity;
                    
                    // Update product stock
                    console.log(`Restoring stock for product ${product.name} (${productId}): ${product.stock} -> ${newStock}`);
                    
                    await updateProduct(product.id, { 
                        stock: newStock,
                        updatedAt: new Date().toISOString(),
                        // Update status based on new stock level
                        status: newStock > 10 ? 'In Stock' : newStock > 0 ? 'Low Stock' : 'Out of Stock'
                    });
                    
                    stockUpdates.push({
                        productId,
                        name: product.name,
                        oldStock: product.stock,
                        newStock: newStock,
                        difference: quantity
                    });
                } else {
                    console.warn(`Product not found for stock restoration: ${productId}`);
                }
            }
            
            // Determine payment status for the cancelled order
            let paymentStatus = 'cancelled';
            const currentPaymentStatus = existingOrder.paymentStatus || '';
            
            // If payment was already made, mark it as refunded
            if (currentPaymentStatus.toLowerCase() === 'paid') {
                paymentStatus = 'refunded';
                console.log(`Order ${orderId} was paid, marking payment status as refunded`);
            }
            
            // Prepare update data for order
            const orderData = {
                status: 'cancelled',
                paymentStatus: paymentStatus,
                cancelledAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                cancellationReason: cancellationReason || 'Cancelled by user',
                stockRestorationUpdates: stockUpdates,
                cancelledBy: req.user.id,
                cancelledByRole: req.user.role
            };
            
            // Update the order
            const updatedOrder = await updateOrder(orderId, orderData);
            
            // Return the updated order data
            return res.json({
                message: 'Order cancelled successfully',
                order: updatedOrder,
                stockUpdates
            });
        } else {
            return res.status(400).json({ message: 'Order has no items to process' });
        }
    } catch (error) {
        console.error('Error cancelling order:', error);
        return res.status(500).json({ error: error.message });
    }
});

// Endpoint to mark notifications as read
app.post('/api/contact/mark-read', authenticate, requireAdmin, async(req, res) => {
    try {
        const { messageIds } = req.body;
        
        if (!messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
            return res.status(400).json({ 
                success: false,
                message: 'Message IDs array is required' 
            });
        }

        const updatePromises = messageIds.map(id => 
            updateContactMessageStatus(id, 'read')
        );
        
        await Promise.all(updatePromises);
        
        res.json({
            success: true,
            message: `Successfully marked ${messageIds.length} message(s) as read`
        });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.status(500).json({ 
            success: false,
            message: 'Server error while updating message status',
            error: error.message 
        });
    }
});

// Get homepage statistics endpoint
app.get('/api/homepage/stats', async (req, res) => {
    try {
        const [products, users] = await Promise.all([
            getAllProducts(),
            getAllUsers()
        ]);

        // Count B2B clients (non-admin users)
        const b2bClients = users.filter(user => user.role !== 'admin').length;

        res.json({
            totalProducts: products.length,
            totalB2bClients: b2bClients
        });
    } catch (error) {
        console.error('Error fetching homepage stats:', error);
        res.status(500).json({ message: 'Error fetching statistics' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
    console.log('Available endpoints:');
    console.log('- POST /api/admin/login - Admin login');
    console.log('- POST /api/user/login - User login');
    console.log('- POST /api/logout - Logout current session');
    console.log('- POST /api/logout-all - Logout all sessions');
    console.log('- GET /api/user - Get user profile');
    console.log('- GET /api/admin - Admin dashboard');
});