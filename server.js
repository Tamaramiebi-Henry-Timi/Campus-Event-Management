// Backend: Node.js with Express and MongoDB

// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    preferences: [String],
    rsvps: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Event' }],
    role: { type: String, default: 'user' } // Role: 'user' or 'admin'
});

const EventSchema = new mongoose.Schema({
    name: String,
    date: Date,
    time: String,
    location: String,
    description: String,
    capacity: Number,
    availableSeats: Number,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const User = mongoose.model('User', UserSchema);
const Event = mongoose.model('Event', EventSchema);

// Routes

// Default route to show all users and events
app.get('/', async (req, res) => {
    try {
        const users = await User.find({}, 'name email role');
        const events = await Event.find({}, 'name date time location description');
        res.json({ users, events });
    } catch (err) {
        res.status(500).send('Error fetching data');
    }
});

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, preferences } = req.body;

        // Normalize the email for comparison
        const normalizedEmail = email.trim().toLowerCase();
        const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Assign role based on the email match
        const role = (normalizedEmail === adminEmail) ? 'admin' : 'user';

        // Create and save the user
        const user = new User({
            name,
            email: normalizedEmail,
            password: hashedPassword,
            preferences,
            role
        });

        await user.save();
        res.status(201).send('User registered successfully');
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(400).send('Error registering user');
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials');
        }
        const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).send('Error logging in');
    }
});

// Create Event (Admin Only)
app.post('/events', async (req, res) => {
    try {
        const { name, date, time, location, description, capacity } = req.body;
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).send('Unauthorized');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user || user.role !== 'admin') {
            return res.status(403).send('Access denied');
        }
        const event = new Event({
            name,
            date,
            time,
            location,
            description,
            capacity,
            availableSeats: capacity,
            createdBy: user._id
        });
        await event.save();
        res.status(201).send('Event created successfully');
    } catch (err) {
        res.status(400).send('Error creating event');
    }
});

// Get Event Listings
app.get('/events', async (req, res) => {
    try {
        const events = await Event.find();
        res.json(events);
    } catch (err) {
        res.status(500).send('Error fetching events');
    }
});

// RSVP to Event
app.post('/events/:eventId/rsvp', async (req, res) => {
    try {
        const { eventId } = req.params;
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).send('Unauthorized');

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);

        const event = await Event.findById(eventId);
        if (!event || event.availableSeats <= 0) {
            return res.status(400).send('Event is full or does not exist');
        }

        event.availableSeats -= 1;
        user.rsvps.push(event._id);

        await event.save();
        await user.save();

        res.send('RSVP successful');
    } catch (err) {
        res.status(500).send('Error RSVPing to event');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
