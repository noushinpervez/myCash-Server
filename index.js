const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:5173', 'https://mycash-mfs.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'User-ID'],
}));

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.9crls8f.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) {
        return res.status(403).send({ message: 'Forbidden' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            res.clearCookie('token');
            return res.status(401).send({ message: 'Unauthorized' });
        }
        req.user = decoded;
        next();
    });
};

// verify admin
const isAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user?.role !== 'Admin') {
            return res.status(403).send({ message: 'Access denied' });
        }
        next();
    });
};

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const userCollection = client.db('mobileFinancialServiceDB').collection('users');
        const transactionCollection = client.db('mobileFinancialServiceDB').collection('transactions');

        // User create
        app.post('/users', async (req, res) => {
            const { pin, email, number, ...userData } = req.body;
            const existingUser = await userCollection.findOne({ $or: [{ email }, { number }] });
            if (existingUser) {
                return res.status(400).send({ message: 'User already exists with this email or mobile number' });
            }

            const hashedPin = await bcrypt.hash(pin, 10);
            const newUser = {
                email,
                number,
                ...userData,
                pin: hashedPin,
            };

            await userCollection.insertOne(newUser);
            res.send({
                message: 'User registered successfully!'
            });
        });

        // User login
        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            const user = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }]
            });
            if (!user) {
                return res.status(400).send({ message: 'User not found' });
            }

            const isMatch = await bcrypt.compare(pin, user.pin);
            if (!isMatch) {
                return res.status(400).send({ message: 'Invalid PIN' });
            }

            // Create a token
            const token = jwt.sign({ id: user._id, role: user?.role }, process.env.JWT_SECRET, {
                expiresIn: '1h',
            });

            res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax' });
            res.send({ message: 'Login successful!', token: token });
        });

        // Private routes
        app.get('/protected', verifyToken, (req, res) => {
            res.json({ message: 'Protected data', user: req.user });
        });

        // Fetch user data by ID
        app.get('/users/:id', verifyToken, async (req, res) => {
            const { id } = req.params;
            if (req.user.id !== id) {
                return res.status(403).send({ message: 'Access denied' });
            }

            const user = await userCollection.findOne({ _id: new ObjectId(id) });

            const { pin, ...userData } = user;
            res.status(200).json(userData);
        });

        // Logout
        app.post('/logout', (req, res) => {
            res.clearCookie('token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax' });
            res.send({ message: 'Logout successful' });
        });

        // Fetch all users
        app.get('/users', verifyToken, isAdmin, async (req, res) => {
            const users = await userCollection.find({}).toArray();
            const usersData = users.map(({ pin, ...userData }) => userData);
            res.status(200).json(usersData);
        });

        // Update user status and new user approval balance
        app.patch('/users/:id', verifyToken, isAdmin, async (req, res) => {
            const { id } = req.params;
            const { status } = req.body;
            const user = await userCollection.findOne({ _id: new ObjectId(id) });
            let newBalance = user?.balance;
            if (status === 'active' && !user.hasReceivedBonus) {
                if (user?.role === 'User') {
                    newBalance += 40;
                } else if (user?.role === 'Agent') {
                    newBalance += 10000;
                }
                user.hasReceivedBonus = true;
            }

            const result = await userCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status, balance: newBalance, hasReceivedBonus: user.hasReceivedBonus } }
            );
            res.send({ modifiedCount: result.modifiedCount, message: 'User status updated successfully' });
        });

        // Validate recipient and amount
        app.post('/validate', verifyToken, async (req, res) => {
            const { identifier, amount } = req.body;
            const user = await userCollection.findOne({ _id: new ObjectId(req.user.id) });

            // Recipient validation
            const recipient = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }]
            });
            if (!recipient) {
                return res.status(404).send({ message: 'Recipient not found' });
            }

            // Prevent sending money to self
            if (recipient._id.toString() === user._id.toString()) {
                return res.status(400).send({ message: 'You cannot send money to yourself' });
            }

            // Amount validation
            if (amount < 50) {
                return res.status(400).send({ message: 'Transaction amount must be at least 50 Taka' });
            }

            const fee = amount > 100 ? 5 : 0;
            const totalAmount = amount + fee;
            if (user.balance < totalAmount) {
                return res.status(400).send({ message: 'Insufficient balance' });
            }

            res.send({ isValid: true });
        });

        // Send money
        app.post('/send-money', verifyToken, async (req, res) => {
            const { identifier, amount, pin } = req.body;
            const user = await userCollection.findOne({ _id: new ObjectId(req.user.id) });

            // Check PIN
            const isMatch = await bcrypt.compare(pin, user.pin);
            if (!isMatch) {
                return res.status(400).send({ message: 'Invalid PIN' });
            }

            // Recipient validation
            const recipient = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }]
            });

            // Fee and total amount
            const fee = amount > 100 ? 5 : 0;
            const totalAmount = amount + fee;

            // Update balance
            await userCollection.updateOne(
                { _id: new ObjectId(req.user.id) },
                { $inc: { balance: -totalAmount } }
            );
            await userCollection.updateOne(
                { _id: new ObjectId(recipient._id) },
                { $inc: { balance: amount } }
            );

            res.send({ message: 'Transaction successful!' });
        });

        // Save transaction
        app.post('/save-transaction', verifyToken, async (req, res) => {
            const transactionData = req.body;
            const result = await transactionCollection.insertOne(transactionData);
            res.send({ message: 'Transaction successful!' });
        });

        // Fetch transactions
        app.get('/transactions', verifyToken, async (req, res) => {
            const { email } = req.query;
            console.log(email);
            const query = {
                $or: [
                    { email: email },
                    { recipient: email }
                ]
            };

            const transactions = await transactionCollection.find(query).sort({ timestamp: -1 }).limit(10).toArray();
            res.status(200).json(transactions);
        });

        // Send a ping to confirm a successful connection
        // await client.db('admin').command({ ping: 1 });
        console.log('Pinged your deployment. You successfully connected to MongoDB!');
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Server is running...');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});