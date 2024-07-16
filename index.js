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
    origin: ['http://localhost:5173'],
    credentials: true
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
            return res.status(401).send({ message: 'Unauthorized' });
        }

        req.user = decoded;
        next();
    });
};

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const userCollection = client.db('mobileFinancialServiceDB').collection('users');

        // User create
        app.post('/users', async (req, res) => {
            const { pin, email, number, ...userData } = req.body;

            const existingUser = await userCollection.findOne({ $or: [{ email }, { number }] });

            if (existingUser) {
                return res.status(400).send({ message: 'User already exists with this email or mobile number.' });
            }

            const hashedPin = await bcrypt.hash(pin, 10);

            const newUser = {
                email,
                number,
                ...userData,
                pin: hashedPin,
                status: 'pending'
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
                return res.status(400).send({ message: 'User not found.' });
            }

            const isMatch = await bcrypt.compare(pin, user.pin);

            if (!isMatch) {
                return res.status(400).send({ message: 'Invalid PIN.' });
            }

            // Create a token
            const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
                expiresIn: '1h',
            });

            res.cookie('token', token, { httpOnly: true, secure: false });
            res.send({ message: 'Login successful!', id: user._id, email: user.email });
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