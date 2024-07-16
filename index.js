const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(express.json());
app.use(cors());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.9crls8f.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const userCollection = client.db('mobileFinancialServiceDB').collection('users');

        // user create
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
                message: 'User registered successfully!'});
        });

        // user login
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

            res.send({ message: 'Login successful!' });
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