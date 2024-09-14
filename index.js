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
    origin: ['http://localhost:5173', 'http://192.168.0.109:5173', 'https://mycash-ten.vercel.app', 'https://mycash-mfs.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'User-ID'],
}));

// MongoDB Setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.9crls8f.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, { serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true } });

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) {
        res.clearCookie('token');
        return res.status(403).send({ message: 'Forbidden' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            res.clearCookie('token');
            return res.status(401).send({
                message: err.name === 'TokenExpiredError' ? 'Token expired. Please log in again.' : 'Unauthorized'
            });
        }
        req.user = decoded;
        next();
    });
};

// Verify role
const isRole = (role) => (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user?.role !== role) {
            return res.status(403).send({ message: 'Access denied' });
        }
        next();
    });
};

async function run() {
    try {
        const userCollection = client.db('mobileFinancialServiceDB').collection('users');
        const transactionCollection = client.db('mobileFinancialServiceDB').collection('transactions');

        // User create
        app.post('/users', async (req, res) => {
            const { pin, email, number, ...userData } = req.body;
            const existingUser = await userCollection.findOne({
                $or: [{ email }, { number }]
            });
            if (existingUser) {
                return res.status(400).send({ message: 'User already exists' });
            }

            const hashedPin = await bcrypt.hash(pin, 10);
            const newUser = { email, number, ...userData, pin: hashedPin };

            await userCollection.insertOne(newUser);
            res.send({ message: 'User registered successfully!' });
        });

        // User login
        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            const user = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }]
            });
            if (!user || !(await bcrypt.compare(pin, user.pin))) {
                return res.status(400).send({ message: 'Invalid credentials' });
            }

            // Create a token
            const token = jwt.sign({ id: user._id, role: user?.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
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

            const user = await userCollection.findOne({
                _id: new ObjectId(id)
            });
            const { pin, ...userData } = user;
            if (user) {
                res.status(200).json(userData);
            }
        });

        // Logout
        app.post('/logout', (req, res) => {
            res.clearCookie('token', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax' });
            res.send({ message: 'Logout successful' });
        });

        // Fetch all users
        app.get('/all-users', verifyToken, isRole('Admin'), async (req, res) => {
            const page = parseInt(req.query.page) || 1;
            const search = req.query.search || '';
            const role = req.query.role || '';
            const status = req.query.status || '';
            const limit = 5;

            // Validate page and limit
            if (page < 1 || limit < 1) {
                return res.status(400).json({ message: 'Invalid page or limit' });
            }

            try {
                // Filter conditions
                const filterConditions = {
                    $or: [
                        { name: { $regex: search, $options: 'i' } },
                        { email: { $regex: search, $options: 'i' } }
                    ]
                };

                if (role) {
                    filterConditions.role = role;
                }

                if (status) {
                    filterConditions.status = status;
                }

                // Fetch total user count based on search term
                const totalCount = await userCollection.countDocuments(filterConditions);
                const users = await userCollection.find(filterConditions)
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .toArray();

                // Exclude user PINs from the response
                const usersData = users.map(({ pin, ...userData }) => userData);

                res.status(200).json({
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                    currentPage: page,
                    users: usersData
                });
            } catch (error) {
                res.status(500).json({ message: 'Error fetching users', error });
            }
        });

        // Update user status and new user bonus
        app.patch('/users/:id', verifyToken, isRole('Admin'), async (req, res) => {
            const { id } = req.params;
            const { status } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(id)
            });

            let bonus = 0;
            if (status === 'active' && !user.hasReceivedBonus) {
                bonus = user.role === 'User' ? 40 : 10000;
                user.hasReceivedBonus = true;
            }

            const result = await userCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status, balance: (user.balance || 0) + bonus, hasReceivedBonus: user.hasReceivedBonus } }
            );
            res.send({ modifiedCount: result.modifiedCount, message: 'User status updated successfully' });
        });

        // Validate recipient and amount
        app.post('/validate-send-money', verifyToken, async (req, res) => {
            const { identifier, amount } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(req.user.id)
            });

            const recipient = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }],
                status: 'active'
            });
            if (!recipient || recipient._id.equals(user._id)) {
                return res.status(400).send({
                    message: !recipient ? 'Recipient not found' : 'Cannot send money to yourself'
                });
            }

            // Validate minimum amount
            if (amount < 50) {
                return res.status(400).send({ message: 'Transaction amount must be at least 50 Taka' });
            }

            const fee = amount > 100 ? 5 : 0;
            if (user.balance < amount + fee) {
                return res.status(400).send({ message: 'Insufficient balance' });
            }

            res.send({ isValid: true });
        });

        // Send money
        app.post('/send-money', verifyToken, async (req, res) => {
            const { identifier, amount, pin } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(req.user.id)
            });

            if (!(await bcrypt.compare(pin, user.pin))) {
                return res.status(400).send({ message: 'Invalid PIN' });
            }

            const recipient = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }],
                status: 'active'
            });
            const fee = amount > 100 ? 5 : 0;

            // Update balance
            await userCollection.updateOne(
                { _id: new ObjectId(req.user.id) },
                { $inc: { balance: -(amount + fee) } }
            );
            await userCollection.updateOne(
                { _id: new ObjectId(recipient._id) },
                { $inc: { balance: amount } }
            );

            res.send({ message: 'Send Money successful!' });
        });

        // Validate cash-out agent and amount
        app.post('/validate-cash-out', verifyToken, async (req, res) => {
            const { identifier, amount } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(req.user.id)
            });

            const agent = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }],
                role: 'Agent',
                status: 'active'
            });
            if (!agent || agent._id.equals(user._id)) {
                return res.status(400).send({
                    message: !agent ? 'Agent not found or inactive' : 'Cannot cash-in to yourself'
                });
            }

            if (amount < 50) {
                return res.status(400).send({ message: 'Amount must be at least 50 Taka' });
            }

            const fee = amount * 0.015;
            if (user.balance < amount + fee) {
                return res.status(400).send({ message: 'Insufficient balance' });
            }

            res.send({ isValid: true });
        });

        // Cash-out
        app.post('/cash-out', verifyToken, async (req, res) => {
            const { identifier, amount, pin } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(req.user.id)
            });

            if (!(await bcrypt.compare(pin, user.pin))) {
                return res.status(400).send({ message: 'Invalid PIN' });
            }

            res.send({ message: 'Cash-out request sent to agent!' });
        });

        // Validate cash-in agent and amount
        app.post('/validate-cash-in', verifyToken, async (req, res) => {
            const { identifier, amount } = req.body;
            const user = await userCollection.findOne({
                _id: new ObjectId(req.user.id)
            });

            const agent = await userCollection.findOne({
                $or: [{ email: identifier }, { number: identifier }],
                role: 'Agent',
                status: 'active'
            });
            if (!agent || agent._id.equals(user._id)) {
                return res.status(400).send({
                    message: !agent ? 'Agent not found or inactive' : 'Cannot cash-in to yourself'
                });
            }

            if (amount < 50) {
                return res.status(400).send({ message: 'Amount must be at least 50 Taka' });
            }

            res.send({ isValid: true });
        });

        // Cash-in
        app.post('/cash-in', verifyToken, async (req, res) => {
            const { identifier, amount, pin } = req.body;
            const user = await userCollection.findOne({ _id: new ObjectId(req.user.id) });

            if (!(await bcrypt.compare(pin, user.pin))) {
                return res.status(400).send({ message: 'Invalid PIN' });
            }

            res.send({ message: 'Cash-in request sent to agent!' });
        });

        // Save transaction
        app.post('/save-transaction', verifyToken, async (req, res) => {
            const transactionData = req.body;
            try {
                await transactionCollection.insertOne(transactionData);
                res.send({ message: 'Transaction successful!' });
            } catch (error) {
                res.status(500).send({ message: 'Transaction saving failed' });
            }
        });

        // Fetch all transactions
        app.get('/transactions', verifyToken, async (req, res) => {
            const { email, number } = req.query;
            const page = parseInt(req.query.page) || 1;
            const limit = 5;

            if (page < 1 || limit < 1) {
                return res.status(400).json({ message: 'Invalid page or limit value' });
            }
            
            try {
                const user = await userCollection.findOne({ email, status: 'active' });
                const role = user?.role;

                // Query based on user role
                const query = role === 'Admin'
                    ? { status: { $nin: ['pending', 'rejected'] } } // Admin sees all transactions
                    : {
                        $or: [{ email: email }, { recipient: email }, { recipient: number }],
                        status: { $nin: ['pending', 'rejected'] }
                    }; // Non-admin users see only their transactions

                const totalCount = await transactionCollection.countDocuments(query);

                // Limit for non-admin users
                const transactionLimit = role === 'Admin' ? totalCount : (role === 'Agent' ? 20 : 10);

                const transactions = await transactionCollection
                    .find(query)
                    .sort({ timestamp: -1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .toArray();

                // Total pages based on the limit for non-admin users
                const totalPages = role === 'Admin' ? Math.ceil(totalCount / limit) : Math.ceil(Math.min(transactionLimit, totalCount) / limit);

                res.status(200).json({
                    totalCount,
                    transactionLimit,
                    transactions,
                    totalPages,
                    currentPage: page
                });
            } catch (error) {
                res.status(500).json({ message: 'Error fetching transactions', error });
            }
        });

        // Fetch pending transactions
        app.get('/pending', verifyToken, isRole('Agent'), async (req, res) => {
            const { email, number } = req.query;
            const page = parseInt(req.query.page) || 1;
            const limit = 5;

            if (page < 1 || limit < 1) {
                return res.status(400).json({ message: 'Invalid page or limit value' });
            }

            const query = {
                $or: [
                    { email: email },
                    { recipient: email },
                    { email: number },
                    { recipient: number }],
                status: 'pending'
            };

            // Exclude transactions where the current user is the sender
            const excludeQuery = {
                ...query,
                $and: [
                    {
                        $or: [
                            {
                                email: { $ne: email }
                            }]
                    }
                ]
            };

            try {
                const totalCount = await transactionCollection.countDocuments(excludeQuery);

                const transactions = await transactionCollection
                    .find(excludeQuery)
                    .sort({ timestamp: 1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .toArray();

                res.status(200).json({
                    totalCount,
                    transactions,
                    totalPages: Math.ceil(totalCount / limit),
                    currentPage: page
                });
            } catch (error) {
                res.status(500).json({ message: 'Error fetching transactions', error });
            }
        });

        // Pending transaction manage
        app.post('/handle-transaction', verifyToken, isRole('Agent'), async (req, res) => {
            const { transactionId, action } = req.body;
            const transaction = await transactionCollection.findOne({ _id: new ObjectId(transactionId) });

            if (!transaction || transaction.status !== 'pending') {
                return res.status(400).send({ message: 'Invalid or already processed transaction' });
            }

            const agent = await userCollection.findOne({ email: transaction.recipient });
            const user = await userCollection.findOne({ email: transaction.email });

            if (!user || !agent) {
                return res.status(400).send({ message: 'User or agent not found' });
            }

            if (action === 'approve') {
                if (transaction.category === 'Cash In' && agent.balance < transaction.amount) {
                    return res.status(400).send({ message: 'Insufficient balance' });
                }

                if (transaction.category === 'Cash Out' && user.balance < transaction.totalAmount) {
                    return res.status(400).send({ message: 'User has insufficient balance' });
                }

                await userCollection.updateOne(
                    { email: agent.email },
                    { $inc: { balance: transaction.category === 'Cash In' ? -transaction.amount : transaction.totalAmount - transaction.fee } }
                );
                await userCollection.updateOne(
                    { email: user.email },
                    { $inc: { balance: transaction.category === 'Cash In' ? transaction.amount : -transaction.totalAmount } }
                );

                await transactionCollection.updateOne(
                    { _id: new ObjectId(transactionId) },
                    { $set: { status: 'approved' } }
                );

                res.send({ message: 'Transaction approved!' });
            } else if (action === 'reject') {
                await transactionCollection.updateOne(
                    { _id: new ObjectId(transactionId) },
                    { $set: { status: 'rejected' } }
                );
                res.send({ message: 'Transaction rejected!' });
            } else {
                res.status(400).send({ message: 'Invalid action' });
            }
        });

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