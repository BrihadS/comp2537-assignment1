require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

//Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

//MongoDB setup
const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true&w=majority`;
const client = new MongoClient(mongoUri, { tlsAllowInvalidCertificates: true });
let db;
let userCollection;

async function connectDB() {
    try {
        await client.connect();
        db = client.db(process.env.MONGODB_DATABASE);
        userCollection = db.collection('users');
        console.log("Successfully connected to MongoDB Atlas!");
    } catch (err) {
        console.error("Failed to connect to MongoDB:", err);
    }
}

//Session setup
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: mongoUri,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// ── Middleware ────

function requireLogin(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    if (req.session.user_type !== 'admin') {
        return res.status(403).render('403', {
            title: 'Access Denied',
            authenticated: req.session.authenticated || false,
            userType: req.session.user_type || null
        });
    }
    next();
}

// ── Routes ───

//Home
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated || false,
        name: req.session.name || null,
        userType: req.session.user_type || null
    });
});

//Sign Up (get)
app.get('/signup', (req, res) => {
    res.render('signup', { errorMsg: null });
});

//Sign Up (post)
app.post('/signupSubmit', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
        return res.render('signup', { errorMsg: error.details[0].message });
    }

    const { name, email, password } = value;
    const hashedPassword = await bcrypt.hash(password, 10);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: 'user'
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = 'user';
    res.redirect('/members');
});

//Log In (get)
app.get('/login', (req, res) => {
    res.render('login', { errorMsg: null });
});

//Log In (post)
app.post('/loginSubmit', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
        return res.render('login', { errorMsg: 'Invalid input.' });
    }

    const { email, password } = value;
    const user = await userCollection.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.render('login', { errorMsg: 'Invalid email/password combination.' });
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type || 'user';
    res.redirect('/members');
});

//Members Page
app.get('/members', requireLogin, (req, res) => {
    res.render('members', {
        authenticated: true,
        name: req.session.name,
        userType: req.session.user_type
    });
});

//Log Out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

//Admin Page
app.get('/admin', requireAdmin, async (req, res) => {
    const users = await userCollection.find({}).toArray();
    res.render('admin', {
        authenticated: true,
        userType: req.session.user_type,
        users
    });
});

//Promote user to admin
app.get('/admin/promote/:email', requireAdmin, async (req, res) => {
    const schema = Joi.string().email().required();
    const { error, value } = schema.validate(req.params.email);
    if (error) return res.redirect('/admin');

    await userCollection.updateOne({ email: value }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

//Demote user to regular user
app.get('/admin/demote/:email', requireAdmin, async (req, res) => {
    const schema = Joi.string().email().required();
    const { error, value } = schema.validate(req.params.email);
    if (error) return res.redirect('/admin');

    await userCollection.updateOne({ email: value }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

//404 Page
app.get('*splat', (req, res) => {
    res.status(404).render('404', {
        title: 'Page Not Found',
        authenticated: req.session.authenticated || false,
        userType: req.session.user_type || null
    });
});

connectDB().then(() => {
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
});
