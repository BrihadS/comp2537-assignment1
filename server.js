//Load secret environment variables
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

//Middleware (Reading form data and displaying images)
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

//Construct connection string using .env variables
const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUri, 
{
    tlsAllowInvalidCertificates: true
});
let db;
let userCollection;

async function connectDB() 
{
    try 
    {
        await client.connect();
        db = client.db(process.env.MONGODB_DATABASE);
        userCollection = db.collection('users');
        console.log("Successfully connected to MongoDB Atlas!");
    } catch (err){
        console.error("Failed to connect to MongoDB:", err);
    }
}

//Session Setup
app.use(session(
{
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create(
    {
        mongoUrl: mongoUri,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 } //expires in 1 hour
}));

//1. Home Page
app.get('/', (req, res) => 
{
    if (req.session.authenticated) 
    {
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a><br><br>
            <a href="/logout"><button>Logout</button></a>
        `);
    } 
    else 
    {
        res.send(`
            <h1>Welcome!</h1>
            <a href="/signup"><button>Sign up</button></a><br><br>
            <a href="/login"><button>Log in</button></a>
        `);
    }
});

//2. Sign Up Page
app.get('/signup', (req, res) => 
{
    res.send(`
        <h2>Create User</h2>
        <form action="/signupSubmit" method="POST">
            <input type="text" name="name" placeholder="Name"><br>
            <input type="email" name="email" placeholder="Email"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/signupSubmit', async (req, res) => 
{
    //Joi Validation
    const schema = Joi.object(
    {
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate(req.body);
    if (validationResult.error != null) 
    {
        return res.send(`
            <p>Error: ${validationResult.error.details[0].message}</p>
            <a href="/signup">Try again</a>
        `);
    }

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); //hash password

    await userCollection.insertOne({ name, email, password: hashedPassword });
    
    req.session.authenticated = true;
    req.session.name = name;
    res.redirect('/members');
});

//3. Log In Page
app.get('/login', (req, res) => 
{
    res.send(`
        <h2>Log In</h2>
        <form action="/loginSubmit" method="POST">
            <input type="email" name="email" placeholder="Email"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/loginSubmit', async (req, res) => 
{
    const schema = Joi.object(
    {
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate(req.body);
    if (validationResult.error != null) {
        return res.send(`
            <p>Invalid input formatting.</p>
            <a href="/login">Try again</a>
        `);
    }

    const { email, password } = req.body;
    const user = await userCollection.findOne({ email: email });

    if (!user || !(await bcrypt.compare(password, user.password))) 
    {
        return res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    res.redirect('/members');
});

//4. Members Only Page
app.get('/members', (req, res) => {
    if (!req.session.authenticated) 
    {
        return res.redirect('/');
    }
    
    const randomImgNum = Math.floor(Math.random() * 3) + 1;
    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src="/${randomImgNum}.jpg" alt="Random Image" width="300"><br><br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});

//5. Log Out Page
app.get('/logout', (req, res) => 
{
    req.session.destroy();
    res.redirect('/');
});

//6. 404 Page
app.get('*splat', (req, res) => 
{
    res.status(404).send('<h1>Page not found - 404</h1>');
});

connectDB().then(() => 
{
    app.listen(port, () => 
    {
        console.log(`Server running on http://localhost:${port}`);
    });
});