
require("./utils.js");

require('dotenv').config();
const url = require('url');
const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
// const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// var {database} = include('databaseConnection');

// const userCollection = database.db(mongodb_database).collection('users');

const { ObjectId } = require('mongodb');

app.set('view engine', 'ejs');

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Login", link: "/login"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/moon"}
]

app.use(express.urlencoded({extended: false})); //middle ware

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

//middle ware
app.use("/", (req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        res.render("index_noLogin");
    } else {
        res.render("index_loggedIn", {req: req});
    }
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Yerim Moon</h1>");
});


app.get('/signup', (req,res) => {
    res.render("signup");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/signupSubmit', async (req, res) => {
    const { username, password } = req.body;

    const schema = Joi.object({
        username: Joi.string().alphanum().min(3).max(20).required(),
        password: Joi.string().min(6).max(20).required() // Ensure passwords are strong
    });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        const errorMessage = validationResult.error.message;
        console.log(validationResult.error);
        res.render("signupError", { errorMessage: errorMessage });
        return;
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Using MySQL's parameterized query feature to prevent SQL injection
        const [result] = await database.execute(
            'INSERT INTO user (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );

        console.log("Inserted user with ID:", result.insertId);

        req.session.authenticated = true;
        req.session.name = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    } catch (error) {
        console.error("Error inserting user:", error.message);
        res.render("signupError", { errorMessage: "Error creating your account." });
    }
});

app.post('/loginSubmit', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Query the database for a user with the provided username
        const [rows] = await database.execute(
            'SELECT * FROM user WHERE username = ?',
            [username]
        );

        // If no user found, render the invalid login view
        if (rows.length === 0) {
            return res.render("invalidLogin");
        }

        // User found, check the password
        const user = rows[0];
        const passwordMatches = await bcrypt.compare(password, user.password);

        if (passwordMatches) {
            // Password matches, set up the session
            req.session.authenticated = true;
            req.session.name = user.username;
            req.session.cookie.maxAge = expireTime;

            return res.redirect('/members');
        } else {
            // Password does not match
            return res.render("invalidLogin");
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).render("error", {errorMessage: "Internal server error"});
    }
});


app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        // Array of image filenames
        const images = ['fluffy.gif', 'socks.gif', 'computer.gif'];
        // Select a random image
        const selectedImage = images[Math.floor(Math.random() * images.length)];
        // Render the members page and pass the selectedImage
        res.render("members", {req: req, selectedImage});
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1, user_type: 1}).toArray();
 
    res.render("admin", {users: result});
});

app.get('/promote/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await userCollection.updateOne({ _id: ObjectId(id) }, { $set: { user_type: 'admin' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});
  
app.get('/demote/:id', async (req, res) => {
    try {
        const id = req.params.id;
        await userCollection.updateOne({ _id: ObjectId(id) }, { $set: { user_type: 'user' } });
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});
  
app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 