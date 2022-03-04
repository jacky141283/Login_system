//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const req = require("express/lib/request");
// const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

//storing all static file in public folder
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });

// const db = mongoose.connection;
// db.on("error", console.error.bind(console, "connection error"));
// db.once("open", function(){
//     console.log("Connection opened");
// });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String, //needed for db to have googleID
    secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const UserModel = new mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(UserModel.createStrategy());

// use static serialize and deserialize of model for passport session support
// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    UserModel.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/LoginSystem"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);

        UserModel.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", (req, res) => {
    res.render("home"); //home.ejs
});

app.get("/auth/google", passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/LoginSystem",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    }
);


app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", (req, res) => {
    const user = new UserModel({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("secrets");
            });
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {
    UserModel.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect('/secrets');
            });
        }
    });
});

app.get("/secrets", (req, res) => {
    UserModel.find({"secret" : {$ne : null}}, (err, foundUsers) => {
        if(err)
            console.log(err);
        else {
            if(foundUsers)
                res.render("secrets", {usersWithSecrets : foundUsers});
        }
    });
});



app.get("/submit", (req, res) => {
    if (req.isAuthenticated())
        res.render("submit"); //secrets.ejs
    else
        res.redirect("/login");
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);

    UserModel.findById(req.user.id, (err, foundUser) => {
        if(err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;  
            foundUser.save(function() {
                res.redirect("/secrets");
            });      
        }
    });
});


app.listen("3000", () => {
    console.log("Server listening at port 3000");
});