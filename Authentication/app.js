//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));      // set public folder as style resource
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));


///////////////Session configure//////////////////////////////////
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize()); // initialize passport
app.use(passport.session());    // use passport to manipulate sessions
/////////////////////////////////////////////////


// connect to mongodb
mongoose.connect("mongodb://localhost:27017/userDB");

// create schema
const userSchema = new mongoose.Schema (
    {
        email: String,
        password: String,
        googleId: String,
        githubId: String,
        username: String,
        secret: Array
    }, 
    { collection: "userinfo"}
);

/////////////////////////////////////////////////
// hash & salt password -> save user into mongodb database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
/////////////////////////////////////////////////

// create model
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

///////////////////////Google authentication//////////////////////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile._json.email, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
/////////////////////////////////////////////////

//////////////////GITHUB Authentication/////////////////////
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENTID,
    clientSecret: process.env.GITHUB_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ username: profile.username,githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
/////////////////////////////////////////////////

// HOME PAGE
app.get("/", function (req, res) {
    res.render("home");
});

// LOGIN PAGE
app.get("/login", function (req, res) {
    res.render("login");
});

        // catche the post from the login route
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
    });

// REGISTER PAGE
app.get("/register", function (req, res) {
    res.render("register");
});

        // catch the post from the register route
app.post("/register", function (req, res) {

    // from the passport-local-mongoose package
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local") (req, res, function () {
                res.redirect("/secrets");
            });
        }
    }); 

});

// SECRET PAGE
// enable directly visit secret url when user logged in
app.get("/secrets", function (req, res) {
    User.find({"secret":{$ne:null}}, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                console.log(foundUsers);
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

// SUBMIT PAGE
app.get("/submit", function (req, res) {
     // check if the user is authenticated
     if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;
    // the passport save the user info in the req.user
    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret.push(submittedSecret);
                foundUser.save(function() {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

// LOGOUT
app.get("/logout", function (req, res) {
    req.logout(function () { console.log('Done logging out.'); });
    res.redirect("/");
    
});

/////////////////////// google authentication
app.get('/auth/google',
    // pop up the google login
  passport.authenticate('google', { scope: ['openid', 'profile', 'email'] })
  );

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });
///////////////////////////////////


/////////////////// github authentication
app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
/////////////////////////////////


app.listen(3000, function() {
    console.log("Server started on port 3000.")
});
