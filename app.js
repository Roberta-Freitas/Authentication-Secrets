//jshint esversion:6
require('dotenv').config(); // Load environment variables from .env file

const express = require("express");
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');

const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

app.use(session({
  secret: process.env.SOME_LONG_UNGUESSABLE_STRING,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('MongoDB connected');
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
  });

  const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});


passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});


app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

  app.get('/auth/google/secrets',
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("secrets");
  });


  app.get("/secrets", async function (req, res) {
    try {
      const foundUsers = await User.find({ secret: { $ne: null } });
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    } catch (err) {
      console.error(err);
    }
  });

  // app.get("/secrets", function (req, res) {
  //   User.find({"secret": {$ne:null }}, function(err, foundUsers){
  //     if (err) {
  //       console.error(err);
  //     } else {
  //       if (foundUsers) {
  //         res.render("secrets", {usersWithSecrets: foundUsers});
  //       }
  //     }
  //   });
  // });


app.get("/submit", function (req, res) {
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async function (req, res) {
  if (req.isAuthenticated()) {
    const submittedSecret = req.body.secret;

    console.log("User is authenticated. User ID:", req.session.passport.user._id); // Access user ID from session

    try {
      const foundUser = await User.findById(req.session.passport.user._id); // Use user ID from session

      if (foundUser) {
        foundUser.secret = submittedSecret;
        await foundUser.save();
        console.log("Secret submitted successfully.");
        res.redirect("secrets");
      } else {
        console.error("User not found in the database.");
        res.redirect("/login");
      }
    } catch (err) {
      console.error("Error submitting secret:", err);
      res.redirect("/submit"); // Redirect to an error page or handle the error as needed
    }
  } else {
    console.error("User is not authenticated.");
    res.redirect("/login");
  }
});



app.get("/logout", function (req, res) {
  req.logout(function(err) {
    if (err) {
      console.error(err);
    }
    // Redirect the user to the home page after logging out
    res.redirect("/");
  });
});


app.post("/register", async function (req, res) {
  const newUser = new User({ username: req.body.username });

  // `User.register` method comes from `passport-local-mongoose`
  User.register(newUser, req.body.password, function (err, user) {
    if (err) {
      console.error(err);
      res.redirect("/register");
    } else {
      // Authenticate the user after successful registration
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});


app.post("/login", async function (req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
    });
});


app.listen(3000, function () {
  console.log("Server started on port 3000");
});
