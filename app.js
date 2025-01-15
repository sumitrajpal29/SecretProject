require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");

const passport = require("passport");
const passportLocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const session = require("express-session");

const googleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook");

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;
const BASE_URL = process.env.BASE_URL;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: "Looking for Alaska.",
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: []
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});


passport.use(new googleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "BASE_URL/auth/google/secrets",
  useProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessTocken, refressTocken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "BASE_URL/auth/facebook/secrets"
},
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


const port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log(`App is running on port ${port}.`);
});

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, found) {
    if (err) console.log(err);
    else
      res.render("secrets", { foundSecrets: found });
  })
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/")
});


//_________________Google Auth_______________//
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  });


//_________________Facebook Auth_______________//
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) res.render("submit");
  else res.redirect("login");
});


app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      res.redirect("/register");
      console.log(err);
    }
    else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/login", function (req, res) {
  const user = new User({ username: req.body.username, password: req.body.password });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
      console.error("error");
      res.redirect("/login")
    }
    else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/submit", function (req, res) {
  User.findById(req.user.id, function (err, found) {
    if (!err) {
      if (found) {
        found.secret.push(req.body.secret);
        found.save();
        res.redirect("/secrets")
      }
      else res.redirect("/login");
    }
    else console.log(err);
  })
});


//deprication fix for mongoose
mongoose.set('useNewUrlParser', true);
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
