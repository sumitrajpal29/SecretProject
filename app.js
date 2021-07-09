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
const FacebookStrategy = require("passport-facebook")

const app = express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:"Looking for Alaska.",
  resave:false,
  saveUninitialized:true
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId : String,
  facebookId : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.use(new googleStrategy({
  clientID : process.env.CLIENT_ID,
  clientSecret : process.env.CLIENT_SECRET,
  callbackURL : "http://localhost:3000/auth/google/secrets",
  // useProfileURL : "http://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessTocken,refressTocken,profile,cb){
    User.findOrCreate({googleId : profile.id},function(err,user){
      return cb(err,user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.listen(3000,function(){
  console.log("app is running on port 3000.");
});

app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  if(req.isAuthenticated()) res.render("secrets");
  else res.redirect("login");
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/")
});


//_________________Google Auth_______________//
app.get("/auth/google",
  passport.authenticate("google",{scope:["profile"]}));

app.get("/auth/google/secrets",
passport.authenticate("google",{failureRedirect:"/login"}),
  function(req,res){
    res.redirect("/secrets");
  });


  //_________________Facebook Auth_______________//
app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });


app.post("/register",function(req,res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err) {
      res.redirect("/register");
      console.log(err);
    }
    else {
      passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    }) }
  })
});

app.post("/login",function(req,res){
  const user = new User ({username:req.body.username,password:req.body.password});
    req.login(user,function(err){
      if(err){
        console.log(err);
        res.redirect("/login")
      }
      else {
        passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        })
      }
    })});


    //deprication fix for mongoose
    mongoose.set('useNewUrlParser', true);
    mongoose.set('useFindAndModify', false);
    mongoose.set('useCreateIndex', true);
