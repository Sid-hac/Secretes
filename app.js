
const express  = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const { ifError } = require("assert");
const { error } = require("console");
const encrypt = require("mongoose-encryption");
const dotenv = require("dotenv").config();
const bcrypt = require("bcrypt");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const expressSession = require("express-session");
const session = require("express-session");
const  GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");



const app = express();

app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

const port = process.env.PORT;

app.use(session({

    secret : process.env.SECRET,
    resave : false,
    saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://localhost:27017/userDB" , {useNewUrlParser : true , useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
    email :String,
    password :String,
    googleId : String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const Users = new mongoose.model("user" , userSchema);
passport.use(Users.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
   
  },
  function(accessToken, refreshToken, profile, cb) {
    Users.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/" , async(req , res) => {
 
    try {
        res.render("home");
    } catch (error) {
        console.log(error);
    }
    
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/register" }),
  async(req, res) => {
    // Successful authentication, redirect secrets.
    try {
        res.redirect("/secrets");
    } catch (error) {
        console.log(error);
    }
    
  });

app.get("/login" , async(req , res) => {
 
    try {
        res.render("login");
    } catch (error) {
        console.log(error);
    }
    
});


app.get("/register" , async(req , res) => {

    try {
        res.render("register");
    } catch (error) {
        console.log(error);
    }
    
});

app.get("/secrets" , async(req , res) => {

    try {
        Users.find({"secret" : {$ne : null}})
        .then(foundUser => {
           res.render("secrets" , {foundUserSecret : foundUser})
        })
        .catch(err => {
     
         console.log(err);
        });
        
    } catch (error) {
        console.log(error);
    }
  
});

app.get("/submit" , async(req , res) =>{
   try {

    if(req.isAuthenticated()){
        res.render("submit");
    }else{
    
        res.redirect("/login");
    }
    
   } catch (error) {
      
    console.log(error);
   }

  
});

app.get("/logout" , async(req , res) => {

    try {
        req.logOut(function(){

            res.redirect("/");
        });
        
    } catch (error) {
        console.log(error);
    }
   
});


app.post("/register" ,async (req , res) =>{

    try {
         
        await Users.register({username : req.body.username} , req.body.password);
        passport.authenticate("local")(req , res , function(){

            res.redirect("/secrets");
        });

        
    } catch (error) {
        
        console.log(error);
        res.redirect("/register");
    }
   
});

app.post("/login" , async (req , res) => {
    
    try {
       
        const user = new Users({

            username: req.body.username,
            password: req.body.password
        });
        
        req.logIn(user , function(err){

            if(err){
                console.log(err);
                res.redirect("/login");
            }else{

                passport.authenticate("local");
                res.redirect("/secrets");
            }
        });
        
    } catch (error) {
        
        console.log(error);
    }

});

app.post("/submit" , async(req , res) => {

    try {
        const submittedSecret = req.body.secret;
    console.log(req.user.id);
    
    Users.findById(req.user.id)
    .then(foundUser => {
        if (foundUser) {
            foundUser.secret = submittedSecret;
            return foundUser.save();
        } 
        res.redirect("/secrets");
    })
    .catch(err => {
        console.log(err);
        res.redirect("/secrets"); // Handle errors appropriately
    });
        
    } catch (error) {
        
        console.log(error);
    }


});


app.listen( port, function(){
    console.log(`server started at port ${port}`);
 });


 