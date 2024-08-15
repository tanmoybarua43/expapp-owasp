const { default: rateLimit } = require('express-rate-limit');
const { default: helmet } = require('helmet');
const { body, validationResult } = require('express-validator');


const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize         =  require("express-mongo-sanitize"),
      xss                   =  require("xss-clean");
     

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");
app.use(mongoSanitize());
app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:true,
    cookie: { 
        secure: true,
        httpOnly: true,
        maxAge: 60 * 60 * 1000 
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
const limit = rateLimit
({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: "Too many requests"
});
app.use("/login",limit);

app.use(express.json({ limit: '10kb' }));

app.use(xss());

app.use(helmet());


//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
// app.get("/register",(req,res)=>{
//     res.render("register");
// });

// app.post("/register",(req,res)=>{
    
//     User.register(new User({username: req.body.username,email: req.body.email,phone: req.body.phone}),req.body.password,function(err,user){
//         if(err){
//             console.log(err);
//             res.render("register");
//         }
//         passport.authenticate("local")(req,res,function(){
//             res.redirect("/login");
//         })    
//     })
// })
app.get("/register", (req, res) => {
    res.render("register", { errorMessages: [] });
});

app.post("/register", [
    body('username').isLength({ min: 4 }).withMessage('Username must be at least 4 characters long.'),
    body('email').isEmail().withMessage('Email must be valid.'),
    body('password').matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/)
        .withMessage('Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a digit, and a special character.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        return res.render('register', { errorMessages });
    }

    User.register(new User({
        username: req.body.username,
        email: req.body.email,
        phone: req.body.phone
    }), req.body.password, function(err, user){
        if (err) {
            console.log(err);
            return res.render('register', { errorMessages: [err.message] });
        }
        passport.authenticate("local")(req, res, function(){
            res.redirect("/login");
        });
    });
});

// app.get("/logout",(req,res)=>{
//     req.logout();
//     res.redirect("/");
// });
app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) { 
            return next(err); 
        }
        res.redirect("/");
    });
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});