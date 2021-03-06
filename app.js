const express = require('express');
const expressEjsLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');


const app = express();

//passport config
require('./config/passport')(passport);

//DB Config
const db = require('./config/keys').MongoURI;


// connect to mongo
mongoose.connect(db, { useNewUrlParser: true, useUnifiedTopology: true})
    .then(() => console.log("mongodb connected..."))
    .catch(err => console.log(err));


// EJS

app.use(expressEjsLayouts);
app.set('view engine', 'ejs');

// bodyParser
app.use(express.urlencoded({ extended: false}));

//express session
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
  }));

  //passport middleware
  app.use(passport.initialize());
  app.use(passport.session());


  //connect flash
  app.use(flash());

  // globel vars
  app.use((req, res, next) =>{
      res.locals.success_msg = req.flash('success_msg');
      res.locals.error_msg = req.flash('error_msg)');
      res.locals.error = req.flash('error');
      next();
  });

//routes
app.use('/', require('./routes/index'));
app.use('/users', require('./routes/users'));

 


const PORT = process.env.PORT|| 5000;

app.listen(PORT, console.log(`server is listining on PORT ${PORT}`));