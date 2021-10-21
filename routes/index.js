const express = require("express");
const router = express.Router();
const { ensureAuthenticated, forwardAuthenticated } = require('../config/auth');

// welcome page
router.get('/',forwardAuthenticated, (req,res) => res.render('welcome'));
// dashbord page
router.get('/dashboard', ensureAuthenticated, (req,res) =>
 res.render('dashboard',{
     name: req.user.name
 }));


module.exports = router;