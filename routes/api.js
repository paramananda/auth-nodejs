var express = require('express');
var router = express.Router();

var user = require('./user');

router.use('/users', user);

module.exports = router;
