var express = require('express');
var userCtrl = require("./ctrls/user");
var router = express.Router();


router.get('/', userCtrl.checkToken, userCtrl.getAllUsers);

router.get('/by-phone', userCtrl.checkToken, userCtrl.getUserByPhone);

router.get('/by-email', userCtrl.checkToken, userCtrl.getUserByEmail);

router.get('/:_id', userCtrl.checkToken, userCtrl.getUser);

router.post('/', userCtrl.checkTokenStrict, userCtrl.createUser);

router.put('/', userCtrl.checkTokenStrict, userCtrl.updateUser);

router.put('/:_id', userCtrl.checkTokenStrict, userCtrl.updateUser);

router.delete('/', userCtrl.checkTokenStrict, userCtrl.deleteUser);

router.delete('/:_id', userCtrl.checkTokenStrict, userCtrl.deleteUser);


router.post('/send-otp', userCtrl.sendOtp);
router.post('/verify-otp', userCtrl.verifyOtp);

router.post('/password-signup', userCtrl.passwordSignup);
router.post('/password-signin', userCtrl.passwordSignin);
router.post('/otp-signin', userCtrl.otpSignin);
router.post('/refresh-token', userCtrl.refreshToken);

module.exports = router;
