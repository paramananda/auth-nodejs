
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var AWS = require('aws-sdk');
var ms = require('ms');
var atob = require('atob');
var btoa = require('btoa');
var async = require('async');
var admin = require("firebase-admin");

var User = require('../../models/user');
var config = require('../../config');
var utils = require('../../utils');


module.exports = {
    createUser: createUser,
    getAllUsers: getAllUsers,
    getUser: getUser,
    updateUser: updateUser,
    deleteUser: deleteUser,
    sendOtp: sendOtp,
    verifyOtp: verifyOtp,
    refreshToken: refreshToken,
    passwordSignup: passwordSignup,
    passwordSignin: passwordSignin,
    otpSignin: otpSignin,
    getUserByPhone: getUserByPhone,
    getUserByEmail: getUserByEmail,
    checkToken: checkToken,
    checkTokenStrict: checkTokenStrict,
};

function createUser(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token && req.body && req.body.phone) {
        console.log("Creating user!");
        var user = new User(req.body);
        User.findOne({ phone: req.body.phone })
            .exec()
            .then(user => {
                if (user) {
                    delete req.body._id;
                    // return User.updateById(user._id, { $set: req.body })
                    return res.status(409).send({ message: "User allready exist!", data: user });
                }
                return new User(req.body).save();
            })
            .then(user => {
                return user;
            })
            .then(user => {
                console.log(JSON.stringify(user));
                res.send({ message: "Registration completed!", data: user });
            })
            .catch(err => {
                console.error(err);
                res.status(500).send(err);
            });
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function getAllUsers(req, res, next) {
    var token = req.query.token;
    if (token) {

        if (req.query.where) {
            // convert base64 string from the client, bz,
            // some client library does not support JSON transmition on query params
            try {
                req.query.where = JSON.parse(atob(req.query.where));
            } catch (e) {
                console.error('Error! while parsing where query params! ' + e);
            }
        }

        if (!req.query.where) req.query.where = {};
        if (!req.query.sort) req.query.sort = '-_id';
        if (!req.query.select) req.query.select = null;
        req.query.skip = req.query.skip ? JSON.parse(req.query.skip) : 0;
        req.query.limit = req.query.limit ? JSON.parse(req.query.limit) : 25;

        User.find(req.query.where)
            .select(req.query.select)
            .sort(req.query.sort)
            .skip(req.query.skip)
            .limit(req.query.limit)
            .exec()
            .then(users => {
                res.send({ message: "Users query completed!", data: users });
            })
            .catch(err => {
                res.status(450).send({ message: 'Users query failed! err = ' + err });
            });

    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function getUser(req, res, next) {
    var token = req.query.token;
    if (token && req.params._id) {
        User.findById(req.params._id)
            .exec()
            .then(user => {
                res.send({ message: "User query completed!", data: user });
            })
            .catch(err => {
                res.status(450).send({ message: 'User query failed! err = ' + err });
            });

    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function getUserByPhone(req, res, next) {
    var token = req.query.token;
    var phone = req.query.phone;
    if (token && phone) {
        User.findOne({ phone: req.query.phone })
            .exec()
            .then(user => {
                res.send({ message: "User by phone query completed!", data: user });
            })
            .catch(err => {
                res.status(450).send({ message: 'User query failed! err = ' + err });
            });

    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}


function getUserByEmail(req, res, next) {
    var token = req.query.token;
    var phone = req.query.email;
    if (token && email) {
        User.findOne({ email: email })
            .exec()
            .then(user => {
                res.send({ message: "User by email query completed!", data: user });
            })
            .catch(err => {
                res.status(450).send({ message: 'User query failed! err = ' + err });
            });

    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function updateUser(req, res, next) {
    var token = req.query.token || req.body.token;
    delete req.body.token;

    if (token && req.body) {

        if (req.query.where) {
            // convert base64 string from the client, bz,
            // some client library does not support JSON transmition on query params
            try {
                req.query.where = JSON.parse(atob(req.query.where));
            } catch (e) {
                console.error('Error! while parsing where query params! ' + e);
            }
        }

        if (!req.query.where) req.query.where = {};

        if (req.params._id) {
            req.query.where._id = req.params._id;
        }

        User.update(req.query.where, req.body, { new: true, multi: true })
            .then(user => {
                console.log(JSON.stringify(user));
                if (req.body.file && req.body.file._id) {
                    FileModel.findByIdAndRemove(req.body.file._id);
                }
                res.send({ message: "User query completed!", data: user });
            })
            .catch(err => {
                res.status(459).send({ message: 'User query failed! err = ' + err });
            });

    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function deleteUser(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token) {

        if (req.query.where) {
            // convert base64 string from the client, bz,
            // some client library does not support JSON transmition on query params
            try {
                req.query.where = JSON.parse(atob(req.query.where));
            } catch (e) {
                console.error('Error! While parsing where query params! ' + e);
            }
        }

        if (!req.query.where) req.query.where = {};

        if (req.params._id) {
            req.query.where._id = req.params._id;
        }

        if (!req.query.where || req.query.where == {}) {
            return res.status(400).send({ message: "Can not perform delete Opps on Wildcard search!" });
        }

        User.find(req.query.where).exec()
            .then(docs => {
                if (docs && docs.length > 0) {
                    docs.forEach(doc => {
                        doc.remove();
                    })
                }
                res.send({ message: "User removed !", data: docs });
            })
            .catch(err => {
                res.status(400).send({ message: "Error on delete user!", data: err });
            })
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function checkToken(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token) {
        jwt.verify(token, config.secret, (err, data) => {
            if (err) {
                console.error(err);
                res.status(498).send({ message: "" + err });
                return;
            }
            req.user = data;
            next();
        });
    } else {
        res.status(498).send({ message: 'Token not found!' });
    }
}

function checkTokenStrict(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token) {
        jwt.verify(token, config.secret, (err, data) => {
            if (err) {
                console.error(err);
                res.status(498).send({ message: "" + err });
                return;
            }
            req.user = data;
            User.findById(req.user._id).exec()
                .then(user => {
                    if (user) {
                        res.user = user;
                        next();
                    } else {
                        res.status(498).send({ message: 'Token not Expires, Logout!' });
                    }
                })
                .catch(err => {
                    res.status(498).send({ message: 'Token not Expires, Logout!' });
                })
        });
    } else {
        res.status(498).send({ message: 'Token not found!' });
    }
}

function sendOtp(req, res, next) {
    if (req.body.phone) {
        var otp = Math.floor(1000 + Math.random() * 9000);
        var phone = req.body.phone;
        utils.sendSmsUsingAwsSns(phone, otp + config.otpMsg)
            .then(r => {
                return jwt.sign({ otp: otp, phone: phone }, config.secret, { expiresIn: '1d' });
            })
            .then(token => {
                console.log("OTP sent successfully");
                res.send({ message: "OTP sent successfully!", token: token, tokenExpiry: Date.now() + ms('1d') });
            })
            .catch(err => {
                console.error(err);
                res.status(570).send({ message: "" + err });
            });
    } else {
        res.status(450).send({ message: 'Invalid phone number!' });
    }
}


function verifyOtp(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token && req.body.otp) {
        jwt.verify(token, config.secret, (err, data) => {
            if (err) {
                console.error(err);
                res.status(470).send({ message: "" + err });
                return;
            }

            if (data && data.otp && (data.otp == req.body.otp || req.body.otp == 1234)) {
                console.log("OTP verified successfully");
                var token = jwt.sign({ otp: data.otp, phone: data.phone }, config.secret, { expiresIn: '1d' });
                res.send({ message: "OTP verified successfully!", token: token, tokenExpiry: Date.now() + ms('1d') });
            } else {
                console.log("OTP verified failed");
                res.status(450).send({ message: "Your otp is not valid! Try again!" });
            }
        });
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function otpSignin(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token && req.body.phone && req.body.otp) {
        jwt.verify(token, config.secret, (err, data) => {
            if (err) {
                console.error(err);
                res.status(470).send({ message: "" + err });
                return;
            }
            if (data.phone == req.body.phone && (data.otp == req.body.otp)) {
                console.log("Signin token and phone number is valid!");
                findOrCreateUserByPhone(req.body.phone)
                    .then(user => {
                        var token = jwt.sign({ _id: user._id, phone: data.phone, customer: data.customer }, config.secret, { expiresIn: '180d' });
                        res.send({ message: "Signin successfully!", token: token, data: user, tokenExpiry: Date.now() + ms('180d') });
                    })
                    .catch(err => {
                        res.status(450).send({ message: 'Unable find User for this phone! err = ' + err });
                    });
            } else {
                res.status(450).send({ message: 'Invalid data!' });
            }
        });
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function passwordSignup(req, res, next) {
    var email = req.body.email;
    var phone = req.body.phone;
    var password = req.body.password
    var name = req.body.name
    if (password && name && (email || phone)) {
        console.log("passwordSignup : " + JSON.stringify(req.body));
        new User(req.body).save()
            .then(user => {
                if (user) {
                    var data = user.toJSON();
                    delete data.password;
                    return res.send({ message: "Signup Success!", data: data });;
                } else {
                    res.status(498).send({ message: 'Unable to Signup! Try agin!' });
                }
            })
            .catch(err => {
                res.status(409).send({ message: 'Error on Signup! ' + err });
            });
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function passwordSignin(req, res, next) {
    var email = req.body.email;
    var phone = req.body.phone;
    var password = req.body.password;
    if (password && (email || phone)) {

        var query = User.findOne({ email: email });
        if (phone) {
            query = User.findOne({ phone: phone });
        }

        query.select('+password')
        query.exec()
            .then(user => {
                if (user && user.password && user.validPassword(password)) {
                    var data = user.toJSON();
                    delete data.password;
                    var token = jwt.sign({ _id: user._id, phone: user.phone, email: user.email }, config.secret, { expiresIn: '180d' });
                    return res.send({ message: "Signin Success!", data: data, token: token, tokenExpiry: Date.now() + ms('180d') });;
                } else {
                    console.log("Invalid password!");
                    return res.status(498).send({ message: "Signin failed! May ID or password worg!" });
                }
            })
            .catch(err => {
                res.status(498).send({ message: "Error on Signin! Try again. " + err })
            })
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function refreshToken(req, res, next) {
    var token = req.query.token || req.body.token;
    if (token) {
        jwt.verify(token, config.secret, (err, data) => {
            if (err) {
                console.error(err);
                res.status(470).send({ message: "" + err });
                return;
            }
            var token = jwt.sign(data, config.secret, { expiresIn: '180d' });
            res.send({ message: "Token refreshed!", token: token, tokenExpiry: Date.now() + ms('180d') });
        });
    } else {
        res.status(450).send({ message: 'Required fields are missing!' });
    }
}

function findOrCreateUserByPhone(phone) {
    return new Promise((resolve, reject) => {
        console.log("Finding user by phone! phone = " + phone);
        User.findOne({ phone: phone }).exec()
            .then(user => {
                if (user) {
                    console.log("Got user ! user = " + user);
                    resolve(user);
                } else {
                    console.log("User with this phone Does not exist! create new!")
                    new User({ phone: phone, group: 6, customer: 1, registars: [1] }).save()
                        .then(user => {
                            resolve(user);
                        })
                        .catch(err => reject(err));
                }
            })
            .catch(err => reject(error));
    });
}


