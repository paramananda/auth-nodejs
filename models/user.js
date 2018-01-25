var mongoose = require('mongoose');
const bcrypt = require('bcrypt');
var autoIncrement = require('mongoose-auto-increment');
var deepPopulate = require('mongoose-deep-populate')(mongoose);

var config = require('../config');

// autoIncrement.initialize(mongoose.connection);

var Schema = mongoose.Schema;

var me = new Schema({
    name: String,
    email: String,
    phone: String,
    password: { type: String, select: false },
    firstName: String,
    lastName: String,
}, { timestamps: true });

// me.plugin(autoIncrement.plugin, {
//     model: 'user', field: '_id', startAt: 1, incrementBy: 1
// });

me.statics.generateHash = function (password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

me.methods.validPassword = function (password) {
    return bcrypt.compareSync(password, this.password);
};

me.plugin(deepPopulate);

me.pre('save', function (next) {
    console.log("Pre save : " + JSON.stringify(this));
    var UserModel = mongoose.model('user');
    if (UserModel) {
        var query = UserModel.findOne({ email: this.email });
        if (this.phone) {
            query = user.findOne({ phone: this.phone });
        }
        query.exec()
            .then(user => {
                if (user) {
                    console.log("User exist!");
                    next(new Error("User already exist!"));
                } else {
                    console.log("User can be register!");
                    this.password = UserModel.generateHash(this.password);
                    next();
                }
            })
            .catch(err => {
                console.log("Error on find user before signup!");
                next(err);
            })
    }
});

me.post('remove', doc => {
    // Handle post middle ware
});


module.exports = mongoose.model('user', me);