var libphonenumber = require('google-libphonenumber');
var AWS = require('aws-sdk');
var ms = require('ms');

// Change it as per AWS SNS config
// AWS.config.region = '<aws.region>';
// AWS.config.update({
//     accessKeyId: '<aws.accessKeyId>',
//     secretAccessKey: '<aws.secretAccessKey>',
// });

// var sns = new AWS.SNS();
// sns.setSMSAttributes(
//     {
//         attributes: {
//             DefaultSMSType: "Transactional"
//         }
//     },
//     function (error) {
//         if (error) {
//             console.log(error);
//         } else {
//             console.log("AWS SNS instance initiated!");
//         }
//     }
// );

function normalizePhoneNumber(phone) {
    return new Promise((resolve, reject) => {
        if (phone) {
            var isValid;
            var normalize;
            try {
                var phoneNumber = libphonenumber.PhoneNumberUtil.getInstance().parse(phone, "IN");   //with default country
                isValid = libphonenumber.PhoneNumberUtil.getInstance().isValidNumber(phoneNumber);
                normalize = libphonenumber.PhoneNumberUtil.getInstance().format(phoneNumber, libphonenumber.PhoneNumberFormat.E164);
            } catch (e) {
                console.error("NumberParseException was thrown: " + e.toString());
            }

            if (isValid && normalize) {
                resolve(normalize);
            } else {
                reject("Invalid phone number formatting!");
            }
        }
    });
}

function sendSmsUsingAwsSns(phone, msg) {
    return new Promise((resolve, reject) => {
        var params = {
            Message: msg,
            MessageStructure: 'string',
            PhoneNumber: phone
        };

        sns.publish(params, (err, data) => {
            if (err) {
                console.log(err, err.stack);  // an error occurred
                reject(err);
            } else {
                console.log(data);            // successful response
                resolve(data);
            }
        });

    });
}



module.exports = {
    normalizePhoneNumber: normalizePhoneNumber,
};
