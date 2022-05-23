const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    roles: {
        User: {
            type: Number,
            default: 1
        },
        Admin: Number
    },
    password: {
        type: String,
        required: true
    },
    refreshToken: String
});

// The first argument is the singular name of the collection your model is for
// Mongoose automatically looks for the plural, lower-cased version of your model name 
// Therefore, for model User it will look for users collection
module.exports = mongoose.model('User', userSchema);