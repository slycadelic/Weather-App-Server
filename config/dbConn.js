const mongoose = require('mongoose');

const connectDB = async () => {
    const DATABASE_URI='mongodb+srv://admin:BillabonG@userdata.ludac.mongodb.net/UserDB?retryWrites=true&w=majority'
    try {
        await mongoose.connect(DATABASE_URI, {
            useUnifiedTopology: true,
            useNewUrlParser: true
        })
    } catch (err) {
        console.log(err);
    }
}

module.exports = connectDB;
