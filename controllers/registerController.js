const User = require('../model/User');
const bcrypt = require('bcrypt');

// Handler for new user registration
const handleNewUser = async (req, res) => {
    
    // get user and password destructured 
    const { user, pwd } = req.body;
    // send response bad request if no user or password
    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });
    
    // check for duplicate usernames in the db and send conflict if duplicate
    const duplicate = await User.findOne({ username: user }).exec();
    if (duplicate) return res.sendStatus(409); //Conflict 
    
    try {
        // encrypt the password using bcrypt with await
        // pass password to bcrypt hash() method and add 10 salt rounds
        const hashedPwd = await bcrypt.hash(pwd, 10);
        
        // create and store new user in db
        const result = await User.create({
            "username": user,
            // "roles": { "User": 2001 }, // assigned by default in DB
            "password": hashedPwd
        });
             
        res.status(201).json({ 'success': `New user ${user} created!` });
        
    } catch (err) {
        res.status(500).json({ 'message': err.message });
    }
}

module.exports = { handleNewUser };