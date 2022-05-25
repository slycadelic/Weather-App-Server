const User = require('../model/User');
const bcrypt = require('bcrypt');

// import jwt package and tokens from env 
const jwt = require('jsonwebtoken');

// function to handle login process
const handleLogin = async (req, res) => {
    
    // get user and password destructured send response if no user or password
    const { user, pwd } = req.body;
    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });
    
    const ACCESS_TOKEN_SECRET='01c6d59179e1fcf38f7856bb1889ec69484d8cb877e65ef85eec16dd529fccb7ac998c8d3e4df1d12c97e76ddd9bcc98113c6f563d9e216e2e06d960de586c54';
    const REFRESH_TOKEN_SECRET='3dec14f47e98c5b49d3bac0dd33ea89774e202570c51d3a45a89f1f4827d26d467c95c26a25b6d28c09bd0cdc412cc0c2686c0e88f03143e30ef1aeb284a1c4a';
    
    // use find method to get user who logs in. If not found, send response Unauthorized
    const foundUser = await User.findOne({ username: user }).exec();
    if (!foundUser) return res.sendStatus(401); //Unauthorized 
    
    // evaluate password using bcrypt compare() method which takes given and stored password
    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {

        // get the role of the user
        const roles = Object.values(foundUser.roles).filter(Boolean);
        
        // create JWTs after login
        // use .sign() method to to create tokens
        // method takes in username+roles_code, token secret from env and
        // options value to make it expire (5 to 15 mins for access and hrs/days
        // for refresh token)
        const accessToken = jwt.sign(
            {
                'UserInfo': {
                    'username': foundUser.username,
                    'roles': roles
                }
            }, 
            ACCESS_TOKEN_SECRET,
            { expiresIn: '5m' } 
        );
        const refreshToken = jwt.sign(
            { 'username': foundUser.username }, 
            REFRESH_TOKEN_SECRET,
            { expiresIn: '1d' } 
        );

        foundUser.refreshToken = refreshToken;
        const result = await foundUser.save();

        // Send token as httpOnly cookie so that it is not available to JavaScript and set
        // its expiry 
        // secure: true
        res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24*60*60*1000 });
        // Send accessToken as json
        res.json({ roles, accessToken });

    } else {
        res.sendStatus(401); // if no password match
    }
}

module.exports = { handleLogin };
