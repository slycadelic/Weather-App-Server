// // import jwt package 
const jwt = require('jsonwebtoken');

// function to verify JWTs
const verifyJWT = (req, res, next) => {

    // check if JWT has valid (Authorization) header 
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if(!authHeader.startsWith('Bearer ')) return res.sendStatus(401); // Unauthorized
    
    // define token by using split() on auth header. 
    // Split on ' ' and extract from 1st position (position starts from 0)
    const token = authHeader.split(' ')[1];
    
    const ACCESS_TOKEN_SECRET='01c6d59179e1fcf38f7856bb1889ec69484d8cb877e65ef85eec16dd529fccb7ac998c8d3e4df1d12c97e76ddd9bcc98113c6f563d9e216e2e06d960de586c54';
    
    // verify token using verify() method
    // takes the token, the token secret and a callback function
    // callback function takes an error and decoded object
    // decoded object will have decoded info from the token 
    // read the username and roles(code) from the decoded token info and attach 
    // that value to the request so it can be passed on to other middleware 
    // and/or the controller.
    // calling next() enables the middleware to call the next middleware function 
    jwt.verify(
        token,
        ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if(err) return res.sendStatus(403); //invalid token
            req.user = decoded.UserInfo.username;
            req.roles = decoded.UserInfo.roles;
            next();
        }
    )
}

module.exports = verifyJWT;
