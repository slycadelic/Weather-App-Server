const User = require('../model/User');

// import jwt package
const jwt = require('jsonwebtoken');

// function to handle refreshToken
const handleRefreshToken = async (req, res) => {
    
    // refresh tokens stored in cookies called jwt so check first if it exists
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;

    // Find user who is logged in or send response if not found
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) return res.sendStatus(403); //forbidden 
    
    // evaluate jwt 
    // verify refresh token using verify() method
    // takes in refresh token, token_secret from env and callback function
    // if there is an error or if username from token is not username of user logged in
    // then return response with error
    // otherwise, refresh token is verified and new access token created using jwt sign()
    // send the new access token back as response 
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if(err || foundUser.username !== decoded.username) return res.sendStatus(403);
            const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    'UserInfo': {
                        "username": decoded.username,
                        'roles': roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '5m' }
            );
            res.json({ roles, accessToken })
        }
    );
}

module.exports = { handleRefreshToken };