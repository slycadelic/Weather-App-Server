const User = require('../model/User');

// import jwt package
const jwt = require('jsonwebtoken');

// function to handle refreshToken
const handleRefreshToken = async (req, res) => {
    
    // refresh tokens stored in cookies called jwt so check first if it exists
    const cookies = req.cookies;
    if (!cookies.jwt) return res.sendStatus(401);
    const refreshToken = cookies.jwt;
    
    const ACCESS_TOKEN_SECRET='01c6d59179e1fcf38f7856bb1889ec69484d8cb877e65ef85eec16dd529fccb7ac998c8d3e4df1d12c97e76ddd9bcc98113c6f563d9e216e2e06d960de586c54';
    const REFRESH_TOKEN_SECRET='3dec14f47e98c5b49d3bac0dd33ea89774e202570c51d3a45a89f1f4827d26d467c95c26a25b6d28c09bd0cdc412cc0c2686c0e88f03143e30ef1aeb284a1c4a';

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
        REFRESH_TOKEN_SECRET,
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
                ACCESS_TOKEN_SECRET,
                { expiresIn: '5m' }
            );
            res.json({ roles, accessToken })
        }
    );
}

module.exports = { handleRefreshToken };
