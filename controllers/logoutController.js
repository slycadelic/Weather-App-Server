const User = require('../model/User');

// function to handle Logout request
const handleLogout = async (req, res) => {

    // On client side, delete the accessToken

    // get cookies from request and send response if no cookies
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); // No content

    // get refreshToken from cookies (stored as jwt in cookies)
    const refreshToken = cookies.jwt;

    // Check for refreshToken in DB
    // first find user with this token 
    // if user not found then clear cookies and send response
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        return res.sendStatus(204);  // No content
    }
    
    // Delete the refreshToken in DB 
    foundUser.refreshToken = '';
    const result = await foundUser.save();

    // Delete the cookie 
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    // Send 204 response saying all is well but no content because logout successful
    res.sendStatus(204);    
}

module.exports = { handleLogout };