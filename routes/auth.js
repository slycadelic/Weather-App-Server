// Define router
const express = require('express');
const router = express.Router();

// Import controller for login auth
const authController = require('../controllers/authController');

// Create Post route which will use the controller 
router.post('/', authController.handleLogin);

// export it to be user by server.js
module.exports = router;