// Define router
const express = require('express');
const router = express.Router();

// Import controller for registering
const registerController = require('../controllers/registerController');

// Create Post route which will use the controller 
router.post('/', registerController.handleNewUser);

// export it to be user by server.js
module.exports = router;