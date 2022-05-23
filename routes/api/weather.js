const express = require('express');
const router = express.Router();
const weatherController = require('../../controllers/weatherController');
// const ROLES_LIST = require('../../config/roles_list');
// const verifyRoles = require('../../middleware/verifyRoles');

router.route('/')
    .get(weatherController.getWeather)


module.exports = router;