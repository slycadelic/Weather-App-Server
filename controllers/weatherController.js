const axios = require('axios')

const getWeather = async (req, res) => {
    const base = "https://api.openweathermap.org/data/2.5/weather?q=";
    const key = process.env.OPEN_WEATHER_API_KEY;
    const query = req.query.cityName;

    try {
        const response = await axios.get(`${base}${query}&units=metric&APPID=${key}`);
        res.json(response.data);
        // console.log('response sent');
        
    } catch (error) {

        // console.log('Error', error.message);
        res.status(error.response.status).send(error.message);
        // console.log('error sent');
        // Error 😨
    //     if (error.response) {
    //         /*
    //          * The request was made and the server responded with a
    //          * status code that falls out of the range of 2xx
    //          */
    //         // console.log(error.response.data);
    //         // console.log(error.response.status);
    //         // console.log(error.response.headers);
    //         res.status(error.response.status).send(error.message);
    //     } else if (error.request) {
    //         /*
    //          * The request was made but no response was received, `error.request`
    //          * is an instance of XMLHttpRequest in the browser and an instance
    //          * of http.ClientRequest in Node.js
    //          */
    //         console.log(error.request);
    //         res.status(error.response.status).send(error.message);
    //     } else {
    //         // Something happened in setting up the request and triggered an Error
    //         console.log('Error', error.message);
    //     }
    //     console.log(error);
    }

}

module.exports = { getWeather }