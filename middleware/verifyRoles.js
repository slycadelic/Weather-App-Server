// Create function to verify Roles with input as a rest operator (similar to spread),
// which allows any number of inputs
const verifyRoles = (...allowedRoles) => {

    // return a anonymous function 
    return (req, res, next) => {

        // Check if there is no request or if the request has valid Roles
        // Done using optional chaining operator .?
        // The optional chaining operator provides a way to simplify accessing 
        // values through connected objects when it's possible that a reference 
        // or function may be undefined or null.
        if(!req.roles) return res.sendStatus(401);

        // store all allowed Roles in an array using the spread operator
        const rolesArray = [...allowedRoles];

        // Map over the roles sent from the JWT in the req. The roles are assigned to 
        // the req in the verifyJWT middleware. 
        // Using map(), compare each role from req with allowedRoles
        // Get true/false for each role in rolesArray using include(). 
        // Then using find(), get the first or any true value. 
        // Any allowed role will give a result which will allow access
        const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);

        // if there is no result, send back error status which will deny access
        if(!result) return res.sendStatus(401);
        next();
    }
}

module.exports = verifyRoles;
