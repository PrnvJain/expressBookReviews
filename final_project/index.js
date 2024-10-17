const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session')
const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer", session({ secret: "fingerprint_customer", resave: true, saveUninitialized: true }))

app.use("/customer/auth/*", function auth(req, res, next) {
    // Check if the user has an access token in the session
    if (!req.session.authorization || !req.session.authorization.accessToken) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // Verify the access token and extract the user details from it
    const accessToken = req.session.authorization.accessToken;
    try {
        const decodedToken = jwt.verify(accessToken, "yourSecretKey"); // Ensure the secret matches
        req.username = decodedToken.username; // Store the username in the request object
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid access token" });
    }
});

const PORT = 5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT, () => console.log("Server is running"));