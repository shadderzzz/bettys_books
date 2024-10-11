// Create a new router
const express = require("express")
const bcrypt = require('bcrypt') // Added bcrypt
const mysql = require('mysql2') // Import mysql2 for database interaction
const saltRounds = 10 // Added saltRounds
const router = express.Router()

// Render the registration form
router.get('/register', function (req, res, next) {
    res.render('register.ejs')                                                               
})    

// Handle the registration form submission
router.post('/registered', function (req, res, next) {
    const plainPassword = req.body.password // Added plainPassword
    const username = req.body.username // Get username from the form
    const firstName = req.body.first // Get first name from the form
    const lastName = req.body.last // Get last name from the form
    const email = req.body.email // Get email from the form

    // Hash the password
    bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
        if (err) {
            return next(err) // Handle error
        }

        // Store hashed password in your database.
        const sql = 'INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?, ?, ?, ?, ?)'
        
        db.query(sql, [username, firstName, lastName, email, hashedPassword], function(err, result) {
            if (err) {
                return next(err) // Handle error
            }

            // Prepare response output
            let resultResponse = 'Hello ' + firstName + ' ' + lastName + 
                ', you are now registered! We will send an email to you at ' + email;
            resultResponse += ' Your password is: ' + plainPassword + 
                ' and your hashed password is: ' + hashedPassword;

            // Sending the response
            res.send(resultResponse)                                                                           
        })
    })
})

router.get('/list', function(req, res, next) {
    // Query to get users without passwords
    const sql = 'SELECT username, first_name, last_name, email FROM users'; // Excluding hashedPassword

    db.query(sql, function(err, results) {
        if (err) {
            return next(err); // Handle error
        }
        // Render the users list page with fetched results
        res.render('users_list.ejs', { users: results });
    });
});

router.get('/login', function(req, res, next) {
    res.render('login.ejs'); // Renders the login form
});

// Add /users/login route to handle the form submission
router.post('/login', function(req, res, next) {
    const username = req.body.username;
    const plainPassword = req.body.password;

    // Query the database to find the user
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], function(err, results) {
        if (err) {
            return next(err); // Handle error
        }
        
        // If user not found
        if (results.length === 0) {
            return res.status(401).send('User not found.'); // Handle error for invalid user
        }

        const user = results[0]; // Assuming the username is unique

        // Compare the provided password with the hashed password in the database
        bcrypt.compare(plainPassword, user.hashedPassword, function(err, isMatch) {
            if (err) {
                return next(err); // Handle error
            }

            if (!isMatch) {
                return res.status(401).send('Invalid password.'); // Handle invalid password
            }

            // Login successful - here you can set session or JWT for the user
            // For now, we'll just send a success response
            res.send('Login successful! Welcome, ' + user.first_name + '!');
        });
    });
});

// Export the router object so index.js can access it
module.exports = router
