// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
const User = require('./models/user'); 

const { body, validationResult } = require('express-validator');
require('dotenv').config();
const app = express();
const cors = require('cors');
app.use(cors());


// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));


app.use(express.json());
app.use('/api/auth', require('./routes/auth'));
// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});



// Forgot Password: Generate token and send reset email
app.post('/forgot-password', 
    body('email').isEmail().withMessage('Please provide a valid email'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array() });
        }

        const { email } = req.body;
        
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Generate a reset token
            const resetToken = crypto.randomBytes(20).toString('hex');
            const resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry

            // Save the token and expiry to the user
            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = resetTokenExpiry;
            await user.save();

            // Send reset link email
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                text: `Click the link to reset your password: ${resetUrl}`,
            };

            await transporter.sendMail(mailOptions);
            res.status(200).json({ message: 'Password reset link sent to your email' });

        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Server error' });
        }
    }
);


// Routes
app.use('/api/auth', authRoutes);


// Reset Password: Validate token and reset password
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    console.log(req.params, req.body);

    try {
        // Find user by token
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }, // Check if token is expired
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update password and clear token and expiry
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
