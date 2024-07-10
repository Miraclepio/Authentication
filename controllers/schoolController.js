const schoolModel = require('../models/schoolModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const sendEmail = require("../utils/mail");
const { generateWelcomeEmail } = require('../utils/emailtemplates');
const signUpUser = async (req, res) => {
    try {
        const { name, email, password, phoneNumber, studentClass } = req.body;
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        // Validating inputs
        if (!name || name.trim().length === 0) {
            return res.status(404).json({ message: "Name field cannot be empty" });
        }

        if (!email || !emailPattern.test(email)) {
            return res.status(404).json({ message: "Invalid email" });
        }

        // if (!password || !passwordPattern.test(password)) {
        //     return res.status(404).json({ 
        //         message: "Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a digit, and a special character" 
        //     });
        // }

        if (!phoneNumber || phoneNumber.trim().length === 0) {
            return res.status(404).json({ message: "Phone number field cannot be empty" });
        }

        if (!studentClass || studentClass.trim().length === 0) {
            return res.status(404).json({ message: "Student class field cannot be empty" });
        }
        const existingEmail = await schoolModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        // Using bcrypt to salt and hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new schoolModel({
            name,
            email,
            password: hashedPassword,
            phoneNumber,
            studentClass
        });

        const createdUser = await user.save();

        // Using JWT to sign in the user
        const token = jwt.sign({ email: createdUser.email, userId: createdUser._id }, process.env.secret_key, { expiresIn: "1d" });

        // Send verification email
        const verificationLink = `http://yourfrontenddomain.com/verify/${token}`;
        const emailSubject = 'Verification Mail';
        const html = generateWelcomeEmail(name, verificationLink);
        const mailOptions = {
            from: process.env.user,
            to: email,
            subject: emailSubject,
            html: html 
        };

        await sendEmail(mailOptions);

        return res.status(200).json({ message: "Successful", token, createdUser });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

const verifyUser = async (req, res) => {
    try {
        const { token } = req.params;
        const { email } = jwt.verify(token, process.env.secret_key);

        const user = await schoolModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'User already verified' });
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: "Verification successful", user });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};
const resendVerification = async (req, res) => {
    try {
        const { email } = req.body;
        const checkUser = await schoolModel.findOne({ email });

        if (!checkUser) {
            return res.status(400).json({ message: 'User with this email is not registered' });
        }

        if (checkUser.isVerified) {
            return res.status(400).json({ message: 'User is already verified' });
        }

        const token = jwt.sign({ email: checkUser.email, userId: checkUser._id }, process.env.secret_key, { expiresIn: "1d" });
        const verificationLink = `http://yourfrontenddomain.com/verify/${token}`;
        const emailSubject = 'Resend Verification Mail';
        const html = generateWelcomeEmail(checkUser.name, verificationLink, true);
        const mailOptions = {
            from: process.env.user,
            to: email,
            subject: emailSubject,
            html: html
        };

        // Send the email
        await sendEmail(mailOptions);

        // Update the user's isVerified status
        checkUser.isVerified = true;
        await checkUser.save();

        return res.status(200).json({ message: "Verification email sent" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};


const login = async (req, res)=>{
    try {
        const {email, password}= req.body
        const findUser = await schoolModel.findOne({email})
        if(!findUser){
            return res.status(404).json({message:'user with this email does not exist'})
        }
        const matchedPassword = await bcrypt.compare(password, findUser.password)
       if(!matchedPassword){
            return res.status(400).json({message:'invalid password'})
        }
        if(findUser.isVerified === false){
           return  res.status(400).json({message:'user with this email is not verified'})
        }
        findUser.isLoggedIn = true
        const token = jwt.sign({ 
            name:findUser.name,
            email: findUser.email,
            userId: findUser._id }, 
            process.env.secret_key,
            { expiresIn: "1d" }); 

            return  res.status(200).json({message:'login successfully ',token})

        
    } catch (error) {
        
        return res.status(500).json(error.message);
    }
}

module.exports={
    signUpUser,
    verifyUser,
    resendVerification,
login,


}

