const schoolModel = require('../models/schoolModel')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()
const sendEmail=require('../utils/mail')
const {generateChangePasswordEmail,generateForgotPasswordEmail}=require('../utils/emailtemplates')

const changePassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { oldPassword, newPassword, confirmNewPassword } = req.body;

        // Decode the token to get the userId
        const decodedToken = jwt.verify(token, process.env.secret_key);
        const userId = decodedToken.userId;

        // Find the user by ID
        const user = await schoolModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Compare the old password with the stored hashed password
        const matchedPassword = await bcrypt.compare(oldPassword, user.password);
        if (!matchedPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Check if the new password matches the confirmation password
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: 'New password does not match confirm new password' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        // Generate change password email content
        const resetLink=`https://thecurve-app.vercel.app/#/${token}`
        const emailSubject = 'Change Password Request';
        const html = generateChangePasswordEmail(user.name,resetLink);
        const mailOptions = {
            from: process.env.user,
            to: user.email,
            subject: emailSubject,
            html: html
        };

        // Send the change password email
        await sendEmail(mailOptions);

        return res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

// FORGOT PASSWORD



// const forgotPassword = async (req, res) => {
//     try {
//         const { email } = req.body;

//         const user = await schoolModel.findOne({ email });
//         if (!user) {
//             return res.status(404).json({ message: 'User with this email does not exist' });
//         }
// //check if the mail has been sent
// if (user.resetToken){
// res.status(200).send({message:"mail is already sent , please check your mail."})
// }
//         // Generate a token
//         const token = jwt.sign({ userId: user._id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '1h' });
//         console.log('1')
//         user.resetToken==token
//         console.log('2')
//         await user.save()

//         // Send password reset email
//         const resetLink = `http://yourfrontend.com/reset-password/${token}`; 
//         const emailSubject = 'Password Reset';
//         const html = `<p>Hello ${user.name},</p><p>Please click the following link to reset your password:</p><a href="${resetLink}">Reset Password</a>`;

//         const mailOptions = {
//             from: process.env.USER,
//             to: email,
//             subject: emailSubject,
//             html: html,
//         };
// // if(sendEmail(mailOptions)){
// //     return res.status(200).json({ message: "password reset email already sent ,please check your mail." });  
// // }

// // mailOptions=false
// console.log('3')
// // if(sendEmail(mailOptions)=true){
// //     return res.status(200).json({ message: "password reset email already sent ,please check your mail." });  
// // }
// console.log('4')

//         await sendEmail(mailOptions);
       

//         return res.status(200).json({ message: 'Password reset email sent successfully' });
//     } catch (error) {
//         return res.status(500).json({ message: error.message }); 
//     }
// };



const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await schoolModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User with this email does not exist' });
        }

        // Check if a reset token is already issued
        // if (user.resetToken) {
        //     return res.status(200).json({ message: 'Password reset email already sent, please check your mail.' });
        // }

        // Generate a token
        const token = jwt.sign({ userId: user._id, email: user.email }, process.env.SECRET_KEY, { expiresIn: '1h' });

        // Update user document with reset token
        user.resetToken = token;
        await user.save();

        // Send password reset email
        const resetLink = `https://support.monday.com/hc/en-us/articles/115005324505-Help-I-forgot-my-password/${token}`;
        const emailSubject = 'Password Reset';
        const html = generateForgotPasswordEmail(user.name,resetLink);

        const mailOptions = { 
            from: process.env.EMAIL_SENDER,
            to: email,
            subject: emailSubject,
            html: html,
        };

        // Send the email
        await sendEmail(mailOptions);

        return res.status(200).json({ message: 'Password reset email sent successfully, please check your mail.' });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};



// RESET PASSWORD




const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { "new password": newPassword, "confirm new password": confirmNewPassword } = req.body;

        // Verify the token
        const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
        const userId = decodedToken.userId;

        // Find the user by ID
        const user = await schoolModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the new password and confirm new password match
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: 'New password does not match confirm new password' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hashSync(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        // Send password reset email
        const resetLink = `https://www.pcmag.com/how-to/how-to-reset-a-forgotten-windows-10-password${token}`;
        const emailSubject = 'Password Reset';
        const html = generateForgotPasswordEmail(user.name, resetLink);

        const mailOptions = {
            from: process.env.EMAIL_SENDER,
            to: user.email,
            subject: emailSubject,
            html: html,
        };

        // Send the email
        await sendEmail(mailOptions);

        return res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};
module.exports= {
    changePassword,forgotPassword,resetPassword
}