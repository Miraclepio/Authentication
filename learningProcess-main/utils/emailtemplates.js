function generateWelcomeEmail(name, verificationLink, isResend = false) {
    const emailSubject = isResend ? 'Resend Verification Mail' : 'Welcome to THE CURVE AFRICA!';
    const emailBody = isResend ? 
        `<p>Please click the button below to verify your account:</p>` :
        `<p>Thank you for signing up for THE CURVE AFRICA. We are excited to have you on board.</p>
        <p>Please click the button below to verify your account:</p>`;
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>${emailSubject}</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #2c2c2c; /* Dark background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto; /* Add some top margin */
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f4f4f4; /* Light grey background */
            }
            .header {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
            }
            .button {
                display: inline-block;
                background-color: #000000;
                color: #ffffff;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>${emailSubject}</h1>
            </div>
            <div class="content">
                <p>Hello ${name},</p>
                ${emailBody}
                <p>
                    <a href="${verificationLink}" class="button">Verify your Account</a>
                </p>
                <p>If you did not create an account, please ignore this email.</p>
                <p>Best regards,<br>The CURVE Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} THE CURVE AFRICA. All rights reserved.</p>
                <p>Your Company Address</p>
            </div>
        </div>
    </body>
    </html>
    `;
}
// change password

function generateChangePasswordEmail(name, resetLink) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Change Password Request</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #2c2c2c; /* Dark background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto; /* Add some top margin */
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f4f4f4; /* Light grey background */
            }
            .header {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
            }
            .button {
                display: inline-block;
                background-color: #000000;
                color: #ffffff;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Change Password Request</h1>
            </div>
            <div class="content">
                <p>Hello ${name},</p>
                <p>We received a request to reset your password. Please click the button below to change your password:</p>
                <p>
                    <a href="${resetLink}" class="button">Change Password</a>
                </p>
                <p>If you did not request a password reset, please ignore this email or contact support if you have questions.</p>
                <p>Best regards,<br>The CURVE Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} THE CURVE AFRICA. All rights reserved.</p>
                <p>Your Company Address</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

// forgot password


function generateForgotPasswordEmail(name, resetLink) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Forgot Password Request</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #f4f4f4; /* Light grey background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto; /* Add some top margin */
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #ffffff; /* White background */
            }
            .header {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
            }
            .button {
                display: inline-block;
                background-color: #000000;
                color: #ffffff;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Forgot Password Request</h1>
            </div>
            <div class="content">
                <p>Hello ${name},</p>
                <p>We received a request to reset your password.</p>
                <p>If you initiated this request, please click the button below to reset your password:</p>
                <p>
                    <a href="${resetLink}" class="button">Reset Password</a>
                </p>
                <p>If you did not initiate this request, please ignore this email or contact support if you have questions.</p>
                <p>Best regards,<br>The CURVE Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} THE CURVE AFRICA. All rights reserved.</p>
                <p>Your Company Address</p>
            </div>
        </div>
    </body>
    </html>
    `;
}


// reset password

function generateResetPasswordEmail(name, resetLink) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Reset Your Password</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #f4f4f4; /* Light grey background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto; /* Add some top margin */
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #ffffff; /* White background */
            }
            .header {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
            }
            .button {
                display: inline-block;
                background-color: #000000;
                color: #ffffff;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Reset Your Password</h1>
            </div>
            <div class="content">
                <p>Hello ${name},</p>
                <p>We received a request to reset your password.</p>
                <p>If you initiated this request, please click the button below to reset your password:</p>
                <p>
                    <a href="${resetLink}" class="button">Reset Password</a>
                </p>
                <p>If you did not initiate this request, please ignore this email or contact support if you have questions.</p>
                <p>Best regards,<br>The CURVE Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} THE CURVE AFRICA. All rights reserved.</p>
                <p>Your Company Address</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

module.exports = { generateWelcomeEmail, generateChangePasswordEmail, generateForgotPasswordEmail, generateResetPasswordEmail };




