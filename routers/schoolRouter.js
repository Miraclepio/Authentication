const express = require('express')
const router = express.Router()
    const {signUpUser,verifyUser, resendVerification,login} = require('../controllers/schoolController')
 const {changePassword,forgotPassword,resetPassword} = require('../controllers/password')
 const {validateEmailAndPassword,validateEmail,validatePassword}=require('../middleware/validateSchoolModel')
router.route("/registerUser").post(signUpUser)
router.route("/verifyUser/:token").post(verifyUser)
router.route("/resendVerification").post(validateEmail,resendVerification)
router.route("/login").post(validateEmailAndPassword,login)
router.route("/changepassword/:token").post(changePassword)
router.route("/forgotPassword/:token").post(validateEmail,forgotPassword)
router.route("/resetPassword/:token").post(resetPassword) 

module.exports = router  