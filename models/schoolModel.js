const mongoose = require('mongoose')

const schoolSchema = new mongoose.Schema({
    name:{type:String, required:true},
    phoneNumber:{type:String, required:true},
    email:{type:String, required:true},
    password:{type:String, required:true},
    studentClass:{type:String, required:true},
    score:{type:Number, default:0},
    isVerified:{type:Boolean, default:false},
    isLoggedIn:{type:Boolean, default:false},
    resetToken:{type:String, default:null}
    
},{timestamps:true}
)

const schoolModel = mongoose.model('Auth', schoolSchema)
module.exports = schoolModel 