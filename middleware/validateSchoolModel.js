const Joi = require('@hapi/joi');


// email and password schema validation
const schema = Joi.object({

   
    email: Joi.string().trim().email().required().messages({
        "any.required": "Please provide an email.",
        "string.empty": "Email cannot be left empty.",
        "string.email": "Please provide a valid email address.",
    }),
  
    password: Joi.string().required().pattern(new RegExp("^(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$")).messages({
        "any.required": "Please provide a password.",
        "string.empty": "Password cannot be left empty.",
        "string.pattern.base": "Password must be at least 8 characters long and include at least one uppercase letter and one special character (!@#$%^&*).",
    }),
});



// password schema validation
const schemas = Joi.object({
password: Joi.string().required().pattern(new RegExp("^(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$")).messages({
        "any.required": "Please provide a password.",
        "string.empty": "Password cannot be left empty.",
        "string.pattern.base": "Password must be at least 8 characters long and include at least one uppercase letter and one special character (!@#$%^&*).",
    }),
});

   

const validatePassword = (req, res, next) => {
    const { error } = schemas.validate(req.body);

    if (error) {
        return res.status(400).json({ errors: error.details.map(detail => detail.message) });
    }

    next();
};

// validate email
const EmailSchema = Joi.object({
 
    email: Joi.string().trim().email().required().messages({
        "any.required": "Please provide an email.",
        "string.empty": "Email cannot be left empty.",
        "string.email": "Please provide a valid email address.",
    }),
  
    });
    
       
    
    const validateEmail = (req, res, next) => {
        const { error } = EmailSchema.validate(req.body);
    
        if (error) {
            return res.status(400).json({ errors: error.details.map(detail => detail.message) });
        }
    
        next();
    };



   

const validateEmailAndPassword = (req, res, next) => {
    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({ errors: error.details.map(detail => detail.message) });
    }

    next();
};

module.exports = { validateEmailAndPassword,validatePassword,validateEmail };
