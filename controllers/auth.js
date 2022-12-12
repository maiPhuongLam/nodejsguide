const User = require('../models/user');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { validationResult, param } = require('express-validator');
const dotenv = require('dotenv')
dotenv.config();

exports.getLogin = (req, res, next) => {
    let message = req.flash('error');
    if (message.length) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: message,
        oldInput: {
            email: '',
            password: '',
        },
        validatorErrors: [],
    });
}

exports.postLogin = (req, res, next) => {
    const { email, password } = req.body;
    const errors = validationResult(req);
    console.log(errors.array());
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: { email, password },
            validatorErrors: errors.array(),
        });
    }
    User.findOne({ email })
        .then(user => {
            if (!user) {
                return res.status(422).render('auth/login', {
                    path: '/login',
                    pageTitle: 'Login',
                    errorMessage: 'Email is not registered',
                    oldInput: { email, password },
                    validatorErrors: [],
                });
            }
            bcrypt.compare(password, user.password)
                .then(doMatch => {
                    if (doMatch) {
                        req.session.isLoggedIn = true;
                        req.session.user = user;
                        return req.session.save(err => {
                            console.log(err);
                            res.redirect('/');
                        }); 
                    }   
                    return res.status(422).render('auth/login', {
                        path: '/login',
                        pageTitle: 'Login',
                        errorMessage: 'Password is incorrect',
                        oldInput: { email, password },
                        validatorErrors: [],
                    });
                })
                .catch(err => {
                    console.log(err);
                    res.redirect('/login');
                });
            
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err);
        res.redirect('/');
    });
}

exports.getSignup = (req, res, next) => {
    let message = req.flash('error');
    if (message.length) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        errorMessage: message,
        oldInput: {
            email: '',
            password: '',
            confirmPassword: '',
        },
        validatorErrors: [],
    });
}

exports.postSignup = (req, res, next) => {
    const { email, password, confirmPassword } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors.array());
        return res.status(422).render('auth/signup', {
            path: '/signup',
            pageTitle: 'Signup',
            errorMessage: errors.array()[0].msg,
            oldInput: { email, password, confirmPassword },
            validatorErrors: errors.array(),
        });
    }
    bcrypt.hash(password, 12)
        .then(hashedPassword => {
            const user = new User({ 
                email, 
                password: hashedPassword,
                cart: { items: [] }
            });
            return user.save();
        })
        .then(result => {
            res.redirect('/login');
            // SEND EMAIL START   
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'maiphuonglambh.2002@gmail.com',
                    pass: process.env.PASS_EMAIL_GOOGLE,
                }
            });
            const mailOptions = {
                from: 'test.2002@gmail.com',
                to: email,
                subject: 'Invoices due',
                text: 'Dudes, we really need your money.',
                html: '<h1 style="color: blue">Signup success</h1>'
            };
            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.log(err);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
            // SEND EMAIL END
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.getReset = (req, res, next) => {
    let message = req.flash('error');
    if (message.length) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/reset', {
        path: '/reset', 
        pageTitle: 'Reset Password',
        errorMessage: message,
    });
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            console.log(err);
            return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User.findOne({ email: req.body.email })
            .then(user => {
                if (!user) {
                    req.flash('err', 'No account with that email found');
                    return res.redirect('/reset');
                }
                user.resetToken = token;
                user.resetTokenExpiration = Date.now() + 3600000;
                return user.save()
            })
            .then(result => {
                if(result) {
                    res.redirect('/login');
                    // SEND EMAIL START
                    const transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: 'maiphuonglambh.2002@gmail.com',
                            pass: 'qqjbsgbmgerxpacj'
                        }
                    });
                    const mailOptions = {
                        from: 'test.2002@gmail.com',
                        to: req.body.email,
                        subject: 'Password reset',
                        html: `
                            <p>You requested a password reset</p>
                            <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
                        `
                    };
                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.log(error);
                        } else {
                            console.log('Email sent: ' + info.response);
                        }
                    });
                    // END SEND EMAIL
                }
            })
            .catch(err => {
                const error = new Error(err);
                error.httpStatusCode = 500;
                return next(error);
            });
    });
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;
    User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
        .then(user => {
            let message = req.flash('error');
            if (message.length) {
                message = message[0];
            } else {
                message = null;
            }
            res.render('auth/new-password', {
                path: '/new-password',
                pageTitle: 'New Password',
                errorMessage: message,
                userId: user._id.toString(),
                passwordToken: token,
            });
        })

}

exports.postNewPassword = (req, res, next) => {
    const { newPassword, confirmNewPassword, userId, passwordToken } = req.body;
    let resetUser;
    if (newPassword !== confirmNewPassword) {
        req.flash('error', 'Password validate fail');
        return res.redirect('/new-password');
    }

    User.findOne({ resetToken: passwordToken, resetTokenExpiration: { $gt: Date.now() }, _id: userId })
        .then(user => {
            resetUser = user;
            return bcrypt.hash(newPassword, 12)
        })
        .then(hashPassword => {
            resetUser.password = hashPassword;
            resetUser.resetToken = undefined;
            resetUser.resetTokenExpiration = undefined;
            return resetUser.save();
        })
        .then(result => {
            res.redirect('/login')
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}
