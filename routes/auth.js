const express = require('express');
const { check, body } = require('express-validator');
const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.post(
    '/login',
    [
        body('email')
        .isEmail()
        .withMessage('Please enter a valid email')
        .normalizeEmail()
        .custom((value, {req}) => {
            return User.findOne({email: value})
                .then(userDoc => {
                    if (!userDoc) {
                        return Promise.reject(
                            'Email is not registered'
                        );
                    }
                })
        }),
        body('password', 'Password is incorrect')
            .isLength({ min: 5 })
            .isAlphanumeric()
            .trim()
    ], 
    authController.postLogin
);

router.post('/logout', authController.postLogout);

router.get('/signup', authController.getSignup);

router.post(
    '/signup', 
    [
        check('email')
            .isEmail()
            .withMessage('Please enter a valid email')
            .normalizeEmail()
            .custom((value, {req}) => {
                // if (value === 'test@test.com') {
                    //     throw new Error('This email address is forbidden.');
                    // }
                    // return true;
                return User.findOne({ email: value })
                    .then(userDoc => {
                        if (userDoc) {
                            return Promise.reject(
                                'Email exist already, please pick a different one'
                            );
                        }
                });
            }),
        body('password', 'Please enter password with only numbers and text at least 5 character')
            .isLength({ min: 5 })
            .isAlphanumeric()
            .trim(),
        body('confirmPassword')
            .trim()
            .custom((value, {req}) => {
                if (value !== req.body.password) {
                    throw new Error('Password have to match');
                }
                return true; 
            }),
    ],
    authController.postSignup
);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;
