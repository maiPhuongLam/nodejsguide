const Product = require('../models/product');
const { validationResult } = require('express-validator');
const fileHelper = require('../util/file');

exports.getAddProduct = (req, res, next) => {
    res.render('admin/edit-product', {
        pageTitle: 'Add Product',
        path: '/admin/add-product',
        editing: false,
        hasError: false,
        errorMessage: null,
        validatorErrors: [],
    });
}

exports.postAddProduct = (req, res, next) => {
    const { title, price, description } = req.body;
    const image = req.file;
    console.log(image);
    if (!image) {
        return res.status(422).render('admin/edit-product', {
            pageTitle: 'Add Product',
            path: '/admin/add-product',
            editing: false,
            product: { title, price, description },
            hasError: true,
            errorMessage: 'Attached file is not image',
            validatorErrors: [],
        });
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).render('admin/edit-product', {
            pageTitle: 'Add Product',
            path: '/admin/add-product',
            editing: false,
            product: { title, imageUrl, price, description },
            hasError: true,
            errorMessage: errors.array()[0].msg,
            validatorErrors: errors.array(),
        });
    }
    const imageUrl = image.path;
    const product = new Product({
        title,
        price,
        description,
        imageUrl,
        userId: req.user,
    });
    product.save()
        .then(result => {
            // console.log(result);
            console.log('Created Product');
            res.redirect('/admin/products');
        })
        .catch(err => {
            // console.log(err);
            // return res.status(500).render('admin/edit-product', {
            //     pageTitle: 'Add Product',
            //     path: '/admin/add-product',
            //     editing: false,
            //     product: { title, imageUrl, price, description },
            //     hasError: true,
            //     errorMessage: 'Db operation failed, please try again!',
            //     validatorErrors: [],
            // });
            // res.redirect('/500');
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.getEditProduct = (req, res, next) => {
    const editMode = req.query.edit;
    if (!editMode) {
        return res.redirect('/');
    }
    const prodId = req.params.productId;
    Product.findById(prodId)
        .then(product => {
            if (!product) {
                return res.redirect('/');
            }
            res.render('admin/edit-product', {
                pageTitle: 'Edit Product',
                path: '/admin/edit-product',
                editing: editMode,
                product: product,
                hasError: false,
                errorMessage: null,
                validatorErrors: [],
            });
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.postEditProduct = (req, res, next) => {
    const prodId = req.body.productId;
    const updatedTitle = req.body.title;
    const updatedPrice = req.body.price;
    const image = req.file;
    const updatedDesc = req.body.description;

    const errors = validationResult(req);
    console.log(errors.array());
    if (!errors.isEmpty()) {
        return res.status(422).render('admin/edit-product', {
            pageTitle: 'Edit Product',
            path: '/admin/edit-product',
            editing: true,
            product: { 
                title: updatedTitle,
                price: updatedPrice, 
                description: updatedDesc,
                _id: prodId
            },
            hasError: true,
            errorMessage: errors.array()[0].msg,
            validatorErrors: errors.array(),
        });
    }

    Product.findById(prodId)
        .then(product => {
            if (product.userId.toString() !== req.user._id.toString()) {
                return res.redirect('/');
            }
            product.title = updatedTitle;
            product.price = updatedPrice;
            product.description = updatedDesc;
            if (image) {
                fileHelper.deleteFile(product.imageUrl)
                product.imageUrl = image.path;
            }
            return product.save();
        })
        .then(result => {
            console.log('UPDATED PRODUCT!');
            res.redirect('/admin/products');
        })
        .catch((err) => console.log(err));
}

exports.getProducts = (req, res, next) => {
    Product.find({userId: req.user._id})
        // .select('title price -_id')
        // .populate('userId', 'name')
        .then((products) => {
            console.log(products);
            res.render('admin/products', {
                prods: products,
                pageTitle: 'Admin Products',
                path: '/admin/products',
            });
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.deleteProduct = (req, res, next) => {
    const prodId = req.params.productId;
    Product.findById(prodId)
        .then(product => {
            if (!product) {
                return next(new Error('Product not found'));
            }
            fileHelper.deleteFile(product.imageUrl);
            return Product.deleteOne({_id: prodId, userId: req.user._id})
        })
        .then(() => {
            console.log('DESTROYED PRODUCT');
            res.status(200).json({mess: 'Succcess'});
        })
        .catch(err => {
            res.status(500).json({mess: 'Fail'});
        });
}
