const Order = require("../models/Order");
const CatchAsync = require("../utils/catch-async");
const QueryMethod = require("../utils/query");
const express = require("express");
const Cart = require("../models/Cart");
const Flutterwave = require("flutterwave-node-v3");
fs = require("fs");
const nodemailer = require("nodemailer");
const { FLW_PUBLIC_KEY, FLW_SECRET_KEY, FLW_ENCRPYTION_KEY } = process.env;

exports.getOrder = CatchAsync(async (req, res, next) => {
  const order = await Order.findById(req.params.id);
  if (req.user.id !== order.userId.toString()) {
    return next(new ErrorObject(`You are not authorized!!!!!!!`, 403));
  }

  res.status(200).json({
    status: "success",
    data: order,
  });
});

exports.getAllOrder = CatchAsync(async (req, res, next) => {
  let queriedOrders = new QueryMethod(Order.find(), req.query)
    .sort()
    .filter()
    .limit()
    .paginate();
  let orders = await queriedOrders.query;
  res.status(200).json({
    status: "success",
    results: orders.length,
    data: {
      orders,
    },
  });
});

exports.checkout = CatchAsync(async (req, res, next) => {
  const flw = new Flutterwave(FLW_PUBLIC_KEY, FLW_SECRET_KEY);
  const userID = req.user._id;
  const user = req.user;
  const order = await Order.findOne({ userID });

  if (order) {
    let payload = {
      card_number: req.body.card_number,
      cvv: req.body.cvv,
      expiry_month: req.body.expiry_month,
      expiry_year: req.body.expiry_year,
      currency: "NGN",
      amount: order.totalAmount,
      fullname: `${user.lastName} ${user.firstName}`,
      email: user.email,
      enckey: FLW_ENCRPYTION_KEY,
      tx_ref: `${user.lastName}-${Date.now()}-${order.totalAmount}`,
    };

    const response = await flw.Charge.card(payload);
    // Authorizing transactions
    // For PIN transactions
    if (response.meta.authorization.mode === "pin") {
      let payload2 = payload;
      payload2.authorization = {
        mode: "pin",
        fields: ["pin"],
        pin: 3310,
      };
      const reCallCharge = await flw.Charge.card(payload2);

      // Add the OTP to authorize the transaction
      const callValidate = await flw.Charge.validate({
        otp: "12345",
        flw_ref: reCallCharge.data.flw_ref,
      });
      if (callValidate.status === "success") {
        res.status(200).json({
          status: "succesfull",
          message: " your payment is successful",
          order,
        });

        await Cart.findOneAndDelete(order.cartId);
      }
    }
    return response;
  } else {
    return res.status(400).json({
      message: "No Order is found",
    });
  }
});
