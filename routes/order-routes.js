const express = require("express");
const { protect, restrictTo } = require("../controllers/auth-contoller");
const { getOrder, getAllOrder, checkout } = require("../controllers/order-controllers");
const router = express.Router();

router.get("/:id",  protect ,getOrder);
router.get("/",protect , restrictTo("admin"), getAllOrder);
router.post("/checkOut",protect,checkout)

module.exports = router;
