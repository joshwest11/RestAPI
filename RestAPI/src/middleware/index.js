const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../user/model");

exports.hashPass = async (req, res, next) => {
  try {
    if (req.body.pass || (req.body.updateObj && req.body.updateObj.pass)) {
      if (req.body.pass) {
        req.body.pass = await bcrypt.hash(req.body.pass, 8);
      } else {
        req.body.updateObj.pass = await bcrypt.hash(req.body.updateObj.pass, 8);
      }
      next();
    } else if (req.body.updateObj) {
      next();
    } else {
      throw new Error("Incorrect information sent");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};

exports.decryptPass = async (req, res, next) => {
  try {
    req.user = await User.findOne({ username: req.body.username });
    if (req.user && (await bcrypt.compare(req.body.pass, req.user.pass))) {
      next();
    } else {
      throw new Error("Incorrect credentials");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};

exports.tokenCheck = async (req, res, next) => {
  try {
    const decodedToken = await jwt.verify(
      req.header("Authorization").replace("Bearer ", ""),
      process.env.SECRET
    );
    req.user = await User.findOne({ _id: decodedToken._id });
    if (req.user) {
      next();
    } else {
      throw new Error("Invalid token");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};