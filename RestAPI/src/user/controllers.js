const jwt = require("jsonwebtoken");
const User = require("./model");

exports.addUser = async (req, res) => {
  try {
    const user = await User.create(req.body);
    const token = await jwt.sign({ _id: user._id }, process.env.SECRET);
    res.status(200).send({ user: user.username, token });
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const token = await jwt.sign({ _id: req.user._id }, process.env.SECRET);
    res.status(200).send({ user: req.user.username, token });
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const updateCheck = await User.updateOne(
      { _id: req.user._id },
      req.body.updateObj
    );
    if (updateCheck.modifiedCount > 0) {
      res.status(200).send({ msg: "Success" });
    } else {
      throw new Error("Nothing updated");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    let deleteCheck;
    if (req.user.username === req.params.username) {
      deleteCheck = await User.deleteOne({ _id: req.user._id });
    } else {
      throw new Error("Incorrect Credentials");
    }
    if (deleteCheck && deleteCheck.deletedCount > 0) {
      res.status(200).send({ msg: "Success" });
    } else {
      throw new Error("Nothing deleted");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({ err: error.message });
  }
};