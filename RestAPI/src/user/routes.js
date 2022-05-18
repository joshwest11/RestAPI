const { Router } = require("express");
const { addUser, login, updateUser, deleteUser } = require("./controllers");
const { hashPass, decryptPass, tokenCheck } = require("../middleware");
const userRouter = Router();

userRouter.post("/user", hashPass, addUser);
userRouter.post("/login", decryptPass, login);
userRouter.get("/user", tokenCheck, login);
userRouter.patch("/user", tokenCheck, hashPass, updateUser);
userRouter.delete("/user/:username", tokenCheck, deleteUser);

module.exports = userRouter;