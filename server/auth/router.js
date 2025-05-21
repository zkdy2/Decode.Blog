const express = require("express");
const passport = require("passport");
const router = express.Router();
const { signUp, signIn, signOut } = require("./controller");
const { deleteUser, editUser } = require("./profile");
const { isAuth } = require("./middlewares");
const GitHubStrategy = require("passport-github").Strategy;
const User = require("../auth/User"); // твоя модель пользователя



router.post("/api/signup", signUp);
router.post(
  "/api/signin",
  passport.authenticate("local", { failureRedirect: "/auth?error=1" }),
  signIn
);
router.get("/api/signout", signOut);
router.get("/api/auth/google", passport.authenticate("google"), (req, res) => {
  res.redirect("/myblogs/" + req.user._id);
});
router.get("/api/auth/github", passport.authenticate("github"));

router.get(
  "/api/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/myblogs/" + req.user._id);
  }
);


router.post("/api/user_edit", isAuth, editUser)
router.delete("/api/user_delete/:id", isAuth, deleteUser);

module.exports = router;
