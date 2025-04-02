const passport = require("passport");
const User = require("../auth/User");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github").Strategy;

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
    },
    function (email, password, done) {
      User.findOne({ email })
        .then((user) => {
          if (!user) {
            return done(null, false, { message: "Incorrect email" });
          }
          bcrypt.compare(password, user.password, function (err, result) {
            if (err) {
              return done(err);
            }
            if (result) {
              return done(null, user);
            } else {
              return done(null, false, { message: "Incorrect password" });
            }
          });
        })
        .catch((e) => {
          return done(e);
        });
    }
  )
);

require("dotenv").config(); 

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:8000/api/auth/google",
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const foundUser = await User.findOne({ googleId: profile.id });
        if (foundUser) {
          return cb(null, foundUser);
        } else {
          const newUser = new User({
            googleId: profile.id,
            full_name: profile.displayName,
            email: profile.emails[0].value,
            description: "Пока ничего о себе не писал...",
          });
          await newUser.save();
          return cb(null, newUser);
        }
      } catch (error) {
        return cb(error);
      }
    }
  )
);

require("dotenv").config(); 

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID, 
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "http://localhost:8000/api/auth/github",
      scope: ["user", "email"],
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const foundUser = await User.findOne({ githubId: profile.id });
        if (foundUser) {
          return cb(null, foundUser);
        } else {
          const newUser = new User({
            githubId: profile.id,
            full_name: profile.displayName,
            email: profile.email,
            description: "Пока ничего о себе не писал...",
          });
          await newUser.save();
          return cb(null, newUser);
        }
      } catch (error) {
        return cb(error);
      }
    }
  )
);


passport.serializeUser(function (user, done) {
  done(null, user._id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id).then((user, err) => {
    done(err, user);
  });
});


