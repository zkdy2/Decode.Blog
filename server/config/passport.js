

require("dotenv").config(); // Загружаем переменные окружения один раз

const passport = require("passport");
const User = require("../auth/User");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github").Strategy;

// Проверяем, загружены ли переменные окружения
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  console.error("Ошибка: GOOGLE_CLIENT_ID или GOOGLE_CLIENT_SECRET не установлены!");
  process.exit(1);
}

if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) {
  console.error("Ошибка: GITHUB_CLIENT_ID или GITHUB_CLIENT_SECRET не установлены!");
  process.exit(1);
}

// Локальная стратегия
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: "Incorrect email" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) return done(null, user);
        return done(null, false, { message: "Incorrect password" });
      } catch (error) {
        return done(error);
      }
    }
  )
);



passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:8000/api/auth/google",
      scope: ["profile", "email"], // Указываем необходимые разрешения
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = new User({
            googleId: profile.id,
            full_name: profile.displayName,
            email: profile.emails?.[0]?.value || "no-email@example.com", // Защита от отсутствия email
            description: "Пока ничего о себе не писал...",
          });
          await user.save();
        }
        return cb(null, user);
      } catch (error) {
        return cb(error);
      }
    }
  )
);


passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "http://localhost:8000/api/auth/github/callback", // Обязательно с /callback в конце
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });

        if (!user) {
          user = new User({
            githubId: profile.id,
            full_name: profile.displayName || profile.username,
            email: profile.emails?.[0]?.value || "no-email@example.com",
            description: "Пока ничего о себе не писал...",
          });
          await user.save();
        }

        done(null, user);
      } catch (err) {
        done(err);
      }
    }
  )
);

// Сериализация пользователя
passport.serializeUser((user, done) => {
  done(null, user._id);
});

// Десериализация пользователя
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;


