const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const flash = require("connect-flash");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
require("dotenv").config();
const User = require("./models/user");
const saltRounds = 10;

// middlewares
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cookieParser(process.env.SECRET));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(bodyParser.urlencoded({ extended: true }));

function requireLogin(req, res, next) {
  if (!req.session.isVerified) {
    res.redirect("login");
  } else {
    next();
  }
}

// database connection
mongoose
  .connect("mongodb://localhost:27017/test", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to mongodb......");
  })
  .catch((e) => {
    console.log(e);
  });

// routes
app.get("/", (req, res) => {
  res.send("<h1>Home</h1>");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res, next) => {
  let { username, password } = req.body;

  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      res.send("Username has been taken......");
    } else {
      // encrypt and save the password
      bcrypt.genSalt(saltRounds, (err, salt) => {
        if (err) {
          next(err);
        }
        bcrypt.hash(password, salt, (err, hash) => {
          if (err) {
            next(err);
          }
          let newUser = new User({ username, password: hash });
          try {
            newUser
              .save()
              .then(() => {
                res.send("Data has been saved......");
              })
              .catch((e) => {
                // validator error handler
                res.send("Error!");
              });
          } catch (err) {
            // asynchronous function error handler
            next(err);
          }
        });
      });
    }
  } catch (err) {
    // asynchronous function error handler
    next(err);
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      bcrypt.compare(password, foundUser.password, (err, result) => {
        if (err) {
          next(err);
        }
        if (result == true) {
          req.session.isVerified = true;
          res.redirect("secret");
        } else {
          res.send("Username or password not corrct......");
        }
      });
    } else {
      res.send("Username or password not corrct......");
    }
  } catch (err) {
    // asynchronous function error handler
    next(err);
  }
});

app.get("/secret", requireLogin, (req, res) => {
  res.render("secret");
});

app.get("/*", (req, res) => {
  res.status(404).send("<h1>404 Page Not Found......</h1>");
});

// general error handler
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).send("Something is broken......");
});

app.listen(3000, () => {
  console.log("Server running on port 3000......");
});
