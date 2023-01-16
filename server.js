const fs = require("fs");
const path = require("path");
const https = require("https");

const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
// from the google OAuth Passport module
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");
const { verify } = require("crypto");

require("dotenv").config();

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

// callbackURL is the endpoint where google will send the accessToken in exchange for the authorization code & client secret
// clientID is the credential created on google cloud console for OAuth implementation
// clientSecret is attached together with the authorization code which is sent to
//              Google OAuth endpoint that then generates a token to act as authentication
//              for our backend server.
const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

// the verifyCallback will accept these 4 parameters
// as arguments once the OAuth flow is completed.
// what the 'verify function' does at the core is if the credentials
// passed/valid (accessToken & refreshToken), we call 'done'
// NOTE: SINCE WE ARE USING GOOGLE OAUTH, the accessToken & refreshToken
//       are already provided by google for us. BUT IF WE WERE CHECKING
//       PASSWORDS OURSELVES, THE USER'S PASSWORD IS WHAT WOULD COME INTO
//       THIS verify callback AND THIS verifyCallback function IS WHERE WE
//       COULD COMPARE THE USER'S PASSWORD AGAINST SOME VALUE IN OUR DATABASE
//       AND DECIDE WHETHER THE CREDENTIALS THAT ARE BEING PASSED IN ARE VALID OR NOT.
// ALSO: WE CAN USE THIS verify function TO SAVE THE USER (profile) THAT'S COME
//       BACK AS WELL AS ANY OF THEIR PROFILE INFORMATION INTO OUR DATABASE.
// BUT SINCE GOOGLE OAUTH HAS ALREADY DONE MOST OF THE WORK FOR US, ALL
// WE HAVE TO DO IS TO CALL 'done'.
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google profile", profile);

  // if something is invalid, we pass in the error as the first arg.But for now we can pass in 'null' as
  // the first option.
  // if user is successfully authenticated, we pass in
  // the user data which is the profile
  done(null, profile);
}

// passport strategy from the module
// first arg: options object
// second arg: verify function
// verify function -> When authenticating a request, a strategy parses the credential contained in the request. A verify function is then called, which is responsible for determining the user to which that credential belongs to. This allows data access to be delegated to the application.
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// To maintain a login session, Passport serializes and deserializes user information to and from the session. The information that is stored is determined by the application, which supplies a serializeUser and a deserializeUser function.

// Save the session to the cookie
// This is the same data we will be retrieving using our secret keys in passport.deserializeUser()
passport.serializeUser((user, done) => {
  // we will use just the id in our session to minimize the size of data that we are
  // sending back and forth and because for the purposes of our example, we don't need
  // any specific data about the user. We're just happy about the fact that they logged in successfully.
  done(null, user.id);
});

// Read the session from the cookie
// If we need additional data from our server, deserializeUser is where
// we do database lookups
passport.deserializeUser((id, done) => {
  // User.findById(id).then((user) => {
  //   done(null, user);
  // }); // req.user object is going to contain all the data in our database about the user.
  done(null, id);
});

const app = express();

// call helmet at the top before any of our routes so that every request passes through the helmet
// middleware regardless of where we respond to it.
// secures all of our endpoints by protecting against common configuration issues
app.use(helmet());

// call the cookie session before the passport middleware
// and after helmet sets up our security headers
app.use(
  cookieSession({
    // name of our session/cookie
    name: "session",
    // how long our session will last in milliseconds
    maxAge: 24 * 60 * 60 * 1000,
    // list of secret values that is used to keep your cookies secure
    // specifically by signing your cookie so that only the server
    // can decide what the session contains. the server will sign cookies it sends
    // to the browser with this secret key and it will in turn verify incoming cookies
    // to make sure that they were created with that secret key. This prevents the user
    // from tampering with their user session, modifying it and saying they are actually logged in
    // as another user.
    // IT IS ALWAYS A GOOD IDEA TO HAVE AT LEAST 2 KEYS BEING USED TO SIGN YOUR COOKIE SESSION
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2], // changing this secret value will invalidate all existing sessions
    // if we wanted to rotate/change our secret key as a precaution and we still wanted our existing logins
    // to work for users, we could add a secret key (the one that we are rotating in), and all new sessions would be signed with
    // the new key but our middleware would still accept keys signed with the original secret key.
  })
);

// call the passport middleware
// initialize is a function that returns
// the passport middleware that helps us set up passport
// By default, when authentication succeeds, the req.user property is set to the authenticated user, a login session is established, and the next function in the stack is called.
// serializeUser/deserializeUser
app.use(passport.initialize());

// initialize passport.session() so that passport understands our cookie session and the req.user object
// that's set by the cookie-session middleware.
app.use(passport.session()); // it authenticates the session that's being sent to our server. it uses the keys from
// cookie-session app.use() and validates that everything is signed as it should be and it
// sets the value user property on our request object to contain the user's identity. That is,
// the passport.session middleware will allow the deserializeUser() function to be called which
// in turn sets req.user which we can use in any of our express middleware.

// passport: req.user
// passport.session() middleware is setting req.user property inside of our express req object
function checkLoggedIn(req, res, next) {
  console.log(`Current user is: ${req.user}`); // this should log that the user is the passport.deserializeUser() that
  // has been read from the cookie. In our case, the cookie is being populated just by the user ID from our google profile
  const isLoggedIn = req.isAuthenticated() && req.user; // Allow access if req.user exists and req.isAuthenticated() returns true
  // req.isAuthenticated() is a built into passport and checks specifically that passport found the user in the session.
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "You must log in!",
    });
  }
  next();
}

app.use(express.static("public"));

// we will also use the passport middleware for
// the 'signin with google' url on our frontend
app.get(
  "/auth/google",
  passport.authenticate("google", {
    // scope specifies which data we're requesting from google
    // when everything succeeds.
    scope: ["email", "profile"],
  }),
  (req, res) => {
    console.log(req);
    console.log(res);
  }
);

// we will use passport's authenticate function as a middleware.

// we pass in 'google' as the FIRST parameter so that passport
// knows that we are using 'google' Strategy to login.

// second parameter is the action we commit (options object) when we fail
// to authenticate and when we authenticate successfully.
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    // specifies which path in our application we want the user to be redirected to
    // when something goes wrong when they're logging in.
    failureRedirect: "/failure",
    // specifies where we want to redirect the user if they logged in successfully.
    successRedirect: "/",
    session: true, // setting session to true or remove it (since it is true by default) will enable passport serialization and deserialization
  }),
  (req, res) => {
    // here we can optionally choose to do something
    // additional when google calls us back
    console.log("Google called us back!");
    console.log(req);
    console.log(res);
  }
);

// passport exposes a logout function on the request object.
// this can be called on any route by just calling req.logout()
app.get("/auth/logout", (req, res) => {
  req.logout(); // will clear any logged in user session and it will remove
  // the req.user property.
  // session still exists but the decoded object is empty
  return res.redirect("/");
});

// pass in a middleware for this specific endpoint only
app.get("/secret", checkLoggedIn, (req, res) => {
  res.set("Content-Type", "text/html");
  const htmlContent = `
  <body>
    <main>
      <div>
        <p>Your personal secret value is <strong>42!</strong></p>
      </div>
    </main>
  </body>
  <style>
  @import url('https://fonts.googleapis.com/css2?family=Montserrat:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap');
  
  body {
    padding: 0;
    margin: 0;
    overflow-x:hidden;
  }

  main {
    font-family: 'Montserrat', sans-serif;
    display: flex; 
    height: 100%; 
    max-width: 100%; 
    justify-content:center; 
    align-items:center;
    background-color: #f3f4f6;
  }

  div {
    box-sizing: border-box;
    padding: 2rem 3rem;
    border-radius: 1rem;
    box-shadow: 0px 0px 15px 0px rgba(0,0,0,0.15);
    background-color: #fff;
  }

  p {
    font-size: 1.1rem;
    text-transform: capitalize;
    line-height: 1.5rem;
    font-weight: 400;
    color: #202020;
  }
  </style>`;
  return res.send(Buffer.from(htmlContent));
});

app.get("/failure", (req, res) => {
  return res.send("Failed to log in!");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    // firs arg: certificates
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    // second arg: express server
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
  });
