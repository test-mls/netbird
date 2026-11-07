# notes-app

A small notes app of the kind an AI writes in an afternoon. It had its own
login. Now NetBird does the login, and the app reads who the user is from the
`X-NetBird-*` headers.

- Notes are attributed to `X-NetBird-User` (the email) and `X-NetBird-User-Id`.
- The delete button only shows for users with the `editor` role, and the
  delete route checks the role again on the server. Hiding a button is not
  security; the server check is.
- Forms refuse cross-site posts. The NetBird login is a cookie, so the usual
  CSRF rules still apply.

## Run it

```bash
npm install
npm start                                   # listens on 127.0.0.1:8003

# in another terminal, from examples/app-authz/
python3 dev/fake_proxy.py --upstream http://127.0.0.1:8003 --listen 127.0.0.1:9003 --preset viewer
# open http://127.0.0.1:9003 (no delete button), then restart with --preset admin
```

Set the service in NetBird to the `headers` forwarding mode, and make sure
only the NetBird proxy can reach port 8003.

## Before and after

This is the change that removed the hand-rolled login: four dependencies and
the users table gone, a few lines added.

```diff
-const session = require("express-session");
-const bcrypt = require("bcrypt");
-const passport = require("passport");
-const LocalStrategy = require("passport-local").Strategy;
-const db = require("./db");
-
-app.use(session({ secret: process.env.SESSION_SECRET || "changeme", resave: false, saveUninitialized: false }));
-app.use(passport.initialize());
-app.use(passport.session());
-
-passport.use(new LocalStrategy(async (email, password, done) => {
-  const user = await db.users.findByEmail(email);
-  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return done(null, false);
-  return done(null, user);
-}));
-passport.serializeUser((user, done) => done(null, user.id));
-passport.deserializeUser(async (id, done) => done(null, await db.users.findById(id)));
-
-app.get("/login", (req, res) => res.send(loginPage()));
-app.post("/login", passport.authenticate("local", { successRedirect: "/", failureRedirect: "/login" }));
-app.post("/logout", (req, res) => req.logout(() => res.redirect("/login")));
-app.get("/signup", (req, res) => res.send(signupPage()));
-app.post("/signup", async (req, res) => { /* hash, insert, email verification... */ });
-app.get("/forgot-password", (req, res) => res.send(forgotPage()));
-app.post("/forgot-password", async (req, res) => { /* tokens, emails... */ });
-
-function requireUser(req, res, next) {
-  if (!req.isAuthenticated()) return res.redirect("/login");
-  next();
-}
-
-function requireEditor(req, res, next) {
-  if (req.user.role !== "editor" && !req.user.isAdmin) return res.status(403).send("Forbidden");
-  next();
-}
+function requireUser(req, res, next) {
+  req.user = identity(req); // X-NetBird-User-Id, -User, -Groups, -Roles
+  if (!req.user) return res.status(401).send("Not signed in through NetBird.");
+  next();
+}
+
+const requireRole = (role) => (req, res, next) =>
+  req.user.roles.includes(role) ? next() : res.status(403).send(`You need the '${role}' role.`);
```

What went away: password hashing, the users table, sessions and the session
secret, signup, password reset, logout, and the "who is an admin" column in
the database. Who is an editor is now a NetBird group, mapped to the `editor`
role in the dashboard.

What stayed: the role check on the delete route, CSRF protection on forms,
and escaping user input in HTML.
