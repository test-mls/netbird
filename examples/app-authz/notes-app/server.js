// notes-app: a typical small CRUD app with the login code deleted.
// NetBird logs people in. The app reads who they are from X-NetBird-* headers
// and checks the "editor" role before anything destructive.
//
// Only safe when the NetBird proxy is the ONLY way to reach this app: bind to
// 127.0.0.1 or a private network. Anyone who can reach it directly can send
// these headers themselves.

const express = require("express");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8003);

const app = express();
app.use(express.urlencoded({ extended: false }));

// --- identity (this replaces passport, sessions, the users table and /login)

function csv(value) {
  return (value || "").split(",").map((s) => s.trim()).filter(Boolean);
}

function identity(req) {
  const userId = req.get("X-NetBird-User-Id");
  if (!userId) return null;
  return {
    userId,
    email: req.get("X-NetBird-User") || "",
    name: req.get("X-NetBird-User") || userId,
    groups: csv(req.get("X-NetBird-Groups")),
    roles: csv(req.get("X-NetBird-Roles")),
  };
}

function requireUser(req, res, next) {
  req.user = identity(req);
  if (!req.user) return res.status(401).send("Not signed in through NetBird.");
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user.roles.includes(role)) return res.status(403).send(`You need the '${role}' role.`);
    next();
  };
}

// The NetBird login is a cookie, so state-changing forms still need CSRF
// protection. Browsers send Sec-Fetch-Site; refuse anything not same-origin.
function sameOriginOnly(req, res, next) {
  const site = req.get("Sec-Fetch-Site");
  if (site && site !== "same-origin" && site !== "none") return res.status(403).send("Cross-site request refused.");
  next();
}

// --- the app

const notes = [];
let nextId = 1;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.use(requireUser);

app.get("/", (req, res) => {
  const canDelete = req.user.roles.includes("editor");
  const items = notes
    .map(
      (n) => `<li>${esc(n.text)} <small>by ${esc(n.author)}</small>
        ${canDelete ? `<form method="post" action="/notes/${n.id}/delete" style="display:inline"><button>Delete</button></form>` : ""}</li>`,
    )
    .join("");
  res.send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Notes</title><body style="font:15px system-ui;max-width:640px;margin:2rem auto;padding:0 16px">
<p>Signed in as <b>${esc(req.user.name)}</b> (roles: ${esc(req.user.roles.join(", ") || "none")})</p>
<form method="post" action="/notes"><input name="text" required placeholder="New note"> <button>Add</button></form>
<ul>${items || "<li>No notes yet.</li>"}</ul></body>`);
});

app.get("/api/notes", (_req, res) => res.json(notes));

app.post("/notes", sameOriginOnly, (req, res) => {
  const text = String(req.body.text || "").trim().slice(0, 500);
  if (!text) return res.status(400).send("Empty note.");
  notes.push({ id: nextId++, text, author: req.user.name, authorId: req.user.userId });
  res.redirect(303, "/");
});

// Hiding the button is UX. This check is the security.
app.post("/notes/:id/delete", sameOriginOnly, requireRole("editor"), (req, res) => {
  const i = notes.findIndex((n) => n.id === Number(req.params.id));
  if (i === -1) return res.status(404).send("No such note.");
  notes.splice(i, 1);
  res.redirect(303, "/");
});

app.listen(PORT, HOST, () => console.log(`notes-app on http://${HOST}:${PORT}`));
