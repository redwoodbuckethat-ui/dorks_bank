// ------------------------------
// DORKS BANK - with signup, hashing, and basic persistence
// ------------------------------

const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

// --------- DATA PERSISTENCE (users.json) ---------
const DATA_FILE = path.join(__dirname, "users.json");
let users = {}; // { username: { passwordHash, balance, history: [] } }

function loadUsers() {
  if (fs.existsSync(DATA_FILE)) {
    try {
      const raw = fs.readFileSync(DATA_FILE, "utf-8");
      users = JSON.parse(raw);
    } catch (err) {
      console.error("Error reading users.json, starting fresh:", err);
      users = {};
    }
  } else {
    users = {};
    saveUsers();
  }
}

function saveUsers() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error("Error writing users.json:", err);
  }
}

// Call this once at startup
loadUsers();

// --------- EXPRESS + SESSIONS ---------
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "dorks-bank-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// --------- AUTH MIDDLEWARE ---------
function requireLogin(req, res, next) {
  if (!req.session.username || !users[req.session.username]) {
    return res.redirect("/login");
  }
  next();
}

// --------- HTML HELPERS ---------
function layout(title, body) {
  return `
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="utf-8" />
      <title>Dorks Bank - ${title}</title>
    </head>
    <body>
      <h1>Dorks Bank</h1>
      ${body}
    </body>
  </html>
  `;
}

// --------- ROUTES ---------
app.get("/", (req, res) => {
  if (req.session.username && users[req.session.username]) {
    return res.redirect("/dashboard");
  }
  res.redirect("/login");
});

// --- SIGNUP ---
app.get("/signup", (req, res) => {
  const error = req.query.error ? `<p style="color:red;">${req.query.error}</p>` : "";
  res.send(
    layout(
      "Sign Up",
      `
      ${error}
      <h2>Create an account</h2>
      <form method="POST" action="/signup">
        <label>Username:
          <input name="username" required />
        </label>
        <br/><br/>
        <label>Password:
          <input type="password" name="password" required />
        </label>
        <br/><br/>
        <button type="submit">Sign up</button>
      </form>
      <p>Already have an account? <a href="/login">Log in</a></p>
      `
    )
  );
});

app.post("/signup", (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  if (!username || !password) {
    return res.redirect("/signup?error=" + encodeURIComponent("Username and password are required."));
  }
  if (users[username]) {
    return res.redirect("/signup?error=" + encodeURIComponent("That username is taken."));
  }
  if (password.length < 4) {
    return res.redirect("/signup?error=" + encodeURIComponent("Password must be at least 4 characters."));
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  users[username] = {
    passwordHash,
    balance: 1000, // starting balance
    history: [],
  };
  saveUsers();

  req.session.username = username;
  res.redirect("/dashboard");
});

// --- LOGIN ---
app.get("/login", (req, res) => {
  const error = req.query.error ? `<p style="color:red;">${req.query.error}</p>` : "";
  res.send(
    layout(
      "Login",
      `
      ${error}
      <h2>Log in</h2>
      <form method="POST" action="/login">
        <label>Username:
          <input name="username" required />
        </label>
        <br/><br/>
        <label>Password:
          <input type="password" name="password" required />
        </label>
        <br/><br/>
        <button type="submit">Log in</button>
      </form>
      <p>No account yet? <a href="/signup">Sign up</a></p>
      `
    )
  );
});

app.post("/login", (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";
  const user = users[username];

  if (!user) {
    return res.redirect("/login?error=" + encodeURIComponent("Invalid username or password."));
  }

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) {
    return res.redirect("/login?error=" + encodeURIComponent("Invalid username or password."));
  }

  req.session.username = username;
  res.redirect("/dashboard");
});

// --- LOGOUT ---
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// --- DASHBOARD ---
app.get("/dashboard", requireLogin, (req, res) => {
  const username = req.session.username;
  const user = users[username];

  const otherUsersOptions = Object.keys(users)
    .filter((name) => name !== username)
    .map((name) => `<option value="${name}">${name}</option>`)
    .join("");

  const historyHtml = (user.history || [])
    .map((line) => `<li>${line}</li>`)
    .join("");

  res.send(
    layout(
      "Dashboard",
      `
      <p>Logged in as <strong>${username}</strong></p>
      <p>Your balance: <strong>${user.balance}</strong></p>

      <h2>Send money</h2>
      ${
        otherUsersOptions
          ? `
      <form method="POST" action="/transfer">
        <label>To:
          <select name="toUser">
            ${otherUsersOptions}
          </select>
        </label>
        <br/><br/>
        <label>Amount:
          <input name="amount" type="number" step="1" min="1" required />
        </label>
        <br/><br/>
        <button type="submit">Send</button>
      </form>
      `
          : "<p>No other users yet to send money to.</p>"
      }

      <h2>Recent activity</h2>
      <ul>
        ${historyHtml || "<li>No activity yet</li>"}
      </ul>

      <p><a href="/logout">Log out</a></p>
      `
    )
  );
});

// --- TRANSFER ---
app.post("/transfer", requireLogin, (req, res) => {
  const fromUser = req.session.username;
  const { toUser, amount } = req.body;

  const amountNumber = Number(amount);

  if (!users[toUser]) {
    return res.send("That user does not exist. <a href='/dashboard'>Back</a>");
  }
  if (!Number.isFinite(amountNumber) || amountNumber <= 0) {
    return res.send("Invalid amount. <a href='/dashboard'>Back</a>");
  }
  if (toUser === fromUser) {
    return res.send("You can't send money to yourself. <a href='/dashboard'>Back</a>");
  }

  const sender = users[fromUser];
  const receiver = users[toUser];

  if (sender.balance < amountNumber) {
    return res.send("Not enough money! <a href='/dashboard'>Back</a>");
  }

  sender.balance -= amountNumber;
  receiver.balance += amountNumber;

  const time = new Date().toLocaleString();
  sender.history = sender.history || [];
  receiver.history = receiver.history || [];

  sender.history.unshift(`Sent ${amountNumber} to ${toUser} at ${time}`);
  receiver.history.unshift(`Received ${amountNumber} from ${fromUser} at ${time}`);

  saveUsers();
  res.redirect("/dashboard");
});

// --------- START SERVER ---------
app.listen(PORT, () => {
  console.log(`✅ Dorks Bank running at http://localhost:${PORT}`);
});
