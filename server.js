// ------------------------------
// FRIEND BANK (BEGINNER VERSION)
// ------------------------------

const express = require("express");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;

// Allow reading form data
app.use(express.urlencoded({ extended: true }));

// Keep users logged in
app.use(
  session({
    secret: "friend-bank-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ------------------------------
// FAKE DATABASE (server-only)
// ------------------------------
const users = {
  alice: { password: "alice123", balance: 1000 },
  bob: { password: "bob123", balance: 1000 },
  charlie: { password: "charlie123", balance: 1000 },
};

// ------------------------------
// LOGIN CHECK
// ------------------------------
function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.redirect("/login");
  }
  next();
}

// ------------------------------
// ROUTES
// ------------------------------
app.get("/", (req, res) => {
  if (req.session.username) {
    return res.redirect("/dashboard");
  }
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.send(`
    <h1>Friend Bank</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="username" />
      <br /><br />
      <input type="password" name="password" placeholder="password" />
      <br /><br />
      <button>Log in</button>
    </form>
    <p>Try: alice / alice123</p>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (!user || user.password !== password) {
    return res.send("Wrong login. <a href='/login'>Try again</a>");
  }

  req.session.username = username;
  res.redirect("/dashboard");
});

app.get("/dashboard", requireLogin, (req, res) => {
  const username = req.session.username;
  const user = users[username];

  const options = Object.keys(users)
    .filter((u) => u !== username)
    .map((u) => `<option value="${u}">${u}</option>`)
    .join("");

  res.send(`
    <h1>Dashboard</h1>
    <p>You are logged in as <b>${username}</b></p>
    <p>Balance: <b>${user.balance}</b></p>

    <h2>Send Money</h2>
    <form method="POST" action="/send">
      <select name="to">${options}</select>
      <input name="amount" type="number" min="1" />
      <button>Send</button>
    </form>

    <br />
    <a href="/logout">Log out</a>
  `);
});

app.post("/send", requireLogin, (req, res) => {
  const from = req.session.username;
  const { to, amount } = req.body;
  const money = Number(amount);

  if (!users[to] || money <= 0 || !Number.isInteger(money)) {
    return res.send("Invalid transfer. <a href='/dashboard'>Back</a>");
  }

  if (users[from].balance < money) {
    return res.send("Not enough money. <a href='/dashboard'>Back</a>");
  }

  users[from].balance -= money;
  users[to].balance += money;

  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// ------------------------------
app.listen(PORT, () => {
  console.log("✅ Friend Bank running at http://localhost:3000");
});
