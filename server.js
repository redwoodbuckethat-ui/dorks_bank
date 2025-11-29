// ------------------------------
// DORKS BANK - with signup, hashing, and basic persistence
// ------------------------------

const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

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

app.use(express.static("public"));

app.use(
  session({
    secret: "dorks-bank-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// --------- AUTH MIDDLEWARE ---------
function requireLogin(req, res, next) {
  if (!req.session.userId) {
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
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h1>Dorks Bank</h1>
        ${body}
      </div>
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

app.post("/signup", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  if (!username || !password) {
    return res.redirect(
      "/signup?error=" +
        encodeURIComponent("Username and password are required.")
    );
  }

  if (password.length < 4) {
    return res.redirect(
      "/signup?error=" +
        encodeURIComponent("Password must be at least 4 characters.")
    );
  }

  try {
    // 1. Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // 2. Insert into Supabase (Postgres)
    await pool.query(
      `
      INSERT INTO users (username, password_hash, role, balance)
      VALUES ($1, $2, 'user', 0)
      `,
      [username, passwordHash]
    );

    // 3. Log user in
    req.session.username = username;
    req.session.role = "user";

    res.redirect("/dashboard");
  } catch (err) {
    // Duplicate username (unique constraint)
    if (err.code === "23505") {
      return res.redirect(
        "/signup?error=" + encodeURIComponent("That username is taken.")
      );
    }

    console.error(err);
    res.redirect(
      "/signup?error=" +
        encodeURIComponent("Something went wrong. Please try again.")
    );
  }
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

app.post("/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  if (!username || !password) {
    return res.redirect(
      "/login?error=" + encodeURIComponent("Invalid username or password.")
    );
  }

  try {
    // 1. Look up user in database
    const result = await pool.query(
      `
      SELECT id, password_hash, role
      FROM users
      WHERE username = $1
      `,
      [username]
    );

    if (result.rows.length === 0) {
      return res.redirect(
        "/login?error=" + encodeURIComponent("Invalid username or password.")
      );
    }

    const user = result.rows[0];

    // 2. Check password
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.redirect(
        "/login?error=" + encodeURIComponent("Invalid username or password.")
      );
    }

    // 3. Store session info
    // ✅ SAVE SESSION BEFORE REDIRECT
    req.session.userId = user.id;
    req.session.username = username;
    req.session.role = user.role;

    req.session.save(() => {
      res.redirect("/dashboard");
    });
  } catch (err) {
    console.error(err);
    res.redirect(
      "/login?error=" +
        encodeURIComponent("Something went wrong. Please try again.")
    );
  }
});


// --- DASHBOARD ---
app.get("/dashboard", requireLogin, async (req, res) => {
  const username = req.session.username;
  const showSentMessage = req.query.sent === "1";
  const errorType = req.query.error;

  try {
    // 1. Get current user's balance
    const userResult = await pool.query(
      `
      SELECT balance
      FROM users
      WHERE username = $1
      `,
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.redirect("/logout");
    }

    const user = userResult.rows[0];

    // 2. Get other users for "send money" dropdown
    const othersResult = await pool.query(
      `
      SELECT username
      FROM users
      WHERE username != $1
      ORDER BY username
      `,
      [username]
    );

    const otherUsersOptions = othersResult.rows
      .map(
        (row) => `<option value="${row.username}">${row.username}</option>`
      )
      .join("");

    // 3. Get recent transactions involving this user
    const txResult = await pool.query(
      `
      SELECT from_user, to_user, amount, created_at
      FROM transactions
      WHERE from_user = $1 OR to_user = $1
      ORDER BY created_at DESC
      LIMIT 10
      `,
      [username]
    );

    const historyItems = txResult.rows
      .map((tx) => {
        const isSender = tx.from_user === username;
        const direction = isSender ? "Sent" : "Received";
        const otherParty = isSender ? tx.to_user : tx.from_user;
        const time = new Date(tx.created_at).toLocaleString();

        return `
          <li>
            ${direction} <strong>${tx.amount}</strong>
            ${isSender ? "to" : "from"} <strong>${otherParty}</strong>
            <span style="color: gray;">(${time})</span>
          </li>
        `;
      })
      .join("");

    // 4. Render dashboard
    res.send(
      layout(
        "Dashboard",
        `
        <p style="text-align:center;">
          Logged in as <strong>${username}</strong>
        </p>

<div class="toast-slot">
  ${
    showSentMessage
      ? '<div class="toast success">✅ Money sent!</div>'
      : errorType === "insufficient"
      ? '<div class="toast error">❌ Not enough money</div>'
      : '<div class="toast placeholder"></div>'
  }
</div>


        <div class="section balance-card">
          <h2>Your balance</h2>
          <div class="balance">$${user.balance}</div>
        </div>

        <div class="section card">
          <h2>Send money</h2>

          ${
            otherUsersOptions
              ? `
          <form method="POST" action="/transfer">
            <label>To</label>
            <select name="toUser" required>
              ${otherUsersOptions}
            </select>

            <label>Amount</label>
            <input name="amount" type="number" min="1" step="1" required />

            <button type="submit">Send money</button>
          </form>
          `
              : "<p>No other users yet.</p>"
          }
        </div>

        <div class="section card">
          <h2>Recent activity</h2>
          <ul class="transaction-list">
            ${historyItems || "<li>No recent transactions.</li>"}
          </ul>
        </div>

        <p style="text-align:center; margin-top: 24px;">
          <a href="/logout">Log out</a>
        </p>

        <script>
  (function () {
    if (
      window.location.search.includes("sent=1") ||
      window.location.search.includes("error=")
    ) {
      window.history.replaceState({}, "", window.location.pathname);
    }
  })();
</script>
        `
      )
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading dashboard");
  }
});



// -------------- TRANSFER ---------------

app.post("/transfer", requireLogin, async (req, res) => {
  const fromUser = req.session.username;
  const fromRole = req.session.role;
  const { toUser, amount } = req.body;

  const amountNumber = Number(amount);

  if (!toUser || !Number.isFinite(amountNumber) || amountNumber <= 0) {
    return res.send("Invalid transfer. <a href='/dashboard'>Back</a>");
  }

  if (toUser === fromUser) {
    return res.send("You can't send money to yourself. <a href='/dashboard'>Back</a>");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Fetch sender (lock row)
    const senderResult = await client.query(
      `
      SELECT balance
      FROM users
      WHERE username = $1
      FOR UPDATE
      `,
      [fromUser]
    );

    if (senderResult.rows.length === 0) {
      throw new Error("Sender not found");
    }

    const senderBalance = senderResult.rows[0].balance;

    // Fetch receiver (lock row)
    const receiverResult = await client.query(
      `
      SELECT balance
      FROM users
      WHERE username = $1
      FOR UPDATE
      `,
      [toUser]
    );

    if (receiverResult.rows.length === 0) {
      throw new Error("Receiver does not exist");
    }

    // Check funds (admin bypass)
    if (fromRole !== "admin" && senderBalance < amountNumber) {
      return res.redirect("/dashboard?error=insufficient");
    }

    // Update balances
    if (fromRole !== "admin") {
      await client.query(
        `
        UPDATE users
        SET balance = balance - $1
        WHERE username = $2
        `,
        [amountNumber, fromUser]
      );
    }

    await client.query(
      `
      UPDATE users
      SET balance = balance + $1
      WHERE username = $2
      `,
      [amountNumber, toUser]
    );

    // Record transaction
    await client.query(
      `
      INSERT INTO transactions (from_user, to_user, amount)
      VALUES ($1, $2, $3)
      `,
      [fromUser, toUser, amountNumber]
    );

    await client.query("COMMIT");
    res.redirect("/dashboard?sent=1");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err.message);
    res.send(err.message + ". <a href='/dashboard'>Back</a>");
  } finally {
    client.release();
  }
});



// --------- START SERVER ---------
app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("select 1 + 1 as answer");
    res.json({ ok: true, answer: result.rows[0].answer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --------- LOGOUT ---------
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});


app.listen(PORT, () => {
  console.log(`✅ Dorks Bank running at http://localhost:${PORT}`);
});
