const express = require("express");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const db = new Database("users.db");

const PORT = 3000;
const isProduction = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET;

if (isProduction && !SESSION_SECRET) {
    throw new Error("Set SESSION_SECRET in production.");
}

app.disable("x-powered-by");
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            styleSrc: ["'self'", "'unsafe-inline'"]
        }
    }
}));

app.use(express.urlencoded({
    extended: false,
    limit: "10kb"
}));

// Create the database table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

// Session configuration
app.use(session({
    name: "secure_login_session",
    secret: SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict",
        maxAge: 30 * 60 * 1000
    }
}));

// Basic login and registration rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: "Too many attempts. Please try again later."
});

app.use(["/login", "/register"], authLimiter);

// Generate a CSRF token for each session
function getCsrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    }
    return req.session.csrfToken;
}

// Escape user-provided text before showing it in HTML
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

// Simple page design
function page(req, title, content) {
    const token = getCsrfToken(req);

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">
        <title>${title}</title>
        <style>
            * { box-sizing: border-box; }
            body {
                font-family: Arial, sans-serif;
                background: #eef2f8;
                margin: 0;
                padding: 30px 15px;
                color: #1e293b;
            }
            .container {
                max-width: 420px;
                margin: 50px auto;
                background: white;
                padding: 30px;
                border-radius: 14px;
                box-shadow: 0 5px 20px #00000012;
            }
            h1 {
                text-align: center;
                color: #2563eb;
                margin-top: 0;
            }
            p { line-height: 1.6; }
            label {
                display: block;
                margin: 15px 0 7px;
                font-weight: bold;
            }
            input {
                width: 100%;
                padding: 12px;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                font-size: 16px;
            }
            button {
                width: 100%;
                padding: 13px;
                margin-top: 20px;
                border: 0;
                border-radius: 7px;
                background: #2563eb;
                color: white;
                font-size: 16px;
                cursor: pointer;
            }
            button:hover { background: #1d4ed8; }
            .link {
                text-align: center;
                margin-top: 20px;
            }
            a { color: #2563eb; }
            .message {
                padding: 10px;
                background: #eff6ff;
                border-radius: 7px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Secure Login System</h1>
            ${content}
        </div>
    </body>
    </html>`;
}

// Validate CSRF tokens on all POST requests
app.use((req, res, next) => {
    if (req.method !== "POST") {
        return next();
    }

    const sent = req.body._csrf;
    const saved = req.session.csrfToken;

    if (
        typeof sent !== "string" ||
        typeof saved !== "string" ||
        sent.length !== saved.length ||
        !crypto.timingSafeEqual(
            Buffer.from(sent),
            Buffer.from(saved)
        )
    ) {
        return res.status(403).send(
            page(req, "Invalid Request",
                "<p>Invalid security token. Please go back and try again.</p>")
        );
    }

    next();
});

// Login page
app.get("/", (req, res) => {
    if (req.session.username) {
        return res.redirect("/dashboard");
    }

    res.send(page(req, "Login", `
        <p>Login to your account</p>
        <form method="POST" action="/login">
            <input type="hidden" name="_csrf"
                   value="${getCsrfToken(req)}">

            <label for="username">Username</label>
            <input id="username" name="username"
                   type="text" autocomplete="username"
                   minlength="3" maxlength="24"
                   pattern="[A-Za-z0-9_]{3,24}" required>

            <label for="password">Password</label>
            <input id="password" name="password"
                   type="password"
                   autocomplete="current-password"
                   required>

            <button type="submit">Login</button>
        </form>
        <div class="link">
            Don't have an account?
            <a href="/register">Register</a>
        </div>
    `));
});

// Registration page
app.get("/register", (req, res) => {
    res.send(page(req, "Register", `
        <p>Create a new account</p>
        <form method="POST" action="/register">
            <input type="hidden" name="_csrf"
                   value="${getCsrfToken(req)}">

            <label for="username">Username</label>
            <input id="username" name="username"
                   type="text" autocomplete="username"
                   minlength="3" maxlength="24"
                   pattern="[A-Za-z0-9_]{3,24}" required>

            <label for="password">Password</label>
            <input id="password" name="password"
                   type="password" autocomplete="new-password"
                   minlength="12" maxlength="72" required>

            <p>Use at least 12 characters for your password.</p>
            <button type="submit">Register</button>
        </form>
        <div class="link">
            Already registered?
            <a href="/">Login</a>
        </div>
    `));
});

// Create a new user account
app.post("/register", async (req, res) => {
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
        return res.status(400).send(
            page(req, "Register",
                "<p>Username must be 3–24 letters, numbers or underscores.</p><a href='/register'>Try again</a>")
        );
    }

    if (
        typeof password !== "string" ||
        password.length < 12 ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        return res.status(400).send(
            page(req, "Register",
                "<p>Password must be at least 12 characters and no more than 72 UTF-8 bytes.</p><a href='/register'>Try again</a>")
        );
    }

    const existing = db.prepare(
        "SELECT id FROM users WHERE username = ?"
    ).get(username);

    if (existing) {
        return res.status(409).send(
            page(req, "Register",
                "<p>Username already exists.</p><a href='/register'>Try again</a>")
        );
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 12);

    try {
        db.prepare(
            "INSERT INTO users (username, password) VALUES (?, ?)"
        ).run(username, hashedPassword);
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).send(
                page(req, "Register",
                    "<p>Username already exists.</p><a href='/register'>Try again</a>")
            );
        }
        throw error;
    }

    res.send(page(req, "Registration Successful", `
        <p class="message">Account created successfully!</p>
        <div class="link"><a href="/">Login now</a></div>
    `));
});

// Login verification
app.post("/login", async (req, res) => {
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (
        !/^[A-Za-z0-9_]{3,24}$/.test(username) ||
        typeof password !== "string" ||
        Buffer.byteLength(password, "utf8") > 72
    ) {
        return res.status(400).send(
            page(req, "Login",
                "<p>Invalid username or password.</p><a href='/'>Try again</a>")
        );
    }

    // Parameterized query helps prevent SQL injection
    const user = db.prepare(
        "SELECT * FROM users WHERE username = ?"
    ).get(username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send(
            page(req, "Login",
                "<p>Invalid username or password.</p><a href='/'>Try again</a>")
        );
    }

    // Regenerate the session after successful login
    req.session.regenerate((error) => {
        if (error) {
            return res.status(500).send("Could not start session.");
        }

        req.session.username = user.username;
        req.session.csrfToken = crypto.randomBytes(32).toString("hex");

        req.session.save((saveError) => {
            if (saveError) {
                return res.status(500).send("Could not save session.");
            }
            res.redirect("/dashboard");
        });
    });
});

// Check whether a user is logged in
function requireLogin(req, res, next) {
    if (!req.session.username) {
        return res.redirect("/");
    }
    next();
}

// Protected dashboard
app.get("/dashboard", requireLogin, (req, res) => {
    const username = escapeHtml(req.session.username);

    res.send(page(req, "Dashboard", `
        <h2>Welcome, ${username}!</h2>
        <p class="message">
            You have successfully logged in to the secure system.
        </p>
        <p>Your account is protected by password hashing
           and session management.</p>

        <form method="POST" action="/logout">
            <input type="hidden" name="_csrf"
                   value="${getCsrfToken(req)}">
            <button type="submit">Logout</button>
        </form>
    `));
});

// Logout and destroy the session
app.post("/logout", requireLogin, (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).send("Logout failed.");
        }

        res.clearCookie("secure_login_session", {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            path: "/"
        });

        res.redirect("/");
    });
});

// Handle unexpected errors
app.use((error, req, res, next) => {
    console.error(error);
    res.status(500).send(
        "Something went wrong. Please try again."
    );
});

// Start server
app.listen(PORT, () => {
    console.log(
        `Secure Login System running at http://localhost:${PORT}`
    );
});