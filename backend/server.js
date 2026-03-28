require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { Issuer, generators } = require("openid-client");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));

// Session Setup
app.use(
    session({
        secret: process.env.APP_SECRET || "fallback-secret",
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false },
    })
);

// OIDC Client
let oidcClient = null;

async function getOidcClient() {
    if (oidcClient) return oidcClient;

    const issuerUrl = process.env.ISSUER_BASE_URL;
    if (!issuerUrl) throw new Error("ISSUER_BASE_URL is not set in .env");

    console.log(`[OIDC] Discovering issuer at: ${issuerUrl}`);
    const issuer = await Issuer.discover(issuerUrl);
    console.log(`[OIDC] Discovered issuer: ${issuer.issuer}`);

    oidcClient = new issuer.Client({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        redirect_uris: [process.env.REDIRECT_URI || "http://localhost:5000/callback"],
        response_types: ["code"],
    });

    return oidcClient;
}

// Read HTML Helper
function readHtml(filename) {
    return fs.readFileSync(
        path.join(__dirname, "..", "frontend", filename),
        "utf-8"
    );
}

// Routes

// Home 
app.get("/", (req, res) => {
    const isLoggedIn = !!req.session.userClaims;
    let html = readHtml("home.html");
    html = html.replace(
        "{{LOGIN_STATE}}",
        isLoggedIn
            ? `<p class="logged-in-notice">Logged in as <strong>${req.session.userClaims?.email || req.session.userClaims?.sub}</strong> — <a href="/profile">View Profile</a> | <a href="/logout">Logout</a></p>`
            : ""
    );
    res.send(html);
});

// Login - generate PKCE + state, redirect to OIDC provider
app.get("/login", async (req, res) => {
    try {
        const client = await getOidcClient();
        const state = generators.state();
        const nonce = generators.nonce();
        const codeVerifier = generators.codeVerifier();
        const codeChallenge = generators.codeChallenge(codeVerifier);

        // Store in session for validation after callback
        req.session.oidcState = state;
        req.session.oidcNonce = nonce;
        req.session.codeVerifier = codeVerifier;

        const authUrl = client.authorizationUrl({
            scope: "openid email profile offline_access",
            state,
            nonce,
            code_challenge: codeChallenge,
            code_challenge_method: "S256",
        });

        console.log(`[LOGIN] Redirecting to: ${authUrl}`);
        res.redirect(authUrl);
    } catch (err) {
        console.error("[LOGIN] Error:", err.message);
        res.status(500).send(`<pre>Error starting login: ${err.message}</pre>`);
    }
});

// Callback — exchange code for tokens, store claims in session
app.get("/callback", async (req, res) => {
    try {
        const client = await getOidcClient();
        const params = client.callbackParams(req);

        const tokenSet = await client.callback(
            process.env.REDIRECT_URI || "http://localhost:5000/callback",
            params,
            {
                state: req.session.oidcState,
                nonce: req.session.oidcNonce,
                code_verifier: req.session.codeVerifier,
            }
        );

        console.log("[CALLBACK] Received TokenSet:");
        console.log("  ID Token:", tokenSet.id_token);
        console.log("  Access Token:", tokenSet.access_token?.substring(0, 40) + "...");

        const claims = tokenSet.claims();
        console.log("[CALLBACK] ID Token Claims:", JSON.stringify(claims, null, 2));

        // Store everything in session
        req.session.userClaims = claims;
        req.session.idToken = tokenSet.id_token;
        req.session.accessToken = tokenSet.access_token;
        req.session.refreshToken = tokenSet.refresh_token;

        // Clean up OIDC state from session
        delete req.session.oidcState;
        delete req.session.oidcNonce;
        delete req.session.codeVerifier;

        res.redirect("/profile");
    } catch (err) {
        console.error("[CALLBACK] Error:", err.message);
        res.status(500).send(`
      <html><body>
        <h2>❌ Callback Error</h2>
        <pre>${err.message}</pre>
        <a href="/">← Back to Home</a>
      </body></html>
    `);
    }
});

// Profile — display parsed JWT claims
app.get("/profile", (req, res) => {
    if (!req.session.userClaims) {
        return res.redirect("/");
    }

    const claims = req.session.userClaims;
    const idToken = req.session.idToken || "";

    // Decode JWT parts (header + payload) for display
    let jwtHeader = {};
    let jwtPayload = {};
    try {
        const [hdr, pay] = idToken.split(".");
        jwtHeader = JSON.parse(Buffer.from(hdr, "base64url").toString());
        jwtPayload = JSON.parse(Buffer.from(pay, "base64url").toString());
    } catch (_) { }

    let html = readHtml("profile.html");
    html = html
        .replace("{{USERNAME}}", claims.name || claims.preferred_username || claims.email || claims.sub || "Unknown")
        .replace("{{EMAIL}}", claims.email || "N/A")
        .replace("{{SUB}}", claims.sub || "N/A")
        .replace("{{ISSUER}}", claims.iss || "N/A")
        .replace("{{PROVIDER}}", process.env.PROVIDER || "hydra")
        .replace("{{RAW_ID_TOKEN}}", idToken)
        .replace("{{JWT_HEADER}}", JSON.stringify(jwtHeader, null, 2))
        .replace("{{JWT_PAYLOAD}}", JSON.stringify(jwtPayload, null, 2))
        .replace("{{ALL_CLAIMS}}", JSON.stringify(claims, null, 2));

    res.send(html);
});

// Logout — clear session
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`\n🚀 App running at http://localhost:${PORT}`);
    console.log(`   Provider: ${process.env.PROVIDER || "(not set)"}`);
    console.log(`   Issuer:   ${process.env.ISSUER_BASE_URL || "(not set)"}`);
    console.log(`   Client:   ${process.env.CLIENT_ID || "(not set)"}\n`);
});