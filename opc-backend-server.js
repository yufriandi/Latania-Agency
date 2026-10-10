/**
 * OPC Backend Server — One Person Company
 * Jembatan integrasi: Gmail (kirim email/proposal) + PayPal (invoice & webhook)
 * Deploy target: Render (Node.js)
 *
 * Variabel environment yang dibutuhkan (diatur di Render > Environment):
 *  - API_KEY              : kunci untuk endpoint dashboard (WAJIB)
 *  - ADMIN_KEY            : kunci admin untuk endpoint sensitif (WAJIB)
 *  - CORS_ORIGIN          : origin dashboard, mis. https://dashboard-anda.onrender.com
 *  - PORT                 : otomatis disediakan Render
 *
 * Gmail:
 *  - GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REDIRECT_URI
 *  - GMAIL_REFRESH_TOKEN   : diisi setelah OAuth flow /auth/gmail/url -> /auth/gmail/callback
 *  - SENDER_EMAIL          : alamat pengirim, mis. agency@latania.com
 *
 * PayPal:
 *  - PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET
 *  - PAYPAL_BASE_URL       : https://api-m.sandbox.paypal.com (lalu live: api-m.paypal.com)
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.text({ type: "*/*" })); // untuk verifikasi webhook raw body

// ---------------------------------------------------------------
// CORS — hanya izinkan origin dashboard yang dikonfigurasi
// ---------------------------------------------------------------
const allowedOrigin = process.env.CORS_ORIGIN || "";
app.use(
  cors({
    origin: allowedOrigin ? allowedOrigin.split(",").map((o) => o.trim()) : true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-API-KEY", "X-ADMIN-KEY"],
  })
);

// ---------------------------------------------------------------
// Helper
// ---------------------------------------------------------------
const LOGS = [];
function log(type, message, meta = {}) {
  const entry = {
    ts: new Date().toISOString(),
    type,
    message,
    meta,
  };
  LOGS.unshift(entry);
  if (LOGS.length > 200) LOGS.pop();
  console.log(`[${type}] ${message}`, JSON.stringify(meta || {}));
}

function requireApiKey(req, res, next) {
  if (req.headers["x-api-key"] !== process.env.API_KEY) {
    return res.status(401).json({ error: "Unauthorized: API key tidak valid" });
  }
  next();
}

function requireAdminKey(req, res, next) {
  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized: Admin key tidak valid" });
  }
  next();
}

async function paypalToken() {
  const basic = Buffer.from(
    `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
  ).toString("base64");
  const resp = await fetch(
    `${process.env.PAYPAL_BASE_URL}/v1/oauth2/token`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "grant_type=client_credentials",
    }
  );
  if (!resp.ok) throw new Error(`PayPal token gagal: HTTP ${resp.status}`);
  const data = await resp.json();
  return data.access_token;
}

// ---------------------------------------------------------------
// Gmail helpers (restful Gmail API via googleapis)
// ---------------------------------------------------------------
const { google } = require("googleapis");

function gmailClient() {
  const auth = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );
  auth.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
  return google.gmail({ version: "v1", auth });
}

function buildRawEmail({ to, subject, body }) {
  const lines = [
    `From: ${process.env.SENDER_EMAIL || "me"}`,
    `To: ${to}`,
    "Content-Type: text/plain; charset=UTF-8",
    "MIME-Version: 1.0",
    `Subject: ${subject}`,
    "",
    body,
  ];
  return Buffer.from(lines.join("\r\n"))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------------------------------------------------------------
// ROUTES
// ---------------------------------------------------------------

// Health check (tanpa API key — untuk Render health monitor)
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "opc-backend",
    gmail: Boolean(process.env.GMAIL_REFRESH_TOKEN),
    paypal: Boolean(process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_CLIENT_SECRET),
    time: new Date().toISOString(),
  });
});

// Semua endpoint di bawah ini butuh API key
app.use("/api", requireApiKey);

// Status integrasi untuk dashboard
app.get("/api/status", (req, res) => {
  res.json({
    backend: "online",
    gmail: process.env.GMAIL_REFRESH_TOKEN ? "configured" : "not-configured",
    paypal:
      process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_CLIENT_SECRET
        ? "configured"
        : "not-configured",
    env: process.env.PAYPAL_BASE_URL && process.env.PAYPAL_BASE_URL.includes("sandbox")
      ? "sandbox"
      : "live",
  });
});

// Log aktivitas terbaru
app.get("/api/logs", (req, res) => {
  res.json({ logs: LOGS.slice(0, 50) });
});

// ----------------------- GMAIL -----------------------

// 1) Mulai OAuth — buka URL ini di browser (butuh admin key)
app.get("/auth/gmail/url", requireAdminKey, (req, res) => {
  const url = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  ).generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/gmail.send"],
  });
  res.redirect(url);
});

// 2) Callback OAuth — tukar code menjadi refresh token
app.get("/auth/gmail/callback", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send("Parameter code tidak ada");
    const oauth2 = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      process.env.GMAIL_REDIRECT_URI
    );
    const { tokens } = await oauth2.getToken(code);
    log("gmail", "OAuth token diperoleh", { refresh_token_present: Boolean(tokens.refresh_token) });
    res.send(
      `<h3>OAuth Gmail berhasil</h3><p>Simpan refresh token berikut sebagai env GMAIL_REFRESH_TOKEN di Render:</p><pre>${tokens.refresh_token || "(tidak ada refresh token — hapus akses aplikasi di akun Google lalu ulangi dengan prompt=consent)"}</pre>`
    );
  } catch (err) {
    log("gmail", "OAuth callback gagal", { error: String(err) });
    res.status(500).send("OAuth gagal: " + err.message);
  }
});

// 3) Kirim email (dipakai agen Sales untuk proposal / follow-up)
app.post("/api/email/send", async (req, res) => {
  try {
    const { to, subject, body } = req.body;
    if (!to || !subject || !body) {
      return res.status(400).json({ error: "to, subject, dan body wajib diisi" });
    }
    const gmail = gmailClient();
    await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: buildRawEmail({ to, subject, body }) },
    });
    log("gmail", `Email terkirim ke ${to}`, { subject });
    res.json({ ok: true, message: `Email terkirim ke ${to}` });
  } catch (err) {
    log("gmail", "Gagal kirim email", { error: String(err), to: req.body?.to });
    res.status(500).json({ error: "Kirim email gagal", detail: err.message });
  }
});

// ----------------------- PAYPAL -----------------------

// Buat invoice PayPal
app.post("/api/paypal/invoice", async (req, res) => {
  try {
    const { clientName, clientEmail, items } = req.body;
    if (!clientName || !clientEmail || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "clientName, clientEmail, dan items wajib diisi" });
    }
    const token = await paypalToken();
    // 1) buat draft invoice
    const invResp = await fetch(
      `${process.env.PAYPAL_BASE_URL}/v2/invoicing/invoices`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          detail: {
            invoice_number: `OPC-${Date.now()}`,
            currency_code: "USD",
            note: "Terima kasih telah memakai jasa One Person Company / Latania Agency.",
          },
          invoicer: { email_address: process.env.PAYPAL_INVOICER_EMAIL || "me" },
          primary_recipients: [
            { billing_info: { name: { full_name: clientName }, email_address: clientEmail } },
          ],
          items: items.map((it) => ({
            name: it.name,
            quantity: String(it.quantity || 1),
            unit_amount: { currency_code: "USD", value: String(it.amount) },
          })),
        }),
      }
    );
    const inv = await invResp.json();
    if (!invResp.ok) throw new Error(inv.message || `HTTP ${invResp.status}`);
    // 2) kirim invoice ke klien
    const sendResp = await fetch(
      `${process.env.PAYPAL_BASE_URL}/v2/invoicing/invoices/${inv.id}/send`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ subject: "Invoice dari One Person Company" }),
      }
    );
    if (!sendResp.ok) throw new Error(`Kirim invoice gagal: HTTP ${sendResp.status}`);
    log("paypal", `Invoice ${inv.id} dikirim ke ${clientEmail}`, {});
    res.json({ ok: true, invoiceId: inv.id });
  } catch (err) {
    log("paypal", "Gagal membuat invoice", { error: String(err) });
    res.status(500).json({ error: "Invoice gagal", detail: err.message });
  }
});

// Webhook pembayaran PayPal — verifikasi tanda tangan, jangan percaya body mentah
app.post("/api/paypal/webhook", async (req, res) => {
  try {
    const rawBody = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    const webhookId = process.env.PAYPAL_WEBHOOK_ID;
    const transmissionId = req.headers["paypal-transmission-id"];
    const transmissionTime = req.headers["paypal-transmission-time"];
    const certUrl = req.headers["paypal-cert-url"];
    const authAlgo = req.headers["paypal-auth-algo"];
    const transmissionSig = req.headers["paypal-transmission-sig"];

    if (!webhookId) {
      // fallback tanpa verifikasi — HANYA untuk testing, jangan dipakai di live
      log("paypal", "Webhook diterima TANPA verifikasi (PAYPAL_WEBHOOK_ID belum diisi)", {
        event: req.headers,
      });
      return res.status(200).json({ ok: true, verified: false });
    }

    const verifyResp = await fetch(
      `${process.env.PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${await paypalToken()}`,
        },
        body: JSON.stringify({
          auth_algo: authAlgo,
          cert_url: certUrl,
          transmission_id: transmissionId,
          transmission_sig: transmissionSig,
          transmission_time: transmissionTime,
          webhook_id: webhookId,
          webhook_event: JSON.parse(rawBody),
        }),
      }
    );
    const verify = await verifyResp.json();
    if (verify.verification_status !== "SUCCESS") {
      log("paypal", "Webhook signature TIDAK VALID", {});
      return res.status(401).json({ error: "Verifikasi webhok gagal" });
    }

    const event = JSON.parse(rawBody);
    log("paypal", `Webhook terverifikasi: ${event.event_type}`, {
      resource: event.resource?.id,
    });
    // Di sini nanti bisa memicu: tandai deal Terkirim, update pendapatan, kirim email terima kasih
    res.status(200).json({ ok: true, verified: true });
  } catch (err) {
    log("paypal", "Webhook error", { error: String(err) });
    res.status(500).json({ error: "Webhook error", detail: err.message });
  }
});

// Endpoint admin: buang log & health sensitif (contoh)
app.get("/api/admin/debug", requireAdminKey, (req, res) => {
  res.json({
    logs: LOGS,
    env_confirm: {
      cors: process.env.CORS_ORIGIN,
      gmail_redirect: process.env.GMAIL_REDIRECT_URI,
    },
  });
});

// LLM agent placeholder — atau bisa diisi pipeline Scout/Sales otomatis
app.post("/api/agents/run-cycle", requireApiKey, (req, res) => {
  log("agents", "Siklus otomatis diminta via API", {});
  res.json({ ok: true, message: "Siklus diminta; log tetap berjalan di backend" });
});

// 404 fallback
app.use((req, res) => res.status(404).json({ error: "Endpoint tidak ditemukan" }));

// ----------------------- START -----------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  log("system", `Backend OPC aktif di port ${PORT}`, {
    sandbox: (process.env.PAYPAL_BASE_URL || "").includes("sandbox"),
    gmail: Boolean(process.env.GMAIL_REFRESH_TOKEN),
  });
});
