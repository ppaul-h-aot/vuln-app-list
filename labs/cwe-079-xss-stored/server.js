"use strict";

const express = require("express");

const PORT = Number(process.env.PORT) || 3000;
const LAB_MANIFEST = {
  cwe: "CWE-79",
  name: "xss-stored",
  endpoints: [
    {
      method: "POST",
      path: "/feedback",
      param: "message",
      type: "stored_xss",
    },
    {
      method: "GET",
      path: "/feedback",
      param: null,
      type: "stored_xss",
    },
  ],
  expected_signals: ["script_persistence", "html_injection"],
};

const feedbackEntries = [];

const SHARED_STYLES = `
  :root {
    --ink: #1a1423;
    --muted: #6b6474;
    --paper: #f7f4fb;
    --panel: #fffdff;
    --line: #ddd4e8;
    --accent: #6b2fa0;
    --accent-soft: #ede0f8;
    --warn: #7a2f12;
    --warn-bg: #f8e8dc;
    --shadow: 0 18px 40px rgba(26, 20, 35, 0.08);
    --radius: 14px;
    --font-display: "DM Serif Display", Georgia, serif;
    --font-body: "Source Sans 3", "Segoe UI", sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    color: var(--ink);
    font-family: var(--font-body);
    background:
      radial-gradient(900px 420px at 0% 0%, #e8d9f5 0%, transparent 55%),
      radial-gradient(800px 380px at 100% 10%, #f5e8d4 0%, transparent 50%),
      linear-gradient(180deg, #ece6f2 0%, var(--paper) 45%, #ebe6ef 100%);
  }
  a { color: var(--accent); text-decoration-thickness: 1px; text-underline-offset: 3px; }
  a:hover { color: var(--ink); }
  .shell { max-width: 880px; margin: 0 auto; padding: 28px 20px 56px; }
  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; margin-bottom: 22px;
  }
  .brand {
    display: flex; align-items: center; gap: 12px;
    font-family: var(--font-display); font-weight: 400; font-size: 1.25rem;
    letter-spacing: -0.02em; color: var(--ink); text-decoration: none;
  }
  .mark {
    width: 34px; height: 34px; border-radius: 50%;
    background: linear-gradient(145deg, #8b4cc7, #5a2788);
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.25);
    position: relative;
  }
  .mark::after {
    content: ""; position: absolute; inset: 10px;
    border: 2px solid #f6ecff; border-radius: 50%;
  }
  .nav { display: flex; gap: 18px; color: var(--muted); font-size: 0.92rem; }
  .nav span { cursor: default; }
  .lab-banner {
    display: flex; gap: 14px; align-items: flex-start;
    padding: 14px 16px; margin-bottom: 28px;
    border: 1px solid #e2c4a8; border-radius: var(--radius);
    background: linear-gradient(120deg, var(--warn-bg), #fff8f0);
    box-shadow: var(--shadow);
  }
  .lab-banner strong {
    display: block; color: var(--warn); font-size: 0.84rem;
    letter-spacing: 0.04em; text-transform: uppercase; margin-bottom: 4px;
  }
  .lab-banner p { margin: 0; color: #5c3a24; line-height: 1.45; font-size: 0.95rem; }
  .hero {
    padding: 28px 28px 30px; border: 1px solid var(--line); border-radius: 22px;
    background: linear-gradient(160deg, rgba(255,255,255,0.92), rgba(255,253,255,0.78));
    box-shadow: var(--shadow);
  }
  .eyebrow {
    margin: 0 0 8px; color: var(--accent); font-size: 0.78rem;
    letter-spacing: 0.08em; text-transform: uppercase; font-weight: 600;
  }
  h1 {
    margin: 0 0 10px; font-family: var(--font-display);
    font-size: clamp(1.8rem, 4vw, 2.35rem); line-height: 1.15;
    letter-spacing: -0.03em; font-weight: 400;
  }
  .lede { margin: 0 0 22px; max-width: 38rem; color: var(--muted); line-height: 1.55; }
  form.feedback {
    display: grid; gap: 12px; padding: 16px; border-radius: var(--radius);
    border: 1px solid var(--line); background: var(--panel);
  }
  label { font-size: 0.92rem; font-weight: 600; color: var(--ink); }
  input[type="text"], textarea {
    border: 1px solid var(--line); outline: none; background: #fff;
    padding: 12px 14px; font: inherit; font-size: 1rem; color: var(--ink);
    border-radius: 10px; width: 100%;
  }
  textarea { min-height: 110px; resize: vertical; }
  button {
    justify-self: start; border: 0; border-radius: 999px; padding: 12px 22px;
    background: var(--accent); color: #fff; font: inherit; font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #57207f; }
  .section-title {
    margin: 34px 0 14px; font-family: var(--font-display);
    font-size: 1.15rem; letter-spacing: -0.02em;
  }
  .feed-list { display: grid; gap: 12px; margin: 0; padding: 0; list-style: none; }
  .feed-item {
    padding: 16px 18px; border: 1px solid var(--line); border-radius: var(--radius);
    background: rgba(255,253,255,0.88);
  }
  .feed-item header {
    display: flex; justify-content: space-between; gap: 12px;
    margin-bottom: 8px; color: var(--muted); font-size: 0.85rem;
  }
  .feed-item strong { color: var(--ink); font-size: 0.95rem; }
  .feed-body { line-height: 1.5; color: var(--ink); }
  .empty {
    padding: 18px; border: 1px dashed var(--line); border-radius: var(--radius);
    color: var(--muted); background: rgba(255,255,255,0.6);
  }
  .footer {
    margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 0.85rem; display: flex;
    justify-content: space-between; gap: 12px; flex-wrap: wrap;
  }
`;

function layout({ title, body }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=Source+Sans+3:wght@400;500;600&display=swap" rel="stylesheet">
  <style>${SHARED_STYLES}</style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="/"><span class="mark" aria-hidden="true"></span>Nimbus Feedback</a>
      <nav class="nav" aria-label="Primary">
        <span>Changelog</span>
        <span>Roadmap</span>
        <span>Support</span>
      </nav>
    </header>
    <aside class="lab-banner" role="note">
      <div>
        <strong>Intentional vulnerability lab</strong>
        <p>
          This app is a scanner target for <em>CWE-79 stored XSS</em>.
          Feedback messages are saved and rendered on later page loads without encoding.
          Do not enter real credentials or private data.
        </p>
      </div>
    </aside>
    ${body}
    <footer class="footer">
      <span>Nimbus Feedback &middot; demo content only</span>
      <span>Lab: CWE-79 / xss-stored</span>
    </footer>
  </div>
</body>
</html>`;
}

function renderFeedbackList() {
  if (feedbackEntries.length === 0) {
    return `<p class="empty">No feedback yet. Submit a note below to populate the wall.</p>`;
  }

  return `<ul class="feed-list">${feedbackEntries
    .map(
      (entry) => `
      <li class="feed-item">
        <header>
          <strong>${entry.author}</strong>
          <time datetime="${entry.createdAt}">${entry.createdAt}</time>
        </header>
        <div class="feed-body">${entry.message}</div>
      </li>`
    )
    .join("")}</ul>`;
}

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/.well-known/lab-manifest.json", (_req, res) => {
  res.json(LAB_MANIFEST);
});

app.get("/", (_req, res) => {
  res.type("html").send(
    layout({
      title: "Nimbus Feedback - Product pulse",
      body: `
    <section class="hero">
      <p class="eyebrow">Customer voice</p>
      <h1>Share what Nimbus should build next</h1>
      <p class="lede">
        This feedback wall is wired for lab testing. Messages persist in memory
        and render for every visitor who opens the feedback page.
      </p>
      <p><a href="/feedback">Open the feedback wall</a></p>
    </section>
    <h2 class="section-title">How this lab works</h2>
    <section class="hero">
      <p class="lede">
        POST a payload to <code>/feedback</code> with <code>author</code> and
        <code>message</code>, then visit <code>GET /feedback</code> to trigger stored XSS.
      </p>
    </section>`,
    })
  );
});

app.get("/feedback", (_req, res) => {
  res.type("html").send(
    layout({
      title: "Feedback wall - Nimbus Feedback",
      body: `
    <section class="hero">
      <p class="eyebrow">Feedback wall</p>
      <h1>What customers are saying</h1>
      <p class="lede">Notes below are stored server-side and replayed to every visitor.</p>
      <form class="feedback" method="post" action="/feedback">
        <div>
          <label for="author">Your name</label>
          <input id="author" name="author" type="text" placeholder="Alex from Ops" autocomplete="off">
        </div>
        <div>
          <label for="message">Message</label>
          <textarea id="message" name="message" placeholder="Tell us what to improve…"></textarea>
        </div>
        <button type="submit">Post feedback</button>
      </form>
    </section>
    <h2 class="section-title">Recent notes</h2>
    ${renderFeedbackList()}
    <p style="margin-top:18px"><a href="/">Back to home</a></p>`,
    })
  );
});

app.post("/feedback", (req, res) => {
  const author =
    typeof req.body.author === "string" && req.body.author.trim()
      ? req.body.author.trim()
      : "Anonymous";
  const message =
    typeof req.body.message === "string" ? req.body.message : "";

  if (message.trim()) {
    // Intentional CWE-79: persist user HTML and render it on later GET requests.
    feedbackEntries.unshift({
      author,
      message,
      createdAt: new Date().toISOString(),
    });
  }

  res.redirect(302, "/feedback");
});

app.listen(PORT, () => {
  console.log(`cwe-079-xss-stored listening on ${PORT}`);
});
