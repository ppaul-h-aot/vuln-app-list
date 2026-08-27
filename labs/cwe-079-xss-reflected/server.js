"use strict";

const express = require("express");

const PORT = Number(process.env.PORT) || 3000;
const LAB_MANIFEST = {
  cwe: "CWE-79",
  name: "xss-reflected",
  endpoints: [
    {
      method: "GET",
      path: "/search",
      param: "q",
      type: "reflected_xss",
    },
  ],
  expected_signals: ["script_reflection", "html_injection"],
};

const SHARED_STYLES = `
  :root {
    --ink: #13212b;
    --muted: #5a6b76;
    --paper: #f3f1eb;
    --panel: #fffdf8;
    --line: #d5d0c4;
    --accent: #0f6e56;
    --accent-soft: #d8efe6;
    --warn: #8a3b12;
    --warn-bg: #f6e4d4;
    --shadow: 0 18px 40px rgba(19, 33, 43, 0.08);
    --radius: 14px;
    --font-display: "Fraunces", Georgia, serif;
    --font-body: "IBM Plex Sans", "Segoe UI", sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    color: var(--ink);
    font-family: var(--font-body);
    background:
      radial-gradient(1200px 500px at 10% -10%, #d9ebe3 0%, transparent 55%),
      radial-gradient(900px 420px at 100% 0%, #efe6d8 0%, transparent 50%),
      linear-gradient(180deg, #ebe7de 0%, var(--paper) 40%, #e7ebe8 100%);
  }
  a { color: var(--accent); text-decoration-thickness: 1px; text-underline-offset: 3px; }
  a:hover { color: var(--ink); }
  .shell { max-width: 920px; margin: 0 auto; padding: 28px 20px 56px; }
  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; margin-bottom: 22px;
  }
  .brand {
    display: flex; align-items: center; gap: 12px;
    font-family: var(--font-display); font-weight: 600; font-size: 1.15rem;
    letter-spacing: -0.02em; color: var(--ink); text-decoration: none;
  }
  .mark {
    width: 34px; height: 34px; border-radius: 10px;
    background: linear-gradient(145deg, #147a5f, #0b4f3d);
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.2);
    position: relative;
  }
  .mark::after {
    content: ""; position: absolute; inset: 9px 8px 9px 14px;
    border: 2px solid #e8fff6; border-left: 0; border-radius: 0 8px 8px 0;
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
    background:
      linear-gradient(160deg, rgba(255,255,255,0.9), rgba(255,253,248,0.75)),
      repeating-linear-gradient(0deg, transparent, transparent 23px, rgba(213,208,196,0.35) 24px);
    box-shadow: var(--shadow);
  }
  .eyebrow {
    margin: 0 0 8px; color: var(--accent); font-size: 0.78rem;
    letter-spacing: 0.08em; text-transform: uppercase; font-weight: 600;
  }
  h1 {
    margin: 0 0 10px; font-family: var(--font-display);
    font-size: clamp(1.8rem, 4vw, 2.45rem); line-height: 1.15;
    letter-spacing: -0.03em; font-weight: 600;
  }
  .lede { margin: 0 0 22px; max-width: 38rem; color: var(--muted); line-height: 1.55; }
  form.search {
    display: grid; grid-template-columns: 1fr auto; gap: 10px;
    padding: 10px; border-radius: 999px; border: 1px solid var(--line);
    background: var(--panel);
  }
  label.sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0,0,0,0); border: 0;
  }
  input[type="text"] {
    border: 0; outline: none; background: transparent;
    padding: 12px 16px; font: inherit; font-size: 1rem; color: var(--ink);
  }
  button {
    border: 0; border-radius: 999px; padding: 12px 20px;
    background: var(--ink); color: #f7faf8; font: inherit; font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #243846; }
  .section-title {
    margin: 34px 0 14px; font-family: var(--font-display);
    font-size: 1.15rem; letter-spacing: -0.02em;
  }
  .grid { display: grid; gap: 12px; }
  @media (min-width: 720px) { .grid.two { grid-template-columns: 1fr 1fr; } }
  .item {
    padding: 16px 18px; border: 1px solid var(--line); border-radius: var(--radius);
    background: rgba(255,253,248,0.85);
  }
  .item h2 { margin: 0 0 6px; font-size: 1rem; font-weight: 600; }
  .item p { margin: 0; color: var(--muted); font-size: 0.92rem; line-height: 1.45; }
  .meta {
    display: inline-block; margin-bottom: 8px; padding: 3px 8px;
    border-radius: 999px; background: var(--accent-soft); color: var(--accent);
    font-size: 0.72rem; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase;
  }
  .query-line {
    margin: 0 0 18px; padding: 14px 16px; border-radius: var(--radius);
    background: #eef4f1; border: 1px solid #c9ddd4; color: var(--ink);
  }
  .query-line em { font-style: normal; font-weight: 600; }
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
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <style>${SHARED_STYLES}</style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="/"><span class="mark" aria-hidden="true"></span>Harbor Knowledge</a>
      <nav class="nav" aria-label="Primary">
        <span>Guides</span>
        <span>API</span>
        <span>Status</span>
      </nav>
    </header>
    <aside class="lab-banner" role="note">
      <div>
        <strong>Intentional vulnerability lab</strong>
        <p>
          This app is a scanner target for <em>CWE-79 reflected XSS</em>.
          The search query is echoed into the results page without encoding
          so you can verify detection. Do not enter real credentials or private data.
        </p>
      </div>
    </aside>
    ${body}
    <footer class="footer">
      <span>Harbor Knowledge &middot; demo content only</span>
      <span>Lab: CWE-79 / xss-reflected</span>
    </footer>
  </div>
</body>
</html>`;
}

const app = express();

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/.well-known/lab-manifest.json", (_req, res) => {
  res.json(LAB_MANIFEST);
});

app.get("/", (_req, res) => {
  res.type("html").send(
    layout({
      title: "Harbor Knowledge - Search",
      body: `
    <section class="hero">
      <p class="eyebrow">Support library</p>
      <h1>Find answers across Harbor docs</h1>
      <p class="lede">
        Browse onboarding notes, API recipes, and incident playbooks.
        Search is wired for lab testing, not production traffic.
      </p>
      <form class="search" method="get" action="/search">
        <label class="sr-only" for="q">Search query</label>
        <input id="q" name="q" type="text" placeholder="Search guides, endpoints, runbooks…" autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </section>
    <h2 class="section-title">Popular right now</h2>
    <div class="grid two">
      <article class="item">
        <span class="meta">Getting started</span>
        <h2>Invite teammates and set workspace roles</h2>
        <p>Walkthrough for owners adding analysts, viewers, and automation bots.</p>
      </article>
      <article class="item">
        <span class="meta">API</span>
        <h2>Rotate personal access tokens safely</h2>
        <p>Expiry windows, scoped permissions, and how revoked tokens behave.</p>
      </article>
      <article class="item">
        <span class="meta">Incidents</span>
        <h2>Escalation ladder for failed deploys</h2>
        <p>Who to page, what to capture, and the rollback checklist.</p>
      </article>
      <article class="item">
        <span class="meta">Security</span>
        <h2>How Harbor handles session cookies</h2>
        <p>Fake article for local flavor. The real finding lives in search reflection.</p>
      </article>
    </div>`,
    })
  );
});

app.get("/search", (req, res) => {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  // Intentional CWE-79: reflect user input into HTML without encoding.
  res.type("html").send(
    layout({
      title: "Search results - Harbor Knowledge",
      body: `
    <section class="hero">
      <p class="eyebrow">Search results</p>
      <h1>Matches in the knowledge base</h1>
      <p class="query-line">You searched for: <em>${q}</em></p>
      <form class="search" method="get" action="/search">
        <label class="sr-only" for="q">Search query</label>
        <input id="q" name="q" type="text" value="" placeholder="Refine your search…" autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </section>
    <h2 class="section-title">Suggested articles</h2>
    <div class="grid">
      <article class="item">
        <span class="meta">Guide</span>
        <h2>Writing safe search result pages</h2>
        <p>Placeholder copy. A secure app would HTML-encode the query before rendering it.</p>
      </article>
      <article class="item">
        <span class="meta">Checklist</span>
        <h2>Scanner verification notes for reflected XSS</h2>
        <p>Confirm script and HTML injection signals against <code>/search?q=</code>.</p>
      </article>
      <article class="item">
        <span class="meta">Demo</span>
        <h2>Sample runbook: “reset staging cache”</h2>
        <p>Filler content so the page feels like a real help center while you probe the sink.</p>
      </article>
    </div>
    <p style="margin-top:18px"><a href="/">Back to home</a></p>`,
    })
  );
});

app.listen(PORT, () => {
  console.log(`cwe-079-xss-reflected listening on ${PORT}`);
});
