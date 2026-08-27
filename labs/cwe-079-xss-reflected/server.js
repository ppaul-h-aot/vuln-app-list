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

const app = express();

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/.well-known/lab-manifest.json", (_req, res) => {
  res.json(LAB_MANIFEST);
});

app.get("/", (_req, res) => {
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CWE-79 Reflected XSS Lab</title>
</head>
<body>
  <h1>Search</h1>
  <p>Intentional vulnerable lab for scanner testing.</p>
  <form method="get" action="/search">
    <label for="q">Query</label>
    <input id="q" name="q" type="text">
    <button type="submit">Search</button>
  </form>
</body>
</html>`);
});

app.get("/search", (req, res) => {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  // Intentional CWE-79: reflect user input into HTML without encoding.
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Search results</title>
</head>
<body>
  <h1>Results</h1>
  <p>You searched for: ${q}</p>
  <p><a href="/">Back</a></p>
</body>
</html>`);
});

app.listen(PORT, () => {
  console.log(`cwe-079-xss-reflected listening on ${PORT}`);
});
