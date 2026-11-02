#!/usr/bin/env node
// WebCheck scanner. Requires Node 18+. No installs needed.
//   Server mode (for the WebCheck page):  node webcheck-scanner.mjs
//   Command line mode:                    node webcheck-scanner.mjs https://your-site.com
import http from "node:http";

const UA = "Mozilla/5.0 (compatible; WebCheckBot/1.0)";
const PORT = process.env.PORT || 3000;
const SKIP_EXT = /\.(jpe?g|png|gif|webp|svg|ico|pdf|zip|mp4|mp3|css|js|xml|json|woff2?)(\?|$)/i;

async function get(url, method = "GET") {
  const t0 = Date.now(), ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 12000);
  try {
    const r = await fetch(url, { method, redirect: "follow", signal: ctl.signal, headers: { "user-agent": UA, accept: "text/html,*/*" } });
    return { r, status: r.status, ms: Date.now() - t0 };
  } catch (e) {
    return { r: null, status: 0, ms: Date.now() - t0, err: e.name === "AbortError" ? "timeout" : (e.cause?.code || e.message) };
  } finally { clearTimeout(timer); }
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

async function checkLink(url) {
  let res = await get(url, "HEAD");
  await res.r?.body?.cancel();
  if (res.status === 0 || res.status >= 400) { res = await get(url, "GET"); await res.r?.body?.cancel(); }
  return { url, status: res.status, error: res.err };
}

const tags = (html, name) => html.match(new RegExp("<" + name + "\\b[^>]*>", "gi")) || [];
const attr = (tag, name) => {
  const m = tag.match(new RegExp("\\s" + name + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", "i"));
  return m ? (m[1] ?? m[2] ?? m[3]) : null;
};

function analyse(html, pageUrl) {
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]?.trim();
  const imgs = tags(html, "img");
  const https = pageUrl.startsWith("https:");
  const insecure = [...imgs, ...tags(html, "script"), ...tags(html, "iframe")].filter(t => /\ssrc\s*=\s*["']?http:\/\//i.test(t)).length
    + tags(html, "link").filter(t => /stylesheet/i.test(attr(t, "rel") || "") && /^http:\/\//i.test(attr(t, "href") || "")).length;
  const links = [];
  for (const a of tags(html, "a")) {
    const href = attr(a, "href"); if (!href) continue;
    try { const u = new URL(href.replace(/&amp;/g, "&"), pageUrl); u.hash = ""; if (/^https?:$/.test(u.protocol)) links.push(u.href); } catch {}
  }
  return {
    hasTitle: !!title,
    hasViewport: tags(html, "meta").some(t => /name\s*=\s*["']?viewport/i.test(t)),
    hasLang: /<html[^>]*\slang\s*=/i.test(html),
    hasFavicon: tags(html, "link").some(t => /icon/i.test(attr(t, "rel") || "")),
    imgCount: imgs.length,
    imgNoAlt: imgs.filter(t => attr(t, "alt") === null).length,
    h1Count: tags(html, "h1").length,
    mixed: https ? insecure : 0,
    links
  };
}

export async function audit(start, maxPages = 15, maxLinks = 150) {
  const origin = new URL(start).origin;
  const queue = [start], seen = new Set([start]), pages = [], linkSet = new Set();
  let firstHeaders = null;

  while (queue.length && pages.length < maxPages) {
    const url = queue.shift(), res = await get(url);
    const rec = { url, status: res.status, ms: res.ms, error: res.err };
    if (res.r) {
      if (!firstHeaders) firstHeaders = res.r.headers;
      if (/text\/html/i.test(res.r.headers.get("content-type") || "")) {
        const html = (await res.r.text()).slice(0, 2_000_000);
        Object.assign(rec, analyse(html, res.r.url || url));
        for (const l of rec.links) {
          linkSet.add(l);
          if (l.startsWith(origin) && !seen.has(l) && !SKIP_EXT.test(l)) { seen.add(l); queue.push(l); }
        }
        delete rec.links;
      } else await res.r.body?.cancel();
    }
    pages.push(rec);
  }

  const pageStatus = new Map(pages.map(p => [p.url, p.status]));
  const toCheck = [...linkSet].filter(l => !pageStatus.has(l)).slice(0, maxLinks);
  const checked = await pool(toCheck, 8, checkLink);
  const links = [...pages.filter(p => p.status).map(p => ({ url: p.url, status: p.status })), ...checked];
  const broken = links.filter(l => l.status === 0 || l.status >= 400);
  const brokenInternal = broken.filter(l => l.url.startsWith(origin));

  const notFound = await get(origin + "/webcheck-404-" + Date.now());
  await notFound.r?.body?.cancel();

  const html = pages.filter(p => "hasTitle" in p);
  const issues = [], checks = {};
  const add = (title, sev, page, detail, exp) => issues.push({ title, sev, page, detail, exp });
  const first = pages[0];

  // Page loading
  pages.filter(p => p === first && (p.status === 0 || p.status >= 400)).forEach(p =>
    add("Page does not load", "Critical", p.url, p.status ? "HTTP " + p.status : "No response (" + (p.error || "unknown") + ")", "Page loads with a 2xx status"));
  checks["0-0"] = pages.every(p => p.status >= 200 && p.status < 400) ? "pass" : "fail";

  // Images and titles
  const noAlt = html.filter(p => p.imgNoAlt);
  if (noAlt.length) add("Images missing alt text", "Minor", noAlt[0].url, noAlt.reduce((n, p) => n + p.imgNoAlt, 0) + " images across " + noAlt.length + " page(s) have no alt attribute", "Every image has an alt attribute");
  checks["0-2"] = html.some(p => p.imgCount) ? (noAlt.length ? "fail" : "pass") : "na";
  const noTitle = html.filter(p => !p.hasTitle);
  if (noTitle.length) add("Page title missing", "Minor", noTitle[0].url, noTitle.length + " page(s) have no title", "Each page has a descriptive title");
  const noIcon = html[0] && !html[0].hasFavicon;
  if (noIcon) add("No favicon link found", "Trivial", html[0].url, "The home page has no icon link tag (a default /favicon.ico may still work)", "Favicon is set");
  checks["0-3"] = html.length ? (noTitle.length || noIcon ? "fail" : "pass") : "na";

  // Navigation
  brokenInternal.slice(0, 20).forEach(l => add("Broken internal link", "Major", l.url, l.status ? "HTTP " + l.status : "No response", "Link opens a working page"));
  broken.filter(l => !l.url.startsWith(origin)).slice(0, 20).forEach(l => add("Broken external link", "Minor", l.url, l.status ? "HTTP " + l.status : "No response", "Link opens a working page"));
  checks["1-0"] = brokenInternal.length ? "fail" : "pass";
  checks["1-3"] = notFound.status === 404 ? "pass" : "fail";
  if (notFound.status !== 404) add("Missing pages do not return 404", "Minor", origin, "A made-up URL returned " + (notFound.status || "no response"), "Unknown URLs return a 404 status and a helpful page");

  // Performance (server response time only)
  const timed = pages.filter(p => p.status);
  const avg = timed.length ? timed.reduce((n, p) => n + p.ms, 0) / timed.length : 0;
  const slow = timed.filter(p => p.ms > 3000);
  slow.slice(0, 5).forEach(p => add("Slow page response", "Minor", p.url, Math.round(p.ms) + " ms to load the HTML", "Under 3 seconds"));
  checks["3-0"] = timed.length ? (avg < 3000 ? "pass" : "fail") : "na";

  // Structure and accessibility basics
  const badH1 = html.filter(p => p.h1Count !== 1);
  if (badH1.length) add("Page does not have exactly one main heading", "Trivial", badH1[0].url, badH1.length + " page(s) have 0 or more than 1 h1 element", "One h1 per page");
  checks["4-3"] = html.length ? (badH1.length ? "fail" : "pass") : "na";
  const noLang = html.filter(p => !p.hasLang);
  if (noLang.length) add("Page language not declared", "Minor", noLang[0].url, "The html element has no lang attribute", "html lang is set");
  const noVp = html.filter(p => !p.hasViewport);
  if (noVp.length) add("Missing viewport meta tag", "Major", noVp[0].url, noVp.length + " page(s) will not scale properly on phones", "Pages include a viewport meta tag");

  // Security
  const https = start.startsWith("https:");
  checks["6-0"] = https ? "pass" : "fail";
  if (!https) add("Site is not served over HTTPS", "Critical", start, "The start URL uses http://", "Site loads over HTTPS");
  const mixed = html.filter(p => p.mixed);
  if (mixed.length) add("Mixed content (http resources on https page)", "Major", mixed[0].url, mixed.reduce((n, p) => n + p.mixed, 0) + " insecure resource(s)", "All resources load over HTTPS");
  checks["6-1"] = https ? (mixed.length ? "fail" : "pass") : "na";
  if (https && firstHeaders && !firstHeaders.get("strict-transport-security"))
    add("HSTS header not set", "Trivial", start, "Strict-Transport-Security header is missing", "HSTS header is present");

  return {
    site: start, pages, links, checks, issues,
    note: "Covers what can be detected from page source and HTTP responses. Typos, keyboard use, visual layout and cross-browser rendering still need a person."
  };
}

function textReport(d) {
  const L = ["WebCheck scan: " + d.site, "", `Pages crawled: ${d.pages.length}`, `Links checked: ${d.links.length}`, `Issues found: ${d.issues.length}`, ""];
  d.issues.forEach((i, n) => L.push(`${n + 1}. [${i.sev}] ${i.title}`, `   ${i.page}`, `   ${i.detail}`));
  L.push("", d.note);
  return L.join("\n");
}

function validUrl(u) { try { return /^https?:$/.test(new URL(u).protocol); } catch { return false; } }

async function main() {
  const arg = process.argv[2];
  if (arg) {
    if (!validUrl(arg)) { console.error("Give a full URL, for example https://example.com"); process.exit(1); }
    console.log("Scanning " + arg + " ...");
    console.log(textReport(await audit(arg)));
    return;
  }
  http.createServer(async (req, res) => {
    const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Private-Network": "true" };
    const send = (code, obj) => { res.writeHead(code, { ...cors, "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (req.method === "OPTIONS") { res.writeHead(204, cors); return res.end(); }
    if (req.method !== "POST") return send(200, { ok: true, name: "WebCheck scanner" });
    let body = ""; for await (const c of req) body += c;
    let data; try { data = JSON.parse(body || "{}"); } catch { return send(400, { error: "Invalid JSON" }); }
    try {
      if (new URL(req.url, "http://x").pathname === "/audit") {
        if (!validUrl(data.url)) return send(400, { error: "Send a full http(s) URL" });
        console.log("Scanning " + data.url);
        return send(200, await audit(data.url));
      }
      const urls = (data.urls || []).filter(validUrl).slice(0, 200);
      send(200, { results: await pool(urls, 8, checkLink) });
    } catch (e) { send(500, { error: e.message }); }
  }).listen(PORT, "127.0.0.1", () => console.log("WebCheck scanner running at http://localhost:" + PORT));
}
main();
