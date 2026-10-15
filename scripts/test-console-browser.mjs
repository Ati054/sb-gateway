import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { resolve, extname, sep, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyConsoleWorkflows } from "../tests/browser/console-workflows.mjs";

const root = resolve("out");
await stat(resolve(root, "index.html"));
const moduleName = process.env.SB_PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName);
const mime = {".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2"};
const server = createServer(async (request, response) => {
  try {
    const name = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    const file = resolve(root, `.${name === "/" ? "/index.html" : name}`);
    if (!file.startsWith(root + sep)) throw new Error("Invalid test asset path");
    const body = await readFile(file);
    response.writeHead(200, {"content-type": mime[extname(file)] ?? "application/octet-stream"});
    response.end(body);
  } catch {response.writeHead(404); response.end();}
});
await new Promise((resolve, reject) => {server.once("error", reject); server.listen(0, "127.0.0.1", resolve);});
let browser;
try {
  browser = await chromium.launch({headless: true, ...(process.env.SB_BROWSER_CHANNEL ? {channel: process.env.SB_BROWSER_CHANNEL} : {})});
  const results = await verifyConsoleWorkflows(browser, `http://127.0.0.1:${server.address().port}`);
  console.log(JSON.stringify(results));
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
