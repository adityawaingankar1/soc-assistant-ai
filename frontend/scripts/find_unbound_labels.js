// frontend/scripts/find_unbound_labels.js
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "src");
const exts = new Set([".js", ".jsx", ".ts", ".tsx"]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (exts.has(path.extname(entry.name))) out.push(p);
  }
  return out;
}

function scanFile(filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);

  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Find <label ...> in JSX
    if (line.includes("<label")) {
      const hasHtmlFor = line.includes("htmlFor=");
      const hasFor = line.includes("for="); // sometimes plain HTML pasted
      const isClosingOnly = line.includes("</label>");
      // only flag if it looks like an opening label and missing htmlFor/for
      if (!hasHtmlFor && !hasFor && !isClosingOnly) {
        findings.push({ lineNo: i + 1, line: line.trim() });
      }
    }
  }
  return findings;
}

const files = walk(ROOT);
let total = 0;

for (const f of files) {
  const hits = scanFile(f);
  if (hits.length) {
    console.log(`\nFILE: ${path.relative(process.cwd(), f)}`);
    for (const h of hits) {
      total++;
      console.log(`  Line ${h.lineNo}: ${h.line}`);
    }
  }
}

console.log(`\nTotal unbound <label> candidates: ${total}`);
process.exit(0);