// frontend/scripts/print_label_context.js
const fs = require("fs");
const path = require("path");

const file = path.join(__dirname, "..", "src", "components", "AuthPages.jsx");
const content = fs.readFileSync(file, "utf8").split(/\r?\n/);

const targets = [210, 719, 770, 790, 818]; // from your scan output
const ctx = 12;

for (const lineNo of targets) {
  const start = Math.max(0, lineNo - ctx - 1);
  const end = Math.min(content.length, lineNo + ctx);
  console.log("\n" + "=".repeat(80));
  console.log(`AuthPages.jsx context around line ${lineNo}`);
  console.log("=".repeat(80));
  for (let i = start; i < end; i++) {
    console.log(String(i + 1).padStart(4, " ") + " | " + content[i]);
  }
}