import { readFileSync, readdirSync } from "node:fs";
import ts from "typescript";

const directory = new URL("../app/console/", import.meta.url);
const modules = [
  "shared", "overview", "clients", "routing", "connections", "operations",
  "settings", "apply-dialog", "client-dialog", "policy-dialog", "tls-profile-dialog",
  "connection-dialog", "setup-wizard", "shell", "auth",
];

// Source-contract tests inspect every section, not the now-small route entry.
export function readConsoleSourceSync() {
  const files = readdirSync(directory).filter(name => name.endsWith(".tsx"));
  const ordered = [...modules.map(name => `${name}.tsx`), ...files.filter(name => !modules.includes(name.slice(0, -4)))];
  const sources = ordered.map(name => [name, readFileSync(new URL(name, directory), "utf8")]);
  sources.push(["page.tsx", readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8")]);
  return sources.map(([name, source]) => {
    const parsed = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    return parsed.statements.filter(statement => !ts.isImportDeclaration(statement))
      .map(statement => {
        let text = statement.getFullText(parsed);
        if (!statement.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.DefaultKeyword)) {
          for (const modifier of [...(statement.modifiers ?? [])].reverse()) {
            if (modifier.kind !== ts.SyntaxKind.ExportKeyword) continue;
            const start = modifier.getStart(parsed) - statement.getFullStart();
            text = text.slice(0, start) + text.slice(start + modifier.getWidth(parsed) + 1);
          }
        }
        return text;
      }).join("\n");
  }).join("\n");
}

export async function readConsoleSource() {
  return readConsoleSourceSync();
}
