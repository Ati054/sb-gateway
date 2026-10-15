import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const directory = new URL("../app/console/", import.meta.url);

test("console sections have acyclic imports and a small route entry", async () => {
  const entry = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.ok(entry.split("\n").length < 40);
  assert.doesNotMatch(entry, /useState|useReducer|apiRequest/);
  const files = (await readdir(directory)).filter(name => name.endsWith(".tsx"));
  for (const name of ["overview", "clients", "routing", "connections", "operations", "settings"]) {
    assert.ok(files.includes(`${name}.tsx`));
  }
  const graph = new Map();
  for (const name of files) {
    const source = await readFile(new URL(name, directory), "utf8");
    assert.ok(source.split("\n").length < 5000, `${name} exceeds the section size guard`);
    const file = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    graph.set(name, file.statements.filter(ts.isImportDeclaration)
      .map(statement => statement.moduleSpecifier.text)
      .filter(path => path.startsWith("./"))
      .map(path => `${path.slice(2)}.tsx`));
    assert.doesNotMatch(source, /from ["']\.\.\/page["']/);
  }
  assert.deepEqual(graph.get("shared.tsx"), [], "shared UI must not depend on sections");
  const done = new Set();
  function visit(name, parents = []) {
    assert.ok(!parents.includes(name), `circular section import: ${[...parents, name].join(" -> ")}`);
    if (done.has(name)) return;
    assert.ok(graph.has(name), `missing module ${name}`);
    for (const dependency of graph.get(name)) visit(dependency, [...parents, name]);
    done.add(name);
  }
  for (const name of files) visit(name);
});
