import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import ts from "typescript";

const root = process.cwd();

function parse(filePath, source, kind) {
  return ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, true, kind);
}

function propertyName(property) {
  if (ts.isStringLiteral(property.name) || ts.isIdentifier(property.name)) return property.name.text;
  return "";
}

function variableObject(file, name) {
  let result;
  function unwrapObject(expression) {
    let current = expression;
    while (ts.isAsExpression(current) || ts.isSatisfiesExpression(current) || ts.isParenthesizedExpression(current)) {
      current = current.expression;
    }
    return ts.isObjectLiteralExpression(current) ? current : undefined;
  }
  function visit(node) {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === name &&
      node.initializer
    ) {
      result = unwrapObject(node.initializer);
      if (result) return;
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  assert.ok(result, `Could not find object literal ${name}`);
  return result;
}

test("English source catalog covers localized UI text and contains no Russian fallback text", async () => {
  const pagePath = path.join(root, "app", "page.tsx");
  const catalogPath = path.join(root, "app", "i18n-text.ts");
  const [pageSource, catalogSource] = await Promise.all([
    readFile(pagePath, "utf8"),
    readFile(catalogPath, "utf8"),
  ]);
  const page = parse(pagePath, pageSource, ts.ScriptKind.TSX);
  const catalog = parse(catalogPath, catalogSource, ts.ScriptKind.TS);
  const object = variableObject(catalog, "englishText");
  const entries = object.properties
    .filter(ts.isPropertyAssignment)
    .map((property) => {
      assert.ok(ts.isStringLiteral(property.name), "Catalog keys must be string literals");
      assert.ok(ts.isStringLiteral(property.initializer), `Translation for ${property.name.text} must be a string literal`);
      return [property.name.text, property.initializer.text];
    });
  const keys = new Set(entries.map(([key]) => key));
  const duplicateKeys = entries
    .map(([key]) => key)
    .filter((key, index, values) => values.indexOf(key) !== index);
  assert.equal(keys.size, entries.length, `English source catalog contains duplicate keys: ${duplicateKeys.join(" | ")}`);
  for (const [key, value] of entries) {
    assert.ok(value.trim(), `Translation for ${key} is empty`);
    assert.doesNotMatch(value, /[А-Яа-яЁё]/, `Translation for ${key} still contains Cyrillic text`);
    const placeholders = (text) => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((match) => match[1]).sort();
    assert.deepEqual(
      placeholders(value),
      placeholders(key),
      `Translation for ${key} must preserve all interpolation placeholders`,
    );
  }

  const missing = new Set();
  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      (node.expression.text === "tr" || node.expression.text === "localizedText") &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0]) &&
      !keys.has(node.arguments[0].text)
    ) {
      missing.add(node.arguments[0].text);
    }
    if (ts.isJsxText(node) && /[А-Яа-яЁё]/.test(node.text)) {
      assert.fail(`Raw Cyrillic JSX text remains: ${node.text.trim()}`);
    }
    if (
      ts.isJsxAttribute(node) &&
      node.initializer &&
      ts.isStringLiteral(node.initializer) &&
      /[А-Яа-яЁё]/.test(node.initializer.text)
    ) {
      assert.fail(`Raw Cyrillic JSX attribute remains: ${node.initializer.text}`);
    }
    ts.forEachChild(node, visit);
  }
  visit(page);
  assert.deepEqual([...missing], [], `Missing English translations: ${[...missing].join(" | ")}`);
  assert.match(
    pageSource,
    /return message\.startsWith\("Ошибка:"\) \|\| message\.startsWith\("Error:"\);/,
    "Both localized error prefixes must remain non-recursive",
  );
});

test("semantic RU and EN message shells expose the same keys", async () => {
  const filePath = path.join(root, "app", "i18n.tsx");
  const source = await readFile(filePath, "utf8");
  const file = parse(filePath, source, ts.ScriptKind.TSX);
  const messages = variableObject(file, "messages");
  const localeObjects = Object.fromEntries(
    messages.properties
      .filter(ts.isPropertyAssignment)
      .filter((property) => ts.isObjectLiteralExpression(property.initializer))
      .map((property) => [propertyName(property), property.initializer]),
  );
  assert.ok(localeObjects.ru && localeObjects.en, "Both RU and EN message shells must exist");
  const keys = (object) => object.properties.filter(ts.isPropertyAssignment).map(propertyName).sort();
  assert.deepEqual(keys(localeObjects.en), keys(localeObjects.ru));
});
