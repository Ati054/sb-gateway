import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { sha256 } from "./harden-image-size.mjs";

// GHSA-vfj7-8cjw-p6xm has no published fix. Bound both parsed nesting and
// public AST walkers; changing a pinned source must fail closed for review.
const depthError = 'throw new SyntaxError("Brace nesting exceeds safe depth");';
const walkPatches = (name) => [
  [`  const ${name} = (node, parent = {}) => {`, `  const ${name} = (node, parent = {}, depth = 0) => {\n    if (depth > 64) ${depthError}`, 1],
  [name === "stringify" ? "stringify(child);" : "walk(child, node);",
    name === "stringify" ? "stringify(child, {}, depth + 1);" : "walk(child, node, depth + 1);", 1],
];

export const bracesTargets = [
  {
    file: "parse.js",
    original: "e572166565f15fa6ad9865ae49d678218e32aabfd1b3720f6d0d43d39800d310",
    patched: "44b656d5643ac1ce5b23bcf03caa7779c44a0c70413e6c58a73235fba913175c",
    replacements: [["      stack.push(block);", `      if (stack.length >= 64) ${depthError}\n      stack.push(block);`, 2]],
  },
  {
    file: "compile.js",
    original: "dc98f22eee3d511785d92a00758d5f0d48efed5f5813bdecc2de430c529b5c9f",
    patched: "80b0cfbf9440a3aff3bebb528c586d112926440e65edd7420368c6e8028f795a",
    replacements: walkPatches("walk"),
  },
  {
    file: "expand.js",
    original: "41ccc196ebfa7b7781a634e721eb744e4e7bcb54cba427a7e3d6806a1b9e58f7",
    patched: "bca4ab8f40f192f37e697edf6ac9e17266cae72acad5e2e2bbb72015238ab40e",
    replacements: walkPatches("walk"),
  },
  {
    file: "stringify.js",
    original: "379f22d77bfa1478341ccd49c5e4267464aabcbba03558bab332aac23fc6f23a",
    patched: "1b9a38051d281030209a6efb0a2ff189b98999a10a4f9a009fd6bc1b8ac5649d",
    replacements: walkPatches("stringify"),
  },
];

export function patchedBracesSource(target, source) {
  if (sha256(source) !== target.original) throw new Error(`Unexpected braces ${target.file} source; review the security patch`);
  for (const [before, after, count] of target.replacements) {
    if (source.split(before).length - 1 !== count) throw new Error(`Ambiguous braces ${target.file} security patch`);
    source = source.replaceAll(before, after);
  }
  if (sha256(source) !== target.patched) throw new Error(`Invalid braces ${target.file} security patch checksum`);
  return source;
}

export function hardenBraces(root) {
  const lock = JSON.parse(readFileSync(resolve(root, "package-lock.json"), "utf8"));
  const copies = Object.keys(lock.packages).filter((path) => path.endsWith("node_modules/braces"));
  if (copies.length !== 1 || copies[0] !== "node_modules/braces") {
    throw new Error("Review braces hardening for changed dependency locations");
  }
  const metadata = JSON.parse(readFileSync(resolve(root, "node_modules/braces/package.json"), "utf8"));
  if (metadata.version !== "3.0.3") throw new Error(`Review braces hardening for ${metadata.version}`);
  const changes = bracesTargets.map((target) => {
    const file = resolve(root, "node_modules/braces/lib", target.file);
    const source = readFileSync(file, "utf8");
    return sha256(source) === target.patched ? null : { file, result: patchedBracesSource(target, source) };
  });
  for (const change of changes) if (change) writeFileSync(change.file, change.result);
}
