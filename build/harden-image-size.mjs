import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Both frameworks vendor image-size, outside npm audit's dependency graph.
// GHSA-w3rx-r6r6-pgpr / GHSA-5p2g-fcmc-qvqq: require bounded, advancing chunks.
export const targets = [
  {
    package: "vinext", version: "1.0.0-beta.9",
    file: "node_modules/vinext/dist/deps/.pnpm/image-size@2.0.2/deps/image-size/dist/index.js",
    original: "456ef3528be51418bebdd975aac4b6f4345610964166d1492220b35d686c8d15",
    patched: "d358ec30ae5aa1570903c15437eeeff1316d8edb551ab83e8c267a761f5013d4",
    replacements: [
      ["if (input.length - offset < 4) return;\n\tconst boxSize = readUInt32BE(input, offset);\n\tif (input.length - offset < boxSize) return;",
        "if (input.length - offset < 8) return;\n\tconst declaredSize = readUInt32BE(input, offset);\n\tconst boxSize = declaredSize === 0 ? input.length - offset : declaredSize;\n\tif (boxSize < 8 || input.length - offset < boxSize) throw new TypeError(\"Invalid image box size\");"],
      ["const imageLengthOffset = imageOffset + ENTRY_LENGTH_OFFSET;\n\treturn [toUTF8String(input, imageOffset, imageLengthOffset), readUInt32BE(input, imageLengthOffset)];",
        "const fileLength = readUInt32BE(input, FILE_LENGTH_OFFSET);\n\tif (fileLength < 8 || fileLength > input.length || imageOffset + 8 > fileLength) throw new TypeError(\"Invalid ICNS header\");\n\tconst imageLengthOffset = imageOffset + ENTRY_LENGTH_OFFSET;\n\tconst imageLength = readUInt32BE(input, imageLengthOffset);\n\tif (imageLength < 8 || imageLength > fileLength - imageOffset) throw new TypeError(\"Invalid ICNS entry size\");\n\treturn [toUTF8String(input, imageOffset, imageLengthOffset), imageLength];"],
    ],
  },
  {
    package: "next", version: "16.3.4",
    file: "node_modules/next/dist/compiled/image-size/index.js",
    original: "1d4f421eb59637a19ffe1acda0b34c670b9ceece24777b09433f48110795052d",
    patched: "fd6ead7c2137438caa4faf2a6a9ba1ffbcd928980ea863370473a498095580f0",
    replacements: [
      ["function readBox(t,n){if(t.length-n<4)return;const r=(0,e.readUInt32BE)(t,n);if(t.length-n<r)return;",
        "function readBox(t,n){if(t.length-n<8)return;const declaredSize=(0,e.readUInt32BE)(t,n);const r=declaredSize===0?t.length-n:declaredSize;if(r<8||t.length-n<r)throw new TypeError(\"Invalid image box size\");"],
      ["function readImageHeader(t,e){const n=e+o;return[(0,r.toUTF8String)(t,e,n),(0,r.readUInt32BE)(t,n)]}",
        "function readImageHeader(t,e){const fileLength=(0,r.readUInt32BE)(t,4);if(fileLength<8||fileLength>t.length||e+8>fileLength)throw new TypeError(\"Invalid ICNS header\");const n=e+o;const imageLength=(0,r.readUInt32BE)(t,n);if(imageLength<8||imageLength>fileLength-e)throw new TypeError(\"Invalid ICNS entry size\");return[(0,r.toUTF8String)(t,e,n),imageLength]}"],
    ],
  },
];

export const sha256 = (text) => createHash("sha256").update(text).digest("hex");

export function patchedSource(target, source) {
  if (sha256(source) !== target.original) throw new Error(`Unexpected ${target.package} image-size source; review the security patch`);
  for (const [before, after] of target.replacements) {
    if (source.split(before).length !== 2) throw new Error(`Ambiguous ${target.package} security patch`);
    source = source.replace(before, after);
  }
  return source;
}

export function hardenImageSize(root = resolve(dirname(fileURLToPath(import.meta.url)), "..")) {
  // Validate every target before modifying any dependency. Unknown upgrades fail closed.
  const changes = targets.map((target) => {
    const metadata = JSON.parse(readFileSync(resolve(root, "node_modules", target.package, "package.json"), "utf8"));
    if (metadata.version !== target.version) throw new Error(`Review image-size hardening for ${target.package}@${metadata.version}`);
    const file = resolve(root, target.file);
    const source = readFileSync(file, "utf8");
    if (sha256(source) === target.patched) return null;
    const result = patchedSource(target, source);
    if (sha256(result) !== target.patched) throw new Error(`Invalid ${target.package} security patch checksum`);
    return { file, result };
  });
  for (const change of changes) if (change) writeFileSync(change.file, change.result);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  hardenImageSize();
  console.log("Bundled image-size security guards verified (Next.js + Vinext).");
}
