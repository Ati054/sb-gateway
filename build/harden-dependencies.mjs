import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hardenImageSize } from "./harden-image-size.mjs";
import { hardenBraces } from "./harden-braces.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
hardenImageSize(root);
hardenBraces(root);
console.log("Dependency source guards verified (image-size + braces).");
