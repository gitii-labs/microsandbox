import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Compile complete README examples against the built, exported declarations.
// Compile temporary source files with the installed compiler's public CLI.
const packages = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let checked = 0;
for (const name of ["protocol-client", "agent-client", "control-client"]) {
  const directory = path.join(packages, name, "typescript");
  const require = createRequire(path.join(directory, "package.json"));
  const compiler = path.join(path.dirname(require.resolve("typescript/package.json")), "bin", "tsc");
  const readme = readFileSync(path.join(directory, "README.md"), "utf8");
  for (const [index, match] of [...readme.matchAll(/```ts\n([\s\S]*?)\n```/g)].entries()) {
    const temporary = mkdtempSync(path.join(directory, ".readme-check-"));
    try {
      const filename = path.join(temporary, `readme-example-${index + 1}.ts`);
      writeFileSync(filename, match[1]);
      const result = spawnSync(process.execPath, [compiler,
        "--ignoreConfig", "--target", "ES2023", "--module", "NodeNext",
        "--moduleResolution", "NodeNext", "--noEmit", "--strict",
        "--noUncheckedIndexedAccess", "--skipLibCheck", "--types", "node",
        "--lib", "ES2023,DOM", filename,
      ], { cwd: directory, stdio: "inherit" });
      if (result.error) throw result.error;
      // A failed compiler or signal must fail documentation validation.
      if (result.status !== 0) process.exitCode = 1;
    } finally {
      rmSync(temporary, { recursive: true });
    }
    checked++;
  }
}
if (!process.exitCode) console.log(`Typechecked ${checked} public README examples.`);
