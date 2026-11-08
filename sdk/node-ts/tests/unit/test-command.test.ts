import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

it("keeps Vitest last so npm test forwards file filters to Vitest", () => {
  const manifest = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
    scripts: Record<string, string>;
  };

  expect(manifest.scripts.test).toBe("npm run test:cloud-release-probe && vitest run");
});
