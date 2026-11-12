import { describe, expect, it } from "vitest";
import fixture from "./contract.json";
import { GIVEN, REQUIRED_CASES, runContractCase, useHarness, type Contract, type ContractCase } from "./helpers";

// worker/test/contract.json is the device ↔ Worker boundary as data. The Rust side (tests/auth.rs) holds its fake
// auth Worker and its client to the same file; here every case is reproduced by the real handle().
const contract = fixture as unknown as Contract;
const h = useHarness();

describe("contract.json", () => {
  it("is version 2: the device-code login", () => {
    expect(Object.keys(contract).sort()).toEqual(["cases", "version"]);
    expect(contract.version).toBe(2);
  });

  it("contains every required case, each name once", () => {
    const names = contract.cases.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    expect(REQUIRED_CASES.filter((name) => !names.includes(name))).toEqual([]);
  });

  it("uses only the known `given` keywords", () => {
    expect(contract.cases.filter((c) => !(GIVEN as readonly string[]).includes(c.given)).map((c) => c.name)).toEqual([]);
  });

  it("the runner refuses an unknown given keyword, matcher or placeholder", async () => {
    const base: ContractCase = { name: "x", given: "none", request: { method: "GET", path: "/" }, response: { status: 200 } };
    await expect(runContractCase(h, { ...base, given: "moon_phase" })).rejects.toThrow(/unknown given/);
    await expect(runContractCase(h, { ...base, response: { status: 200, body_matches: "x" } as never })).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, { ...base, request: { method: "GET", path: "/", cookies: {} } as never })).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, { ...base, note: "x" } as never)).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, { ...base, request: { method: "POST", path: "/refresh", json: { refresh_token: "<grant>" } } })).rejects.toThrow(/unknown placeholder/);
    await runContractCase(h, base);
  });

  it("the runner notices a wrong answer", async () => {
    const pollGet = contract.cases.find((c) => c.name === "poll_get")!;
    await expect(runContractCase(h, { ...pollGet, response: { ...pollGet.response, status: 404 } })).rejects.toThrow();
    await expect(runContractCase(h, { ...pollGet, response: { ...pollGet.response, headers: { allow: "GET" } } })).rejects.toThrow();
    await expect(runContractCase(h, { ...pollGet, response: { ...pollGet.response, json: { error: "method_not_allowed" } } })).rejects.toThrow();
    await expect(runContractCase(h, { ...pollGet, response: { ...pollGet.response, json: { error: "not_found", message: "<string>" } } })).rejects.toThrow();
  });

  for (const c of contract.cases) {
    it(`case ${c.name} (given ${c.given})`, async () => {
      await runContractCase(h, c);
    });
  }
});
