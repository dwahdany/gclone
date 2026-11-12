import { describe, expect, it } from "vitest";
import fixture from "./contract.json";
import { CHALLENGE, CHECK_CODE, DEVICE_STATE, EMAIL, GIVEN, PORT, REQUIRED_CASES, VERIFIER, runContractCase, useHarness, type Contract, type ContractCase } from "./helpers";

// worker/test/contract.json is the device ↔ Worker boundary as data. The Rust side (tests/auth.rs) holds its fake
// auth Worker and its client to the same file; here every case is reproduced by the real handle().
const contract = fixture as Contract;
const h = useHarness();

describe("contract.json", () => {
  it("is version 1 and carries the shared test vector", () => {
    expect(Object.keys(contract).sort()).toEqual(["cases", "vector", "version"]);
    expect(contract.version).toBe(1);
    expect(contract.vector).toEqual({ verifier: VERIFIER, challenge: CHALLENGE, state: DEVICE_STATE, port: PORT, check_code: CHECK_CODE, email: EMAIL });
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
    await expect(runContractCase(h, contract, { ...base, given: "moon_phase" })).rejects.toThrow(/unknown given/);
    await expect(runContractCase(h, contract, { ...base, response: { status: 200, body_matches: "x" } as never })).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, contract, { ...base, request: { method: "GET", path: "/", cookies: {} } as never })).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, contract, { ...base, note: "x" } as never)).rejects.toThrow(/unknown key/);
    await expect(runContractCase(h, contract, { ...base, request: { method: "GET", path: "/", query: { a: "<nonce>" } } })).rejects.toThrow(/unknown placeholder/);
    await runContractCase(h, contract, base);
  });

  it("the runner notices a wrong answer", async () => {
    const tokenGet = contract.cases.find((c) => c.name === "token_get")!;
    await expect(runContractCase(h, contract, { ...tokenGet, response: { ...tokenGet.response, status: 404 } })).rejects.toThrow();
    await expect(runContractCase(h, contract, { ...tokenGet, response: { ...tokenGet.response, headers: { allow: "GET" } } })).rejects.toThrow();
    await expect(runContractCase(h, contract, { ...tokenGet, response: { ...tokenGet.response, json: { error: "method_not_allowed" } } })).rejects.toThrow();
    await expect(runContractCase(h, contract, { ...tokenGet, response: { ...tokenGet.response, location: "http://.+" } })).rejects.toThrow();
    await expect(runContractCase(h, contract, { ...tokenGet, response: { ...tokenGet.response, body_contains: ["no such text"] } })).rejects.toThrow();
  });

  for (const c of contract.cases) {
    it(`case ${c.name} (given ${c.given})`, async () => {
      await runContractCase(h, contract, c);
    });
  }
});
