import { describe, it, expect } from "vitest";
import { makePassport } from "../src/passport";

const base = {
  agentId: "a",
  agentName: "n",
  payload: { k: 1 },
};

describe("eventType validation", () => {
  it.each(["commit", "acme.risk_review", "tool_call"])("accepts %s", (eventType) => {
    const p = makePassport({ ...base, eventType });
    expect(p.event.type).toBe(eventType);
  });

  it.each(["", "Not A Type", ".leading_dot", "trailing.", "UPPER", "9start", "commit\n"])(
    "rejects %j",
    (eventType) => {
      expect(() => makePassport({ ...base, eventType })).toThrow(/eventType/);
    }
  );
});
