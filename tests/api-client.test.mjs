import assert from "node:assert/strict";
import test from "node:test";

import {
  GatewayApiError,
  apiRequest,
  getSystemLogs,
  getXrayLogs,
  isUncertainOperationError,
} from "../app/api-client.ts";

const originalFetch = globalThis.fetch;

globalThis.window = {
  clearTimeout,
  setTimeout,
  sessionStorage: {
    getItem() {
      return null;
    },
    removeItem() {},
    setItem() {},
  },
};

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("turns an HTML 502 proxy page into a bounded operational error", async () => {
  let requests = 0;
  globalThis.fetch = async () => {
    requests += 1;
    return new Response("<html><body><h1>502 Bad Gateway</h1></body></html>", {
      status: 502,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  };

  await assert.rejects(
    apiRequest("/drafts/apply", { method: "POST", body: "{}", retries: 3 }),
    (error) => {
      assert.ok(error instanceof GatewayApiError);
      assert.equal(error.status, 502);
      assert.equal(error.code, "upstream_unavailable");
      assert.match(error.message, /потерял связь с локальным control plane/i);
      assert.doesNotMatch(error.message, /<html|Bad Gateway/i);
      return true;
    },
  );
  assert.equal(requests, 1, "a mutation must never be retried automatically");
});

test("classifies proxy failures as uncertain without retrying the mutation", () => {
  assert.equal(
    isUncertainOperationError(
      new GatewayApiError("proxy unavailable", {
        status: 503,
        code: "upstream_unavailable",
      }),
    ),
    true,
  );
  assert.equal(
    isUncertainOperationError(
      new GatewayApiError("validation failed", {
        status: 422,
        code: "validation_failed",
      }),
    ),
    false,
  );
});

test("Xray log requests expose only a bounded tail selector", async () => {
  let requestedURL = "";
  globalThis.fetch = async (url) => {
    requestedURL = String(url);
    return new Response(JSON.stringify({ lines: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await getXrayLogs("process", 50_000);
  assert.equal(requestedURL, "/api/v1/runtime/xray-logs?source=process&lines=500");
});

test("system log requests expose only a bounded fixed source", async () => {
  let requestedURL = "";
  globalThis.fetch = async (url) => {
    requestedURL = String(url);
    return new Response(JSON.stringify({ lines: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await getSystemLogs("lifecycle", 50_000);
  assert.equal(requestedURL, "/api/v1/runtime/system-logs?source=lifecycle&lines=500");
});
