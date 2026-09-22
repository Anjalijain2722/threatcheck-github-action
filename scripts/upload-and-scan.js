#!/usr/bin/env node
/**
 * ThreatCheck upload-and-scan flow, per the official build spec (v1.0, 21 Sep 2026).
 * Three API calls and one file transfer, in a fixed order:
 *   1. Presign  - POST {baseUrl}/v1/products/{productId}/firmware
 *   2. Upload   - block upload straight to Azure Blob Storage (does NOT use the API token)
 *   3. Complete - POST {baseUrl}/v1/products/{productId}/versions/{productVersionId}/uploaded
 *
 * Exits as soon as step 3 responds. Does not poll, does not wait for scan results, does not
 * fail the workflow based on findings - all explicitly out of scope per the spec.
 *
 * Security: the presigned uploadUrl and the API token are never logged, printed, or written
 * to GITHUB_OUTPUT - both are credentials. Only ids and status values are surfaced.
 */

const fs = require("fs");
const path = require("path");

const BLOCK_SIZE = 8 * 1024 * 1024; // 8 MiB, matches the portal implementation
const MAX_BLOCK_RETRIES = 3;
const MAX_GATEWAY_RETRIES = 3;

function fail(message) {
  console.log(`ThreatCheck: ${message}`);
  console.log(`::error::${message}`);
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function appendOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  }
}

function formatSize(bytes) {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Fixed-width block id: base64("block-" + zeroPad(index, 6)). Width MUST be consistent
 *  across all blocks or Azure rejects the commit - see spec section 5. */
function blockId(index) {
  const padded = String(index).padStart(6, "0");
  return Buffer.from(`block-${padded}`, "utf8").toString("base64");
}

async function extractServerMessage(response) {
  try {
    const body = await response.json();
    if (body && typeof body.message === "string") return body.message;
    if (body && body.error) {
      return typeof body.error === "string" ? body.error : JSON.stringify(body.error);
    }
    return JSON.stringify(body);
  } catch {
    return await response.text().catch(() => "(no response body)");
  }
}

/** Maps HTTP status to the exact behaviour the spec requires (section 7). */
async function requireSuccess(response, action) {
  if (response.ok) return;
  const serverMessage = await extractServerMessage(response);
  const status = response.status;
  if (status === 401) {
    fail(`token rejected while trying to ${action} (401): ${serverMessage}. This will not be retried.`);
  } else if (status === 403) {
    fail(`permission denied to ${action} (403): ${serverMessage}`);
  } else if (status === 404) {
    fail(`product/release not found while trying to ${action} (404): ${serverMessage}`);
  } else if (status === 400) {
    fail(`request rejected while trying to ${action} (400): ${serverMessage}`);
  } else if (status === 409) {
    fail(`already in progress or already exists (409) while trying to ${action}: ${serverMessage}`);
  } else {
    fail(`failed to ${action}: HTTP ${status} - ${serverMessage}`);
  }
}

/** Retries 429 (rate limit) and 503 (storage unavailable) with backoff, per spec section 7. */
async function fetchWithGatewayRetry(url, options) {
  let lastResponse = null;
  for (let attempt = 1; attempt <= MAX_GATEWAY_RETRIES; attempt++) {
    const response = await fetch(url, options);
    if (response.status === 429 || response.status === 503) {
      lastResponse = response;
      await sleep(1000 * attempt);
      continue;
    }
    return response;
  }
  return lastResponse;
}

// --- Step 1: Presign ---------------------------------------------------------------------

async function presignUpload(baseUrl, apiToken, productId, version, fileName, contentType, sizeBytes) {
  const response = await fetchWithGatewayRetry(`${baseUrl}/v1/products/${productId}/firmware`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ version, fileName, contentType, sizeBytes }),
  });
  await requireSuccess(response, "presign upload");
  const json = await response.json();
  return json.data;
}

// --- Step 2: Upload to blob storage (block upload, per spec section 5) -------------------

async function putBlockWithRetry(uploadUrl, id, chunk) {
  const separator = uploadUrl.includes("?") ? "&" : "?";
  const url = `${uploadUrl}${separator}comp=block&blockid=${encodeURIComponent(id)}`;

  let lastError = null;
  for (let attempt = 1; attempt <= MAX_BLOCK_RETRIES; attempt++) {
    try {
      // Per spec: send NO headers on a block PUT - the blob doesn't exist yet, and
      // x-ms-blob-type/Content-Type on this call make Azure return 400.
      const response = await fetch(url, { method: "PUT", body: chunk });
      if (response.ok) return;
      lastError = new Error(`Block upload failed: HTTP ${response.status}`);
    } catch (e) {
      lastError = e;
    }
    await sleep(500 * attempt); // short escalating backoff, per spec
  }
  throw lastError;
}

async function uploadBlocks(uploadUrl, fileBuffer) {
  const blockIds = [];
  const totalBytes = fileBuffer.length;
  const blockCount = Math.max(1, Math.ceil(totalBytes / BLOCK_SIZE));

  for (let index = 0; index < blockCount; index++) {
    const start = index * BLOCK_SIZE;
    const end = Math.min(start + BLOCK_SIZE, totalBytes);
    const chunk = fileBuffer.subarray(start, end);
    const id = blockId(index);
    await putBlockWithRetry(uploadUrl, id, chunk);
    blockIds.push(id);
  }
  return blockIds;
}

async function commitBlockList(uploadUrl, blockIds, contentType) {
  const xml =
    '<?xml version="1.0" encoding="utf-8"?><BlockList>' +
    blockIds.map((id) => `<Latest>${id}</Latest>`).join("") +
    "</BlockList>";

  const separator = uploadUrl.includes("?") ? "&" : "?";
  const url = `${uploadUrl}${separator}comp=blocklist`;

  // x-ms-blob-content-type here is what the blob is actually stored as - must equal the
  // contentType declared at presign, or step 3 rejects the upload with a 409.
  const response = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/xml",
      "x-ms-blob-content-type": contentType,
    },
    body: xml,
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    fail(`failed to commit block list: HTTP ${response.status} - ${text}`);
  }
}

// --- Step 3: Complete (this starts the scan) ----------------------------------------------

async function completeUpload(baseUrl, apiToken, productId, productVersionId, uploadId) {
  // Strict schema per spec: uploadId only.
  const response = await fetchWithGatewayRetry(
    `${baseUrl}/v1/products/${productId}/versions/${productVersionId}/uploaded`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ uploadId }),
    }
  );
  await requireSuccess(response, "complete upload");
  const json = await response.json();
  return json.data;
}

// --- Main ------------------------------------------------------------------------------

async function main() {
  const baseUrl = (process.env.THREATCHECK_BASE_URL || "").replace(/\/$/, "");
  const apiToken = process.env.THREATCHECK_API_TOKEN;
  const productId = process.env.THREATCHECK_PRODUCT_ID;
  const artifactPath = process.env.THREATCHECK_ARTIFACT_PATH;
  const contentType = process.env.THREATCHECK_CONTENT_TYPE || "application/octet-stream";
  const version = (process.env.THREATCHECK_VERSION || "").trim() || process.env.GITHUB_RUN_NUMBER || "unknown";

  if (!baseUrl) fail("base-url is required (no default - see spec section 9)");
  if (!apiToken) fail("api-token is required");
  if (!productId) fail("product-id is required");
  if (!artifactPath) fail("artifact-path is required");

  if (!fs.existsSync(artifactPath)) {
    fail(`artifact not found at '${artifactPath}'. Check artifact-path is correct and relative to the workspace.`);
  }

  const fileBuffer = fs.readFileSync(artifactPath);
  const fileName = path.basename(artifactPath);

  console.log(`ThreatCheck: uploading ${artifactPath} (${formatSize(fileBuffer.length)}) to product ${productId}`);

  const presign = await presignUpload(baseUrl, apiToken, productId, version, fileName, contentType, fileBuffer.length);
  const { productVersionId, productScanId, uploadId, uploadUrl } = presign;
  // uploadUrl is a credential (write-only SAS) - held only in this local variable, never logged.

  const blockIds = await uploadBlocks(uploadUrl, fileBuffer);
  await commitBlockList(uploadUrl, blockIds, contentType);
  console.log(`ThreatCheck: upload ${uploadId} committed in ${blockIds.length} block(s)`);

  const completed = await completeUpload(baseUrl, apiToken, productId, productVersionId, uploadId);
  const status = completed.status || "unknown";
  console.log(`ThreatCheck: scan ${productScanId} queued for release ${version} (status: ${status})`);

  appendOutput("product-scan-id", productScanId);
  appendOutput("product-version-id", productVersionId);
  appendOutput("upload-id", uploadId);
  appendOutput("status", status);
}

main().catch((err) => {
  fail(err && err.message ? err.message : String(err));
});
