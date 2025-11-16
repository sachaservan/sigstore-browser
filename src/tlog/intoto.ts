/*
 * Intoto transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/intoto.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle field comparison instead of SignatureContent abstraction
 * - Uses crypto.subtle.digest for hash computation instead of Node.js crypto
 * - Handles double-base64 encoding using our base64Decode utility
 */

import { base64Decode, base64ToUint8Array, hexToUint8Array, toArrayBuffer, uint8ArrayEqual } from "../encoding.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

interface IntotoEnvelope {
  payload: string;
  payloadType: string;
  signatures: Array<{
    keyid?: string;
    sig: string;
    publicKey?: string;
  }>;
}

interface IntotoSpec {
  content: {
    envelope: IntotoEnvelope;
    hash?: {
      algorithm: string;
      value: string;
    };
    payloadHash?: {
      algorithm: string;
      value: string;
    };
  };
  publicKey?: string;
}

interface IntotoEntry extends RekorEntry {
  apiVersion: "0.0.2";
  kind: "intoto";
  spec: IntotoSpec;
}

export async function verifyIntotoBody(
  entry: RekorEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const intotoEntry = entry as IntotoEntry;

  if (intotoEntry.apiVersion !== "0.0.2") {
    throw new Error(
      `Unsupported intoto version: ${intotoEntry.apiVersion}`
    );
  }

  if (!bundle.dsseEnvelope) {
    throw new Error("Bundle missing dsseEnvelope for intoto entry");
  }

  const tlogEnvelope = intotoEntry.spec.content.envelope;

  if (!tlogEnvelope.signatures || tlogEnvelope.signatures.length !== 1) {
    throw new Error("Intoto entry must have exactly one signature");
  }

  const tlogSigBase64 = tlogEnvelope.signatures[0].sig;
  const tlogSigDecoded = base64Decode(tlogSigBase64);
  const tlogSigBytes = base64ToUint8Array(tlogSigDecoded);

  if (bundle.dsseEnvelope.signatures.length === 0) {
    throw new Error("Bundle DSSE envelope missing signatures");
  }

  const bundleSigBytes = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Intoto signature mismatch between TLog entry and bundle");
  }

  if (intotoEntry.spec.content.payloadHash) {
    const tlogHash = intotoEntry.spec.content.payloadHash.value;
    const tlogHashBytes = hexToUint8Array(tlogHash);

    const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
    const bundleHashBytes = new Uint8Array(
      await crypto.subtle.digest("SHA-256", toArrayBuffer(payloadBytes))
    );

    if (!uint8ArrayEqual(tlogHashBytes, bundleHashBytes)) {
      throw new Error("Intoto payload hash mismatch between TLog entry and bundle");
    }
  }
}
