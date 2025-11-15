import { ASN1Obj } from "./asn1/index.js";
import {
  base64ToUint8Array,
  hexToUint8Array,
  toArrayBuffer,
} from "./encoding.js";
import { EcdsaTypes, HashAlgorithms, KeyTypes } from "./interfaces.js";
import { toDER } from "./pem.js";

// Convert PKCS#1 RSAPublicKey to SPKI format
function pkcs1ToSpki(pkcs1Bytes: Uint8Array): Uint8Array {
  // RSA algorithm identifier: SEQUENCE { OID rsaEncryption, NULL }
  // OID 1.2.840.113549.1.1.1 (rsaEncryption) = 06 09 2a 86 48 86 f7 0d 01 01 01
  const algorithmIdentifier = new Uint8Array([
    0x30, 0x0d, // SEQUENCE (13 bytes)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
    0x05, 0x00  // NULL
  ]);

  // The PKCS#1 key needs to be wrapped in a BIT STRING
  const bitStringHeader = new Uint8Array([0x03]); // BIT STRING tag
  const bitStringLength = pkcs1Bytes.length + 1; // +1 for unused bits byte
  const unusedBits = new Uint8Array([0x00]); // no unused bits

  // Calculate total length for the outer SEQUENCE
  const totalContentLength = algorithmIdentifier.length + 1 + lengthBytes(bitStringLength).length + bitStringLength;

  // Build the complete SPKI structure
  const result = new Uint8Array(1 + lengthBytes(totalContentLength).length + totalContentLength);
  let offset = 0;

  // Outer SEQUENCE
  result[offset++] = 0x30; // SEQUENCE tag
  const totalLengthBytes = lengthBytes(totalContentLength);
  result.set(totalLengthBytes, offset);
  offset += totalLengthBytes.length;

  // Algorithm identifier
  result.set(algorithmIdentifier, offset);
  offset += algorithmIdentifier.length;

  // BIT STRING with PKCS#1 key
  result[offset++] = 0x03; // BIT STRING tag
  const bitStringLengthBytes = lengthBytes(bitStringLength);
  result.set(bitStringLengthBytes, offset);
  offset += bitStringLengthBytes.length;
  result[offset++] = 0x00; // unused bits
  result.set(pkcs1Bytes, offset);

  return result;
}

// Helper to encode ASN.1 length
function lengthBytes(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  } else if (length < 256) {
    return new Uint8Array([0x81, length]);
  } else {
    // For lengths requiring 2 bytes
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
}

export async function importKey(
  keytype: string,
  scheme: string,
  key: string,
): Promise<CryptoKey> {
  // Debug logging
  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Importing key: keytype=${keytype}, scheme=${scheme}, keyLen=${key.length}`);
    if (keytype.toLowerCase().includes("pkcs1")) {
      console.error(`RSA key first 50 chars: ${key.substring(0, 50)}`);
    }
  }

  class importParams {
    format: "raw" | "spki" = "spki";
    keyData: ArrayBuffer = new ArrayBuffer(0);
    algorithm: RsaHashedImportParams | EcKeyImportParams | Algorithm = { name: "ECDSA" };
    extractable: boolean = true;
    usage: Array<KeyUsage> = ["verify"];
  }

  const params = new importParams();
  // Let's try to detect the encoding
  if (key.includes("BEGIN")) {
    // If it has a begin then it is a PEM
    params.format = "spki";
    params.keyData = toArrayBuffer(toDER(key));
  } else if (/^[0-9A-Fa-f]+$/.test(key)) {
    // Is it hex?
    params.format = "raw";
    params.keyData = toArrayBuffer(hexToUint8Array(key));
  } else {
    // It might be base64, without the PEM header, as in sigstore trusted_root
    params.format = "spki";
    const keyBytes = base64ToUint8Array(key);

    // Check if it's a PKCS#1 RSA key (starts with SEQUENCE then large INTEGER for modulus)
    // PKCS#1 RSAPublicKey starts with 30 82 XX XX 02 82
    if (keytype.toLowerCase().includes("pkcs1") &&
        keyBytes[0] === 0x30 && keyBytes[1] === 0x82 &&
        keyBytes[4] === 0x02 && keyBytes[5] === 0x82) {
      // Convert PKCS#1 to SPKI
      if (process.env.DEBUG_SIGSTORE) {
        console.error('Converting PKCS#1 RSAPublicKey to SPKI format');
      }
      params.keyData = toArrayBuffer(pkcs1ToSpki(keyBytes));
    } else {
      params.keyData = toArrayBuffer(keyBytes);
    }
  }

  // Let's see supported key types
  if (keytype.toLowerCase().includes("ecdsa")) {
    // Let'd find out the key size, and retrieve the proper naming for crypto.subtle
    if (scheme.includes("256") || scheme === "secp256r1") {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P256 };
    } else if (scheme.includes("384") || scheme === "secp384r1") {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P384 };
    } else if (scheme.includes("521") || scheme === "secp521r1") {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P521 };
    } else {
      if (process.env.DEBUG_SIGSTORE) {
        console.error(`Cannot determine ECDSA key size for scheme: ${scheme}`);
      }
      throw new Error(`Cannot determine ECDSA key size for scheme: ${scheme}`);
    }
  } else if (keytype.toLowerCase().includes("ed25519")) {
    // Ed2559 eys can be only one size, we do not need more info
    params.algorithm = { name: "Ed25519" };
  } else if (keytype.toLowerCase().includes("rsa") || keytype.toLowerCase().includes("pkcs1")) {
    // RSA support for CT logs and checkpoints
    // Check scheme to determine which RSA algorithm to use
    if (scheme.includes("PKCS1") || scheme.includes("RSA_PKCS1")) {
      // CT logs use RSASSA-PKCS1-v1_5
      params.algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      };
    } else {
      // Checkpoints and other uses might use RSA-PSS
      params.algorithm = {
        name: "RSA-PSS",
        hash: { name: "SHA-256" },
      };
    }
  } else {
    throw new Error(`Unsupported ${keytype}`);
  }

  try {
    if (process.env.DEBUG_SIGSTORE) {
      console.error(`About to import key: format=${params.format}, algorithm=${JSON.stringify(params.algorithm)}`);
    }
    return await crypto.subtle.importKey(
      params.format,
      params.keyData,
      params.algorithm,
      params.extractable,
      params.usage,
    );
  } catch (e) {
    if (process.env.DEBUG_SIGSTORE) {
      console.error(`Key import failed: format=${params.format}, algorithm=${JSON.stringify(params.algorithm)}`);
      console.error(`Error: ${e}`);
    }
    throw e;
  }
}

export async function verifySignature(
  key: CryptoKey,
  signed: Uint8Array,
  sig: Uint8Array,
  hash: string = "sha256",
): Promise<boolean> {
  if (process.env.DEBUG_SIGSTORE) {
    console.error(`verifySignature called with key algorithm: ${JSON.stringify(key.algorithm)}, hash: ${hash}`);
  }

  const options: {
    name: string;
    hash?: {
      name: string;
    };
  } = {
    name: key.algorithm.name,
  };

  if (key.algorithm.name === KeyTypes.Ecdsa) {
    // Later we need to supply exactly sized R and R dependingont he curve for sig verification
    const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
    let sig_size = 32;

    if (namedCurve === "P-256") {
      sig_size = 32;
    } else if (namedCurve === "P-384") {
      sig_size = 48;
    } else if (namedCurve === "P-521") {
      sig_size = 66;
    }

    options.hash = { name: "" };
    // Then we need to select an hashing algorithm
    if (hash.includes("256")) {
      options.hash.name = HashAlgorithms.SHA256;
    } else if (hash.includes("384")) {
      options.hash.name = HashAlgorithms.SHA384;
    } else if (hash.includes("512")) {
      options.hash.name = HashAlgorithms.SHA512;
    } else {
      throw new Error("Cannot determine hashing algorithm;");
    }

    // For posterity: this mess is because the web crypto API supports only
    // IEEE P1363, so we etract r and s from the DER sig and manually ancode
    // big endian and append them one after each other

    // The verify option will do hashing internally
    // const signed_digest = await crypto.subtle.digest(hash_alg, signed)
    let raw_signature: Uint8Array;
    try {
      const asn1_sig = ASN1Obj.parseBuffer(sig);
      const r = asn1_sig.subs[0].toInteger();
      const s = asn1_sig.subs[1].toInteger();
      // Sometimes the integers can be less than the average, and we would miss bytes. The functione expects a finxed
      // input in bytes depending on the curve, or it fails early.
      const binr = hexToUint8Array(r.toString(16).padStart(sig_size * 2, "0"));
      const bins = hexToUint8Array(s.toString(16).padStart(sig_size * 2, "0"));
      raw_signature = new Uint8Array(binr.length + bins.length);
      raw_signature.set(binr, 0);
      raw_signature.set(bins, binr.length);
    } catch {
      // Signature is probably malformed
      return false;
    }

    if (process.env.DEBUG_SIGSTORE) {
      console.error(`About to verify ECDSA signature with options: ${JSON.stringify(options)}`);
    }

    try {
      return await crypto.subtle.verify(
        options,
        key,
        toArrayBuffer(raw_signature),
        toArrayBuffer(signed),
      );
    } catch (e) {
      if (process.env.DEBUG_SIGSTORE) {
        console.error(`ECDSA verify failed: ${e}`);
      }
      throw e;
    }
  } else if (key.algorithm.name === KeyTypes.Ed25519) {
    return await crypto.subtle.verify(
      key.algorithm.name,
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === "RSA-PSS") {
    // RSA-PSS signature verification
    const saltLength = 32; // SHA-256 output length
    return await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: saltLength,
      },
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === "RSASSA-PKCS1-v1_5") {
    // RSASSA-PKCS1-v1_5 signature verification (used by CT logs)
    return await crypto.subtle.verify(
      key.algorithm.name,
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else {
    throw new Error("Unsupported key type!");
  }
}

export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
