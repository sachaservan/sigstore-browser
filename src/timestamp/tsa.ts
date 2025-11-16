/*
 * TSA (Time-Stamping Authority) timestamp verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/tsa.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Uses Web Crypto API for all cryptographic operations
 * - Integrates with existing RFC3161 timestamp implementation
 */

import { RFC3161Timestamp } from "../rfc3161/index.js";
import { X509Certificate } from "../x509/cert.js";
import { bufferEqual } from "../crypto.js";
import { base64ToUint8Array, Uint8ArrayToHex } from "../encoding.js";
import type { RawTimestampAuthority } from "../interfaces.js";

/**
 * Verifies an RFC3161 timestamp against a set of timestamp authorities
 *
 * @param timestamp - The RFC3161 timestamp to verify
 * @param data - The data that was timestamped
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time
 * @throws Error if timestamp cannot be verified
 */
export async function verifyRFC3161Timestamp(
  timestamp: RFC3161Timestamp,
  data: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<Date> {
  const signingTime = timestamp.signingTime;

  // Filter for CAs which were valid at the time of signing
  let validAuthorities = filterCertAuthorities(
    timestampAuthorities,
    signingTime
  );

  // Filter for CAs which match serial and issuer embedded in the timestamp
  validAuthorities = filterCAsBySerialAndIssuer(validAuthorities, {
    serialNumber: timestamp.signerSerialNumber,
    issuer: timestamp.signerIssuer,
  });

  // Check that we can verify the timestamp with AT LEAST ONE of the remaining CAs
  const verificationResults = await Promise.allSettled(
    validAuthorities.map(ca => verifyTimestampForCA(timestamp, data, ca))
  );

  const verified = verificationResults.some(
    result => result.status === "fulfilled"
  );

  if (!verified) {
    const errors = verificationResults
      .filter(r => r.status === "rejected")
      .map(r => (r as PromiseRejectedResult).reason?.message || 'Unknown error');
    throw new Error(`Timestamp could not be verified against any trusted authority. Errors: ${errors.join(', ')}`);
  }

  return signingTime;
}

/**
 * Filters certificate authorities to those valid at a specific time
 */
function filterCertAuthorities(
  authorities: RawTimestampAuthority[],
  validAt: Date
): RawTimestampAuthority[] {
  return authorities.filter(ca => {
    if (ca.validFor) {
      const start = ca.validFor.start ? new Date(ca.validFor.start) : null;
      const end = ca.validFor.end ? new Date(ca.validFor.end) : null;

      if (start && validAt < start) {
        return false;
      }
      if (end && validAt > end) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Filters certificate authorities by serial number and issuer
 */
function filterCAsBySerialAndIssuer(
  timestampAuthorities: RawTimestampAuthority[],
  criteria: { serialNumber: Uint8Array; issuer: Uint8Array }
): RawTimestampAuthority[] {
  return timestampAuthorities.filter(ca => {
    if (!ca.certChain || ca.certChain.certificates.length === 0) {
      return false;
    }

    // Check all certificates in the chain to find the one matching the criteria
    for (let i = 0; i < ca.certChain.certificates.length; i++) {
      const cert = X509Certificate.parse(base64ToUint8Array(ca.certChain.certificates[i].rawBytes));

      // If this certificate matches the criteria, we found the right CA
      if (bufferEqual(cert.serialNumber, criteria.serialNumber) &&
          bufferEqual(cert.issuer, criteria.issuer)) {
        return true;
      }
    }

    return false;
  });
}

/**
 * Verifies a timestamp against a specific certificate authority
 */
async function verifyTimestampForCA(
  timestamp: RFC3161Timestamp,
  data: Uint8Array,
  ca: RawTimestampAuthority
): Promise<void> {
  if (!ca.certChain || ca.certChain.certificates.length === 0) {
    throw new Error("Certificate authority missing certificate chain");
  }

  // Find the certificate that matches the timestamp's signer
  let signingCert: X509Certificate | null = null;
  let signingCertIndex = -1;

  for (let i = 0; i < ca.certChain.certificates.length; i++) {
    const cert = X509Certificate.parse(base64ToUint8Array(ca.certChain.certificates[i].rawBytes));

    if (bufferEqual(cert.serialNumber, timestamp.signerSerialNumber) &&
        bufferEqual(cert.issuer, timestamp.signerIssuer)) {
      signingCert = cert;
      signingCertIndex = i;
      break;
    }
  }

  if (!signingCert) {
    throw new Error("No certificate in chain matches timestamp signer");
  }

  // Verify the certificate chain starting from the signing certificate
  await verifyCertificateChain(signingCert, ca, timestamp.signingTime, signingCertIndex);

  // Get the public key from the signing certificate
  const publicKey = await signingCert.publicKeyObj;

  // Verify the timestamp signature using the existing RFC3161 implementation
  await timestamp.verify(data, publicKey);
}

/**
 * Verifies a certificate chain for TSA certificates
 */
async function verifyCertificateChain(
  signingCert: X509Certificate,
  ca: RawTimestampAuthority,
  validAt: Date,
  startIndex: number
): Promise<void> {
  // Check that the signing certificate was valid at the signing time
  if (!signingCert.validForDate(validAt)) {
    throw new Error("TSA certificate not valid at timestamp signing time");
  }

  // If there are more certificates in the chain, verify up the chain
  if (ca.certChain && startIndex + 1 < ca.certChain.certificates.length) {
    let currentCert = signingCert;

    for (let i = startIndex + 1; i < ca.certChain.certificates.length; i++) {
      const issuerCert = X509Certificate.parse(base64ToUint8Array(ca.certChain.certificates[i].rawBytes));

      // Check that the issuer cert was valid at the signing time
      if (!issuerCert.validForDate(validAt)) {
        throw new Error(`Certificate chain element ${i} not valid at timestamp signing time`);
      }

      // Verify that the current cert was signed by the issuer
      const verified = await currentCert.verify(issuerCert);

      if (!verified) {
        throw new Error(`Certificate chain verification failed at element ${i}`);
      }

      currentCert = issuerCert;
    }
  }
}

/**
 * Extracts the verified timestamp from a bundle's timestamp verification data
 *
 * @param timestampData - The timestamp verification data from the bundle
 * @param signature - The signature being verified
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time, or undefined if no timestamp
 */
export async function verifyBundleTimestamp(
  timestampData: any,
  signature: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<Date | undefined> {
  if (!timestampData?.rfc3161Timestamps?.length) {
    return undefined;
  }

  // Process each RFC3161 timestamp
  const errors: string[] = [];
  for (const tsData of timestampData.rfc3161Timestamps) {
    try {
      // Decode the base64-encoded timestamp
      const timestampBytes = base64ToUint8Array(tsData.signedTimestamp);
      const timestamp = RFC3161Timestamp.parse(timestampBytes);

      const signingTime = await verifyRFC3161Timestamp(
        timestamp,
        signature,
        timestampAuthorities
      );
      return signingTime;
    } catch (e) {
      // Continue to next timestamp if this one fails
      errors.push(e instanceof Error ? e.message : String(e));
      continue;
    }
  }

  throw new Error(`No valid RFC3161 timestamps found. Errors: ${errors.join(', ')}`);
}