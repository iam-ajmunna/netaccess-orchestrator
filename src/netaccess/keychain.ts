/**
 * NetAccess macOS Native Keychain Credential Provider
 * 
 * Implements CredentialStore backed by macOS Keychain Services via /usr/bin/security.
 * Enforces the Secret Lifetime Contract:
 * - Plaintext credentials exist strictly in ephemeral memory buffers
 * - References are parsed and strictly validated before invoking /usr/bin/security
 * - Tolerant status/stderr inspection distinguishing missing items vs permission/system errors
 * - MemoryCredentialStore fallback for isolated testing and non-macOS platforms
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const KEYCHAIN_SERVICE_NAME = "netaccess.orchestrator";
export const SECRET_REF_PREFIX = "keychain://netaccess/";
const TRANSPORT_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;
const SECRET_REF_REGEX = /^keychain:\/\/netaccess\/([a-zA-Z0-9_-]{1,64})$/;

// ---------------------------------------------------------------------------
// Typed Errors
// ---------------------------------------------------------------------------

export class InvalidSecretRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSecretRefError";
  }
}

export class KeychainPermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeychainPermissionError";
  }
}

export class KeychainOperationError extends Error {
  public exitCode?: number;
  constructor(message: string, exitCode?: number) {
    super(message);
    this.name = "KeychainOperationError";
    this.exitCode = exitCode;
  }
}

export class KeychainDeletionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeychainDeletionError";
  }
}

// ---------------------------------------------------------------------------
// Reference Validation & Formatting
// ---------------------------------------------------------------------------

/**
 * Validates a transportId and returns the canonical secretRef URL
 */
export function formatSecretRef(transportId: string): string {
  if (!transportId || !TRANSPORT_ID_REGEX.test(transportId)) {
    throw new InvalidSecretRefError(
      `Invalid transportId for secretRef: "${transportId}". Must match ${TRANSPORT_ID_REGEX}.`,
    );
  }
  return `${SECRET_REF_PREFIX}${transportId}`;
}

/**
 * Validates a secretRef string and extracts the transportId account name
 * Rejects path traversal, malformed schemes, whitespace, or control characters.
 */
export function parseAndValidateSecretRef(secretRef: string): string {
  if (typeof secretRef !== "string" || !secretRef) {
    throw new InvalidSecretRefError("Secret reference must be a non-empty string.");
  }

  const match = secretRef.match(SECRET_REF_REGEX);
  if (!match) {
    throw new InvalidSecretRefError(
      `Invalid secretRef format "${secretRef}". Must match format "${SECRET_REF_PREFIX}<transportId>".`,
    );
  }

  const transportId = match[1];
  if (!TRANSPORT_ID_REGEX.test(transportId) || transportId.includes("..") || transportId.includes("/")) {
    throw new InvalidSecretRefError(`Invalid transport ID in secretRef: "${transportId}".`);
  }

  return transportId;
}

// ---------------------------------------------------------------------------
// CredentialStore Interface
// ---------------------------------------------------------------------------

export interface CredentialStore {
  getSecret(ref: string): Promise<string | null>;
  setSecret(ref: string, secret: string): Promise<void>;
  deleteSecret(ref: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// MacOSKeychainStore
// ---------------------------------------------------------------------------

export class MacOSKeychainStore implements CredentialStore {
  private securityBin: string;
  private service: string;

  constructor(opts: { securityBin?: string; service?: string } = {}) {
    this.securityBin = opts.securityBin ?? "/usr/bin/security";
    this.service = opts.service ?? KEYCHAIN_SERVICE_NAME;
  }

  public async setSecret(ref: string, secret: string): Promise<void> {
    const account = parseAndValidateSecretRef(ref);
    if (typeof secret !== "string" || secret.length === 0) {
      throw new KeychainOperationError("Secret value must be a non-empty string.");
    }

    // Command: security add-generic-password -a <account> -s <service> -w <secret> -U
    const args = ["add-generic-password", "-a", account, "-s", this.service, "-w", secret, "-U"];

    try {
      await execFileAsync(this.securityBin, args, {
        encoding: "utf8",
        timeout: 5000,
      });
    } catch (err: unknown) {
      const execErr = err as { code?: number; stderr?: string; message?: string };
      const stderr = execErr.stderr ?? execErr.message ?? "";

      if (/User interaction is not allowed|denied/i.test(stderr)) {
        throw new KeychainPermissionError(`macOS Keychain access denied for account "${account}": ${stderr.trim()}`);
      }
      throw new KeychainOperationError(
        `Failed to store secret in macOS Keychain for account "${account}": ${stderr.trim()}`,
        execErr.code,
      );
    }
  }

  public async getSecret(ref: string): Promise<string | null> {
    const account = parseAndValidateSecretRef(ref);

    // Command: security find-generic-password -a <account> -s <service> -w
    const args = ["find-generic-password", "-a", account, "-s", this.service, "-w"];

    try {
      const { stdout } = await execFileAsync(this.securityBin, args, {
        encoding: "utf8",
        timeout: 5000,
      });
      return stdout.replace(/\r?\n$/, "");
    } catch (err: unknown) {
      const execErr = err as { code?: number; stderr?: string; message?: string };
      const stderr = execErr.stderr ?? execErr.message ?? "";
      const code = execErr.code;

      // Tolerant item-not-found check: exit code 44 or stderr matching item-not-found
      if (
        code === 44 ||
        /The specified item could not be found in the keychain/i.test(stderr) ||
        /SecKeychainSearchCopyNext/i.test(stderr)
      ) {
        return null;
      }

      if (/User interaction is not allowed|denied/i.test(stderr)) {
        throw new KeychainPermissionError(`macOS Keychain permission denied for account "${account}": ${stderr.trim()}`);
      }

      throw new KeychainOperationError(
        `Failed to retrieve secret from macOS Keychain for account "${account}": ${stderr.trim()}`,
        code,
      );
    }
  }

  public async deleteSecret(ref: string): Promise<boolean> {
    const account = parseAndValidateSecretRef(ref);

    // Command: security delete-generic-password -a <account> -s <service>
    const args = ["delete-generic-password", "-a", account, "-s", this.service];

    try {
      await execFileAsync(this.securityBin, args, {
        encoding: "utf8",
        timeout: 5000,
      });
      return true;
    } catch (err: unknown) {
      const execErr = err as { code?: number; stderr?: string; message?: string };
      const stderr = execErr.stderr ?? execErr.message ?? "";
      const code = execErr.code;

      // If item was already absent, treat as successful idempotent deletion
      if (
        code === 44 ||
        /The specified item could not be found in the keychain/i.test(stderr) ||
        /SecKeychainSearchCopyNext/i.test(stderr)
      ) {
        return false;
      }

      if (/User interaction is not allowed|denied/i.test(stderr)) {
        throw new KeychainPermissionError(`macOS Keychain delete permission denied for account "${account}": ${stderr.trim()}`);
      }

      throw new KeychainDeletionError(
        `Failed to delete secret from macOS Keychain for account "${account}": ${stderr.trim()}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// MemoryCredentialStore (Isolated Test & Non-Darwin Fallback)
// ---------------------------------------------------------------------------

export class MemoryCredentialStore implements CredentialStore {
  private secrets = new Map<string, string>();

  public async setSecret(ref: string, secret: string): Promise<void> {
    const account = parseAndValidateSecretRef(ref);
    if (typeof secret !== "string" || secret.length === 0) {
      throw new KeychainOperationError("Secret value must be a non-empty string.");
    }
    this.secrets.set(account, secret);
  }

  public async getSecret(ref: string): Promise<string | null> {
    const account = parseAndValidateSecretRef(ref);
    return this.secrets.get(account) ?? null;
  }

  public async deleteSecret(ref: string): Promise<boolean> {
    const account = parseAndValidateSecretRef(ref);
    return this.secrets.delete(account);
  }

  public clear(): void {
    this.secrets.clear();
  }
}

// ---------------------------------------------------------------------------
// Default CredentialStore Factory
// ---------------------------------------------------------------------------

let defaultStoreInstance: CredentialStore | null = null;

export function getDefaultCredentialStore(): CredentialStore {
  if (defaultStoreInstance) {
    return defaultStoreInstance;
  }

  if (process.env.NETACCESS_USE_MEMORY_KEYCHAIN === "1" || process.platform !== "darwin") {
    defaultStoreInstance = new MemoryCredentialStore();
  } else {
    defaultStoreInstance = new MacOSKeychainStore();
  }

  return defaultStoreInstance;
}

export function resetDefaultCredentialStore(): void {
  defaultStoreInstance = null;
}
