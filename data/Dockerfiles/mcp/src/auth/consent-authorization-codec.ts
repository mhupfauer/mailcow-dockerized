import { createHash } from "node:crypto";

import type { CredentialVault } from "./crypto-vault.js";
import { MCP_OAUTH_SCOPES } from "./oidc-provider.js";

const allowedScopes = new Set<string>(MCP_OAUTH_SCOPES);
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const proofPattern = /^[A-Za-z0-9_-]{32,256}$/u;
const digestPattern = /^[A-Za-z0-9_-]{43}$/u;
const bridgeEnvelopePattern = /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/u;
const maximumBridgeEnvelopeLength = 4_096;
const maximumStoredRetiredBridges = 1_024;

export type ConsentLifecycle =
  | "pending_reauth"
  | "active"
  | "cleanup_pending"
  | "cleanup_finalizing"
  | "quarantined"
  | "revoked";

export interface ReauthenticationBridge {
  proof: string;
  authorizationEpoch: string;
  expiresAt: number;
  bindingEnvelope: string;
}

export interface ReauthenticationBridgeClaims {
  proof: string;
  authorizationEpoch: string;
  expiresAt: number;
}

export interface VerifiedReauthenticationBridge {
  fingerprint: string;
  authorizationEpoch: string;
  authorizationGeneration: string;
  expiresAt: number;
}

export interface RetiredReauthenticationBridge {
  fingerprint: string;
  expiresAt: number;
}

export interface PendingReauthenticationAuthority {
  bridgeFingerprint: string;
  authorizationEpoch: string;
  sessionUid: string;
  expiresAt: number;
}

interface StoredConsentV2 {
  version: 2;
  lifecycle: ConsentLifecycle;
  scopes: string[];
  authorityEnvelope: string;
}

interface ConsentAuthorityV2 {
  version: 2;
  lifecycle: ConsentLifecycle;
  clientId: string;
  resource: string;
  scopes: string[];
  authorizationGeneration?: string;
  grantId?: string;
  sessionIds: string[];
  pendingReauthentication?: PendingReauthenticationAuthority;
  retiredReauthenticationBridges?: RetiredReauthenticationBridge[];
  consumedProofDigest?: string;
  cleanupReturnTo?: string;
  evidence?: string;
}

interface ConsentAuthorityV1 {
  version: 1;
  clientId: string;
  grantId: string;
  sessionIds: string[];
}

interface ReauthenticationBridgeBindingV2 {
  version: 2;
  accountId: string;
  clientId: string;
  resource: string;
  proof: string;
  authorizationEpoch: string;
  authorizationGeneration: string;
  expiresAt: number;
}

export interface EncodedConsentRow {
  clientId: string;
  value: string;
  accountActive: number;
}

export interface ConsentAuthorizationState {
  lifecycle: ConsentLifecycle;
  clientId: string;
  resource?: string;
  scopes: string[];
  authorizationGeneration?: string;
  grantId?: string;
  sessionIds: string[];
  accountActive: boolean;
  pendingReauthentication?: {
    sessionUid: string;
    expiresAt: number;
  };
  pendingBridgeFingerprint?: string;
  pendingAuthorizationEpoch?: string;
  retiredReauthenticationBridges?: RetiredReauthenticationBridge[];
  consumedProofDigest?: string;
  cleanupReturnTo?: string;
  quarantineEvidence?: string;
  needsQuarantine?: boolean;
}

export interface ConsentSealOptions {
  pending?: PendingReauthenticationAuthority;
  consumedProofDigest?: string;
  evidence?: string;
}

export function validAccountId(accountId: string): boolean {
  return uuidPattern.test(accountId);
}

export function validReauthenticationBridge(
  bridge: ReauthenticationBridge,
): boolean {
  return (
    proofPattern.test(bridge.proof) &&
    bridge.authorizationEpoch !== "" &&
    Number.isSafeInteger(bridge.expiresAt) &&
    bridge.expiresAt > 0 &&
    typeof bridge.bindingEnvelope === "string" &&
    bridge.bindingEnvelope.length <= maximumBridgeEnvelopeLength &&
    bridgeEnvelopePattern.test(bridge.bindingEnvelope)
  );
}

function normalizeScopes(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    !value.every(
      (scope) => typeof scope === "string" && allowedScopes.has(scope),
    )
  ) {
    return null;
  }
  return [...new Set(value)].sort();
}

function validLifecycle(value: unknown): value is ConsentLifecycle {
  return (
    value === "pending_reauth" ||
    value === "active" ||
    value === "cleanup_pending" ||
    value === "cleanup_finalizing" ||
    value === "quarantined" ||
    value === "revoked"
  );
}

function authorityRecordType(clientId: string): string {
  const clientHash = createHash("sha256")
    .update(clientId, "utf8")
    .digest("base64url");
  return `consent-authority:${clientHash}`;
}

function reauthenticationBridgeRecordType(clientId: string): string {
  const clientHash = createHash("sha256")
    .update(clientId, "utf8")
    .digest("base64url");
  return `reauthentication-bridge:${clientHash}`;
}

function parseStoredV2(value: string): StoredConsentV2 | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    const record = parsed as Record<string, unknown>;
    const scopes = normalizeScopes(record.scopes);
    if (
      record.version !== 2 ||
      !validLifecycle(record.lifecycle) ||
      scopes === null ||
      typeof record.authorityEnvelope !== "string" ||
      record.authorityEnvelope === ""
    ) {
      return null;
    }
    return {
      version: 2,
      lifecycle: record.lifecycle,
      scopes,
      authorityEnvelope: record.authorityEnvelope,
    };
  } catch {
    return null;
  }
}

function parseAuthorityV1(
  plaintext: Uint8Array,
  clientId: string,
): ConsentAuthorityV1 | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(plaintext).toString("utf8"));
    const record =
      typeof value === "object" && value !== null
        ? (value as Record<string, unknown>)
        : undefined;
    const sessionIds = record?.sessionIds;
    if (
      record === undefined ||
      record.version !== 1 ||
      record.clientId !== clientId ||
      typeof record.grantId !== "string" ||
      record.grantId === "" ||
      !Array.isArray(sessionIds) ||
      !sessionIds.every(
        (sessionId) => typeof sessionId === "string" && sessionId !== "",
      )
    ) {
      return null;
    }
    return value as ConsentAuthorityV1;
  } catch {
    return null;
  }
}

function parsePending(
  value: unknown,
): PendingReauthenticationAuthority | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const bridgeFingerprint =
    typeof record.bridgeFingerprint === "string"
      ? record.bridgeFingerprint
      : record.proofDigest;
  if (
    typeof bridgeFingerprint !== "string" ||
    !digestPattern.test(bridgeFingerprint) ||
    typeof record.authorizationEpoch !== "string" ||
    record.authorizationEpoch === "" ||
    typeof record.sessionUid !== "string" ||
    record.sessionUid === "" ||
    !Number.isSafeInteger(record.expiresAt) ||
    (record.expiresAt as number) < 1
  ) {
    return undefined;
  }
  return {
    bridgeFingerprint,
    authorizationEpoch: record.authorizationEpoch,
    sessionUid: record.sessionUid,
    expiresAt: record.expiresAt as number,
  };
}

function parseRetiredReauthenticationBridges(
  value: unknown,
): RetiredReauthenticationBridge[] | null {
  if (value === undefined) {
    return [];
  }
  if (
    !Array.isArray(value) ||
    value.length > maximumStoredRetiredBridges
  ) {
    return null;
  }
  const retired: RetiredReauthenticationBridge[] = [];
  const fingerprints = new Set<string>();
  for (const item of value) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return null;
    }
    const record = item as Record<string, unknown>;
    if (
      typeof record.fingerprint !== "string" ||
      !digestPattern.test(record.fingerprint) ||
      !Number.isSafeInteger(record.expiresAt) ||
      (record.expiresAt as number) < 1 ||
      fingerprints.has(record.fingerprint)
    ) {
      return null;
    }
    fingerprints.add(record.fingerprint);
    retired.push({
      fingerprint: record.fingerprint,
      expiresAt: record.expiresAt as number,
    });
  }
  return retired.sort((first, second) => {
    const expiryOrder = first.expiresAt - second.expiresAt;
    if (expiryOrder !== 0) {
      return expiryOrder;
    }
    return first.fingerprint < second.fingerprint
      ? -1
      : first.fingerprint > second.fingerprint
        ? 1
        : 0;
  });
}

function parseAuthorityV2(
  plaintext: Uint8Array,
  clientId: string,
): ConsentAuthorityV2 | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(plaintext).toString("utf8"));
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return null;
    }
    const record = value as Record<string, unknown>;
    const scopes = normalizeScopes(record.scopes);
    const sessionIds = record.sessionIds;
    if (
      record.version !== 2 ||
      !validLifecycle(record.lifecycle) ||
      record.clientId !== clientId ||
      typeof record.resource !== "string" ||
      record.resource === "" ||
      scopes === null ||
      !Array.isArray(sessionIds) ||
      !sessionIds.every(
        (sessionId) => typeof sessionId === "string" && sessionId !== "",
      ) ||
      (
        record.authorizationGeneration !== undefined &&
        (
          typeof record.authorizationGeneration !== "string" ||
          !digestPattern.test(record.authorizationGeneration)
        )
      ) ||
      (
        record.grantId !== undefined &&
        (typeof record.grantId !== "string" || record.grantId === "")
      ) ||
      (
        record.consumedProofDigest !== undefined &&
        (
          typeof record.consumedProofDigest !== "string" ||
          !digestPattern.test(record.consumedProofDigest)
        )
      ) ||
      (
        record.evidence !== undefined &&
        typeof record.evidence !== "string"
      ) ||
      (
        record.cleanupReturnTo !== undefined &&
        (
          typeof record.cleanupReturnTo !== "string" ||
          record.cleanupReturnTo === ""
        )
      )
    ) {
      return null;
    }
    const pending = parsePending(record.pendingReauthentication);
    const retiredReauthenticationBridges =
      parseRetiredReauthenticationBridges(
        record.retiredReauthenticationBridges,
      );
    if (
      retiredReauthenticationBridges === null ||
      (record.lifecycle === "pending_reauth" && pending === undefined) ||
      (
        record.lifecycle !== "pending_reauth" &&
        record.pendingReauthentication !== undefined
      ) ||
      (
        record.lifecycle === "active" &&
        (typeof record.grantId !== "string" || sessionIds.length === 0)
      ) ||
      (
        record.lifecycle === "cleanup_finalizing" &&
        typeof record.cleanupReturnTo !== "string"
      ) ||
      (
        record.lifecycle !== "cleanup_finalizing" &&
        record.cleanupReturnTo !== undefined
      ) ||
      (
        record.lifecycle === "revoked" &&
        (
          record.grantId !== undefined ||
          sessionIds.length !== 0
        )
      ) ||
      (
        record.lifecycle === "quarantined" &&
        typeof record.evidence !== "string"
      )
    ) {
      return null;
    }
    return {
      version: 2,
      lifecycle: record.lifecycle,
      clientId,
      resource: record.resource,
      scopes,
      ...(typeof record.authorizationGeneration === "string"
        ? { authorizationGeneration: record.authorizationGeneration }
        : {}),
      ...(typeof record.grantId === "string"
        ? { grantId: record.grantId }
        : {}),
      sessionIds: [...new Set(sessionIds as string[])],
      ...(pending === undefined ? {} : { pendingReauthentication: pending }),
      ...(retiredReauthenticationBridges.length === 0
        ? {}
        : { retiredReauthenticationBridges }),
      ...(typeof record.consumedProofDigest === "string"
        ? { consumedProofDigest: record.consumedProofDigest }
        : {}),
      ...(typeof record.cleanupReturnTo === "string"
        ? { cleanupReturnTo: record.cleanupReturnTo }
        : {}),
      ...(typeof record.evidence === "string"
        ? { evidence: record.evidence }
        : {}),
    };
  } catch {
    return null;
  }
}

function stateFromAuthority(
  authority: ConsentAuthorityV2,
  accountActive: boolean,
): ConsentAuthorizationState {
  return {
    lifecycle: authority.lifecycle,
    clientId: authority.clientId,
    resource: authority.resource,
    scopes: authority.scopes,
    ...(authority.authorizationGeneration === undefined
      ? {}
      : { authorizationGeneration: authority.authorizationGeneration }),
    ...(authority.grantId === undefined
      ? {}
      : { grantId: authority.grantId }),
    sessionIds: authority.sessionIds,
    accountActive,
    retiredReauthenticationBridges:
      authority.retiredReauthenticationBridges ?? [],
    ...(authority.pendingReauthentication === undefined
      ? {}
      : {
          pendingReauthentication: {
            sessionUid: authority.pendingReauthentication.sessionUid,
            expiresAt: authority.pendingReauthentication.expiresAt,
          },
          pendingBridgeFingerprint:
            authority.pendingReauthentication.bridgeFingerprint,
          pendingAuthorizationEpoch:
            authority.pendingReauthentication.authorizationEpoch,
        }),
    ...(authority.consumedProofDigest === undefined
      ? {}
      : { consumedProofDigest: authority.consumedProofDigest }),
    ...(authority.cleanupReturnTo === undefined
      ? {}
      : { cleanupReturnTo: authority.cleanupReturnTo }),
    ...(authority.evidence === undefined
      ? {}
      : { quarantineEvidence: authority.evidence }),
  };
}

function sameScopes(first: readonly string[], second: readonly string[]): boolean {
  return (
    first.length === second.length &&
    first.every((scope, index) => scope === second[index])
  );
}

function quarantinedStateFromAuthority(
  row: EncodedConsentRow,
  authority: ConsentAuthorityV2,
): ConsentAuthorizationState {
  return {
    lifecycle: "quarantined",
    clientId: authority.clientId,
    resource: authority.resource,
    scopes: authority.scopes,
    ...(authority.authorizationGeneration === undefined
      ? {}
      : { authorizationGeneration: authority.authorizationGeneration }),
    ...(authority.grantId === undefined
      ? {}
      : { grantId: authority.grantId }),
    sessionIds: [
      ...new Set([
        ...authority.sessionIds,
        ...(authority.pendingReauthentication === undefined
          ? []
          : [authority.pendingReauthentication.sessionUid]),
      ]),
    ],
    accountActive: row.accountActive === 1,
    quarantineEvidence: row.value,
    needsQuarantine: true,
  };
}

export class ConsentAuthorizationCodec {
  constructor(
    private readonly vault: CredentialVault,
    private readonly expectedResource: string,
  ) {
    if (expectedResource === "") {
      throw new Error("invalid consent resource");
    }
  }

  async issueReauthenticationBridge(
    accountId: string,
    clientId: string,
    resource: string,
    claims: ReauthenticationBridgeClaims,
    authorizationGeneration: string,
  ): Promise<ReauthenticationBridge> {
    if (
      !validAccountId(accountId) ||
      clientId === "" ||
      resource !== this.expectedResource ||
      !proofPattern.test(claims.proof) ||
      claims.authorizationEpoch === "" ||
      !digestPattern.test(authorizationGeneration) ||
      !Number.isSafeInteger(claims.expiresAt) ||
      claims.expiresAt < 1
    ) {
      throw new Error("invalid reauthentication bridge");
    }
    const binding: ReauthenticationBridgeBindingV2 = {
      version: 2,
      accountId,
      clientId,
      resource,
      proof: claims.proof,
      authorizationEpoch: claims.authorizationEpoch,
      authorizationGeneration,
      expiresAt: claims.expiresAt,
    };
    const bindingEnvelope = await this.vault.seal(
      reauthenticationBridgeRecordType(clientId),
      accountId,
      Buffer.from(JSON.stringify(binding), "utf8"),
    );
    return {
      ...claims,
      bindingEnvelope,
    };
  }

  async verifyReauthenticationBridge(
    accountId: string,
    clientId: string,
    resource: string,
    bridge: ReauthenticationBridge,
  ): Promise<VerifiedReauthenticationBridge> {
    try {
      if (
        !validAccountId(accountId) ||
        clientId === "" ||
        resource !== this.expectedResource ||
        !validReauthenticationBridge(bridge)
      ) {
        throw new Error("invalid bridge");
      }
      const plaintext = await this.vault.open(
        reauthenticationBridgeRecordType(clientId),
        accountId,
        bridge.bindingEnvelope,
      );
      const parsed: unknown = JSON.parse(
        Buffer.from(plaintext).toString("utf8"),
      );
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        throw new Error("invalid bridge");
      }
      const binding = parsed as Record<string, unknown>;
      if (
        binding.version !== 2 ||
        binding.accountId !== accountId ||
        binding.clientId !== clientId ||
        binding.resource !== resource ||
        binding.proof !== bridge.proof ||
        binding.authorizationEpoch !== bridge.authorizationEpoch ||
        typeof binding.authorizationGeneration !== "string" ||
        !digestPattern.test(binding.authorizationGeneration) ||
        binding.expiresAt !== bridge.expiresAt
      ) {
        throw new Error("invalid bridge");
      }
      return {
        fingerprint: createHash("sha256")
          .update(bridge.bindingEnvelope, "utf8")
          .digest("base64url"),
        authorizationEpoch: bridge.authorizationEpoch,
        authorizationGeneration: binding.authorizationGeneration,
        expiresAt: bridge.expiresAt,
      };
    } catch {
      throw new Error("invalid reauthentication bridge");
    }
  }

  async parse(
    accountId: string,
    row: EncodedConsentRow,
  ): Promise<ConsentAuthorizationState> {
    const stored = parseStoredV2(row.value);
    let authorityEnvelope = stored?.authorityEnvelope;
    if (authorityEnvelope === undefined) {
      try {
        const untrusted: unknown = JSON.parse(row.value);
        if (
          typeof untrusted === "object" &&
          untrusted !== null &&
          !Array.isArray(untrusted) &&
          typeof (untrusted as Record<string, unknown>).authorityEnvelope ===
            "string"
        ) {
          authorityEnvelope = (untrusted as Record<string, string>)
            .authorityEnvelope;
        }
      } catch {
        // The legacy/evidence path below handles non-object JSON.
      }
    }
    if (authorityEnvelope !== undefined && authorityEnvelope !== "") {
      try {
        const plaintext = await this.vault.open(
          authorityRecordType(row.clientId),
          accountId,
          authorityEnvelope,
        );
        const authority = parseAuthorityV2(
          plaintext,
          row.clientId,
        );
        if (authority !== null) {
          if (
            stored !== null &&
            stored.lifecycle === authority.lifecycle &&
            sameScopes(stored.scopes, authority.scopes) &&
            authority.resource === this.expectedResource
          ) {
            return stateFromAuthority(authority, row.accountActive === 1);
          }
          return quarantinedStateFromAuthority(row, authority);
        }
      } catch {
        // The original row is preserved as encrypted quarantine evidence.
      }
    }

    let scopes: string[] = [];
    let grantId: string | undefined;
    let sessionIds: string[] = [];
    try {
      const legacy: unknown = JSON.parse(row.value);
      if (Array.isArray(legacy)) {
        scopes = normalizeScopes(legacy) ?? [];
      } else if (
        typeof legacy === "object" &&
        legacy !== null &&
        (legacy as Record<string, unknown>).version === 1
      ) {
        scopes =
          normalizeScopes((legacy as Record<string, unknown>).scopes) ?? [];
        const envelope = (legacy as Record<string, unknown>)
          .authorityEnvelope;
        if (typeof envelope === "string") {
          const plaintext = await this.vault.open(
            authorityRecordType(row.clientId),
            accountId,
            envelope,
          );
          const authority = parseAuthorityV1(plaintext, row.clientId);
          if (authority !== null) {
            grantId = authority.grantId;
            sessionIds = [...new Set(authority.sessionIds)];
          }
        }
      }
    } catch {
      // Unknown evidence stays opaque and permanently denied.
    }
    return {
      lifecycle: "quarantined",
      clientId: row.clientId,
      scopes,
      ...(grantId === undefined ? {} : { grantId }),
      sessionIds,
      accountActive: row.accountActive === 1,
      quarantineEvidence: row.value,
      needsQuarantine: true,
    };
  }

  async seal(
    accountId: string,
    state: ConsentAuthorizationState,
    {
      pending,
      consumedProofDigest,
      evidence,
    }: ConsentSealOptions = {},
  ): Promise<string> {
    if (
      state.resource !== undefined &&
      state.resource !== this.expectedResource
    ) {
      throw new Error("invalid consent resource");
    }
    const resource = this.expectedResource;
    const scopes = normalizeScopes(state.scopes) ?? [];
    const retiredReauthenticationBridges =
      parseRetiredReauthenticationBridges(
        state.retiredReauthenticationBridges,
      );
    if (
      retiredReauthenticationBridges === null ||
      (
        state.authorizationGeneration !== undefined &&
        !digestPattern.test(state.authorizationGeneration)
      ) ||
      (state.lifecycle === "pending_reauth" &&
        parsePending(pending) === undefined) ||
      (state.lifecycle !== "pending_reauth" && pending !== undefined) ||
      (
        state.lifecycle === "cleanup_finalizing" &&
        (state.cleanupReturnTo === undefined || state.cleanupReturnTo === "")
      ) ||
      (
        state.lifecycle !== "cleanup_finalizing" &&
        state.cleanupReturnTo !== undefined
      )
    ) {
      throw new Error("invalid consent authority state");
    }
    const authority: ConsentAuthorityV2 = {
      version: 2,
      lifecycle: state.lifecycle,
      clientId: state.clientId,
      resource,
      scopes,
      ...(state.authorizationGeneration === undefined
        ? {}
        : { authorizationGeneration: state.authorizationGeneration }),
      ...(state.grantId === undefined ? {} : { grantId: state.grantId }),
      sessionIds: [...new Set(state.sessionIds)],
      ...(pending === undefined ? {} : { pendingReauthentication: pending }),
      ...(retiredReauthenticationBridges.length === 0
        ? {}
        : { retiredReauthenticationBridges }),
      ...(consumedProofDigest === undefined
        ? {}
        : { consumedProofDigest }),
      ...(state.cleanupReturnTo === undefined
        ? {}
        : { cleanupReturnTo: state.cleanupReturnTo }),
      ...(evidence === undefined ? {} : { evidence }),
    };
    const authorityEnvelope = await this.vault.seal(
      authorityRecordType(state.clientId),
      accountId,
      Buffer.from(JSON.stringify(authority), "utf8"),
    );
    return JSON.stringify({
      version: 2,
      lifecycle: state.lifecycle,
      scopes,
      authorityEnvelope,
    } satisfies StoredConsentV2);
  }
}
