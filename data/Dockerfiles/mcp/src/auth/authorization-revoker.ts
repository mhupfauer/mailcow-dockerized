import type { Provider } from "oidc-provider";

import type {
  AuthorizationMutationCoordinator,
  MariaDbConsentAuthorizationRepository,
} from "./authorization-state.js";

export async function revokeProviderAuthority(
  provider: Provider,
  grantIds: readonly string[],
  sessionIds: readonly string[],
): Promise<void> {
  for (const grantId of new Set(grantIds.filter(Boolean))) {
    await Promise.all([
      provider.AccessToken.revokeByGrantId(grantId),
      provider.AuthorizationCode.revokeByGrantId(grantId),
      provider.RefreshToken.revokeByGrantId(grantId),
    ]);
    const grant = await provider.Grant.find(grantId);
    await grant?.destroy();
  }
  for (const sessionId of new Set(sessionIds.filter(Boolean))) {
    const session = await provider.Session.findByUid(sessionId);
    await session?.destroy();
  }
}

export async function revokeProviderAuthorityBestEffort(
  provider: Provider,
  grantIds: readonly string[],
  sessionIds: readonly string[],
): Promise<void> {
  const operations: Promise<unknown>[] = [];
  for (const grantId of new Set(grantIds.filter(Boolean))) {
    operations.push(
      provider.AccessToken.revokeByGrantId(grantId),
      provider.AuthorizationCode.revokeByGrantId(grantId),
      provider.RefreshToken.revokeByGrantId(grantId),
      (async () => {
        const grant = await provider.Grant.find(grantId);
        await grant?.destroy();
      })(),
    );
  }
  for (const sessionId of new Set(sessionIds.filter(Boolean))) {
    operations.push(
      (async () => {
        const session = await provider.Session.findByUid(sessionId);
        await session?.destroy();
      })(),
    );
  }
  const results = await Promise.allSettled(operations);
  if (results.some((result) => result.status === "rejected")) {
    throw new Error("unable to revoke provider authority");
  }
}

export class MariaDbAccountAuthorizationRevoker {
  constructor(
    private readonly consentRepository: MariaDbConsentAuthorizationRepository,
    private readonly provider: Provider,
    private readonly authorityMutations: AuthorizationMutationCoordinator,
    private readonly resource: string,
  ) {}

  async revokeCredential(accountId: string): Promise<void> {
    const states =
      await this.consentRepository.prepareAccountRevocation(accountId);
    let cleanupFailed = false;
    for (const prepared of states) {
      if (prepared.lifecycle === "revoked") {
        continue;
      }
      const lease = await this.authorityMutations.acquire(
        accountId,
        prepared.clientId,
        this.resource,
      );
      if (lease === null) {
        cleanupFailed = true;
        continue;
      }
      try {
        const state = await this.consentRepository.getStored(
          accountId,
          prepared.clientId,
        );
        if (state === null || state.lifecycle === "revoked") {
          continue;
        }
        await revokeProviderAuthorityBestEffort(
          this.provider,
          state.grantId === undefined ? [] : [state.grantId],
          state.sessionIds,
        );
        if (state.lifecycle === "cleanup_pending") {
          await this.consentRepository.completeClientCleanup(
            accountId,
            state.clientId,
          );
        }
      } catch {
        cleanupFailed = true;
      } finally {
        lease.release();
      }
    }
    if (cleanupFailed) {
      throw new Error("unable to revoke account authorization");
    }
  }
}
