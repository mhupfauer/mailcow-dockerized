export interface ExpectedIndex {
  tableName: string;
  indexName: string;
  nonUnique: 0 | 1;
  columns: readonly string[];
}

// These values are deliberately hand-derived from the OAuth persistence
// contract. They must not be generated from the migration under test.
export const expectedIndexes: readonly ExpectedIndex[] = [
  {
    tableName: "accounts",
    indexName: "PRIMARY",
    nonUnique: 0,
    columns: ["id"],
  },
  {
    tableName: "accounts",
    indexName: "uq_accounts_mailbox_normalized",
    nonUnique: 0,
    columns: ["mailbox_normalized"],
  },
  {
    tableName: "audit_events",
    indexName: "PRIMARY",
    nonUnique: 0,
    columns: ["id"],
  },
  {
    tableName: "audit_events",
    indexName: "idx_audit_events_account_id",
    nonUnique: 1,
    columns: ["account_id"],
  },
  {
    tableName: "audit_events",
    indexName: "idx_audit_events_created_at",
    nonUnique: 1,
    columns: ["created_at"],
  },
  {
    tableName: "consents",
    indexName: "PRIMARY",
    nonUnique: 0,
    columns: ["account_id", "client_id"],
  },
  {
    tableName: "oidc_objects",
    indexName: "PRIMARY",
    nonUnique: 0,
    columns: ["model", "id_hash"],
  },
  {
    tableName: "oidc_objects",
    indexName: "idx_oidc_objects_expires_at",
    nonUnique: 1,
    columns: ["expires_at"],
  },
  {
    tableName: "oidc_objects",
    indexName: "idx_oidc_objects_grant_id",
    nonUnique: 1,
    columns: ["grant_id"],
  },
  {
    tableName: "oidc_objects",
    indexName: "idx_oidc_objects_uid_hash",
    nonUnique: 1,
    columns: ["uid_hash"],
  },
  {
    tableName: "oidc_objects",
    indexName: "idx_oidc_objects_user_code_hash",
    nonUnique: 1,
    columns: ["user_code_hash"],
  },
];
