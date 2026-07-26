CREATE TABLE IF NOT EXISTS oidc_objects (
  model VARCHAR(64) NOT NULL,
  id_hash VARBINARY(32) NOT NULL,
  payload_json JSON NOT NULL,
  grant_id VARBINARY(32) NULL,
  user_code_hash VARBINARY(32) NULL,
  uid_hash VARBINARY(32) NULL,
  consumed_at DATETIME(6) NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (model, id_hash),
  KEY idx_oidc_objects_expires_at (expires_at),
  KEY idx_oidc_objects_grant_id (grant_id),
  KEY idx_oidc_objects_user_code_hash (user_code_hash),
  KEY idx_oidc_objects_uid_hash (uid_hash)
);

CREATE TABLE IF NOT EXISTS accounts (
  id BINARY(16) NOT NULL,
  mailbox_normalized VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  credential_envelope TEXT NOT NULL,
  credential_version TINYINT UNSIGNED NOT NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_accounts_mailbox_normalized (mailbox_normalized)
);

CREATE TABLE IF NOT EXISTS consents (
  account_id BINARY(16) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  scopes JSON NOT NULL,
  created_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL,
  PRIMARY KEY (account_id, client_id),
  CONSTRAINT fk_consents_account
    FOREIGN KEY (account_id) REFERENCES accounts (id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  account_id BINARY(16) NULL,
  action VARCHAR(64) NOT NULL,
  outcome VARCHAR(32) NOT NULL,
  object_id VARBINARY(32) NULL,
  count_value INT UNSIGNED NULL,
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_audit_events_account_id (account_id),
  KEY idx_audit_events_created_at (created_at),
  CONSTRAINT fk_audit_events_account
    FOREIGN KEY (account_id) REFERENCES accounts (id)
    ON DELETE SET NULL
);
