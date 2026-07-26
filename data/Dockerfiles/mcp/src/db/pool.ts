import { createPool as createMysqlPool, type Pool, type PoolOptions } from "mysql2/promise";

export type DatabasePoolConfig = Pick<
  PoolOptions,
  "host" | "port" | "database" | "user" | "password"
>;

export function createPool(config: DatabasePoolConfig): Pool {
  return createMysqlPool({
    ...config,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });
}
