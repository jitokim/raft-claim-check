// A minimal D1Database over Node's built-in node:sqlite, with every file in migrations/ applied in name order.
// It covers only what src/ calls: prepare().bind().first()/all()/run() and batch().
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS = new URL("../migrations/", import.meta.url);

type Params = (string | number | null)[];

class Statement {
  constructor(private readonly db: DatabaseSync, private readonly sql: string, private readonly params: Params = []) {}

  bind(...params: Params): Statement {
    return new Statement(this.db, this.sql, params);
  }

  async first<T>(column?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...this.params) as Record<string, unknown> | undefined;
    if (!row) return null;
    return (column ? row[column] : { ...row }) as T;
  }

  async all<T>(): Promise<{ results: T[]; success: true; meta: Record<string, never> }> {
    const rows = this.db.prepare(this.sql).all(...this.params) as Record<string, unknown>[];
    return { results: rows.map((row) => ({ ...row }) as T), success: true, meta: {} };
  }

  async run(): Promise<{ results: []; success: true; meta: { changes: number; last_row_id: number } }> {
    const info = this.db.prepare(this.sql).run(...this.params);
    return { results: [], success: true, meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } };
  }
}

class SqliteD1 {
  constructor(private readonly db: DatabaseSync) {}

  prepare(sql: string): Statement {
    return new Statement(this.db, sql);
  }

  async batch(statements: Statement[]): Promise<unknown[]> {
    this.db.exec("BEGIN");
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      this.db.exec("COMMIT");
      return results;
    } catch (cause) {
      this.db.exec("ROLLBACK");
      throw cause;
    }
  }
}

/** A fresh in-memory database with the repository's migrations applied. `sqlite` is the raw handle for assertions. */
export function migratedDatabase(): { d1: D1Database; sqlite: DatabaseSync } {
  const sqlite = new DatabaseSync(":memory:");
  for (const name of readdirSync(MIGRATIONS).filter((file) => file.endsWith(".sql")).sort()) {
    sqlite.exec(readFileSync(new URL(name, MIGRATIONS), "utf8"));
  }
  return { d1: new SqliteD1(sqlite) as unknown as D1Database, sqlite };
}
