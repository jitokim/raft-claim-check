import type { Store } from "./store";

/** A row of v1's sessions table, as authenticate() loads it. */
export interface Session {
  id_hash: string; server_id: string; server_slug: string; server_name: string | null;
  principal_id: string; principal_type: string; display_name: string | null; scopes: string; expires_at: string;
}

/** What an action handler gets once the size and session checks have passed. `now` is epoch milliseconds. */
export interface ActionContext {
  store: Store;
  session: Session;
  now: number;
}

export type ActionHandler = (ctx: ActionContext, body: Uint8Array) => Promise<Response>;
