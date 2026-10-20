import type { Logger } from "pino";
import { errorMessage } from "../core/errors.js";
import type { AuditEvent } from "../discord/auditEvent.js";
import type { LockManager } from "./infra/lockManager.js";
import type { PolicyService } from "./policy/policyService.js";

export interface AuditHandler {
  onAuditEvent(event: AuditEvent): Promise<void>;
}

export class AuditDispatcher {
  constructor(
    private readonly handlers: ReadonlyArray<{ name: string; handler: AuditHandler }>,
    private readonly policies: PolicyService,
    private readonly locks: LockManager,
    private readonly logger: Logger
  ) {}

  async dispatch(event: AuditEvent): Promise<void> {
    if (!this.policies.isGuildAllowed(event.guildId)) return;
    if (!(await this.locks.once(`audit:${event.guildId}:${event.id}`, 3600000))) return;
    const results = await Promise.allSettled(this.handlers.map(({ handler }) => handler.onAuditEvent(event)));
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        this.logger.error(
          { err: errorMessage(result.reason), handler: this.handlers[index]?.name, guildId: event.guildId, action: event.actionName },
          "Audit handler failed"
        );
      }
    });
  }
}
