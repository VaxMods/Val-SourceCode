import { main } from "./app/bootstrap.js";
import { ConfigurationError, errorMessage } from "./core/errors.js";
import { redactString } from "./core/redact.js";

main().catch((error: unknown) => {
  const message = error instanceof ConfigurationError ? error.message : errorMessage(error);
  process.stderr.write(`Val Protection failed to start: ${redactString(message)}\n`);
  process.exitCode = 1;
  setTimeout(() => process.exit(1), 3000).unref();
});
