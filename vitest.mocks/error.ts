export class InternalError extends Error {
  code?: string;
  retryable?: boolean;
  severity?: string;

  constructor(opts: { code?: string; message?: string; retryable?: boolean; severity?: string; cause?: unknown }) {
    super(opts.message);
    this.code = opts.code;
    this.retryable = opts.retryable;
    this.severity = opts.severity;
    if (opts.cause) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (this as any).cause = opts.cause;
    }
  }
}
