import pino from "pino";

const streams = [
  { level: "info", stream: process.stdout },
  { level: "error", stream: process.stderr },
];

export const logger = pino(
  {
    level: process.env.LOGGER_LEVEL ?? "info",
    // This is a safety net. If a circular object is passed,
    // pino will try its best to handle it rather than crashing.
    serializers: {
      err: pino.stdSerializers.err,
      req: pino.stdSerializers.req,
      res: pino.stdSerializers.res,
    },
    // Prevents logging huge objects that might contain circular refs
    redact: {
      paths: ["req.socket", "req.connection", "req.httpVersion"],
      remove: true,
    },
  },
  pino.multistream(streams)
);
