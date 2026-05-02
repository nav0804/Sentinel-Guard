import pino from "pino";

const streams = [
  { level: "info", stream: process.stdout },
  { level: "error", stream: process.stderr },
];

export const logger = pino(
  {
    level: process.env.LOGGER_LEVEL ?? "info",
    serializers: {
      err: pino.stdSerializers.err,
      req: pino.stdSerializers.req,
      res: pino.stdSerializers.res,
    },
    redact: {
      paths: ["req.socket", "req.connection", "req.httpVersion"],
      remove: true,
    },
  },
  pino.multistream(streams)
);
