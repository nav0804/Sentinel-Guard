import pino from "pino"
const streams = [
    {level: 'info', stream: process.stdout},
    {level: 'error', stream: process.stderr},
]

export const logger = pino(
    {
        level: process.env.LOGGER_LEVEL ?? 'info'
    },
    pino.multistream(streams)
)