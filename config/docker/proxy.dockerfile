FROM node:20-alpine AS base

RUN npm i -g pnpm
WORKDIR /app

COPY pnpm-workspace.yaml ./
COPY package.json ./
COPY pnpm-lock.yaml ./

COPY config/tsconfig/         ./config/tsconfig/
COPY packages/schemas/        ./packages/schemas/
COPY packages/logger/         ./packages/logger/
COPY packages/cache/          ./packages/cache/
COPY packages/ip-reputation/  ./packages/ip-reputation/
COPY packages/pipeline/       ./packages/pipeline/
COPY packages/agents/         ./packages/agents/
COPY apps/proxy/              ./apps/proxy/

RUN pnpm install --frozen-lockfile

RUN pnpm --filter @sentinel/schemas build \
    && ls -la packages/schemas/dist/

RUN pnpm --filter @sentinel/logger build \
    && ls -la packages/logger/dist/

RUN pnpm --filter @sentinel/cache build \
    && ls -la packages/cache/dist/

RUN pnpm --filter @sentinel/ip-reputation build \
    && ls -la packages/ip-reputation/dist/

RUN pnpm --filter @sentinel/pipeline build \
    && ls -la packages/pipeline/dist/

RUN pnpm --filter @sentinel/agents build \
    && ls -la packages/agents/dist/

RUN pnpm --filter @sentinel-guard/proxy build \
    && ls -la apps/proxy/dist/

CMD ["node", "apps/proxy/dist/index.js"]