FROM node:22-alpine AS tooling
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./

FROM tooling AS test
RUN npm ci
COPY tsconfig.json vitest.config.ts ./
COPY src ./src
CMD ["sh", "-c", "npm run typecheck && npm test"]

FROM tooling AS deps
RUN npm ci --omit=dev

FROM node:22-alpine

WORKDIR /app
# Нативные бинарники собраны на той же базе, поэтому переносятся как есть.
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src

EXPOSE 3001
CMD ["npm", "start"]
