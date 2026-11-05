# The command-line verifier in a container, for hosts without Node.
#   docker build -t eventchain-verify-ts https://github.com/eventchain-protocol/verify.git
#   docker run --rm -v "$PWD:/data:ro" eventchain-verify-ts aof /data/history.jsonl
FROM node:22-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-slim
WORKDIR /app
COPY --from=build /src/package.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
