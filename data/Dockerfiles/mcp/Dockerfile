FROM node:24.18.0-alpine3.24 AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24.18.0-alpine3.24 AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
  && addgroup -S -g 10001 mcp \
  && adduser -S -D -H -u 10001 -G mcp mcp

COPY --from=build --chown=10001:10001 /app/dist ./dist
COPY --from=build --chown=10001:10001 /app/src/db/migrations ./dist/db/migrations
RUN chmod -R a-w /app

USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:3000/health/ready || exit 1

CMD ["node", "dist/server.js"]
