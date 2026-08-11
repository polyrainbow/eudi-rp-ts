# Node 24 runs TypeScript directly, so there is no build stage.
FROM node:24-alpine

WORKDIR /app

# Install runtime dependencies only. package-lock.json is committed, so this is
# reproducible.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY app ./app
# Public certificates only. This used to be `COPY test/fixtures`, which put the
# throwaway private keys from test/fixtures/real/ into the runtime image because
# the default trust anchor happened to live next to them.
COPY anchors ./anchors

ENV PORT=3000
EXPOSE 3000

USER node
CMD ["node", "app/main.ts"]
