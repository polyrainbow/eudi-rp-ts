# Node 24 runs TypeScript directly, so there is no build stage.
FROM node:24-alpine

WORKDIR /app

# package-lock.json is committed, so this is reproducible.
#
# Not `--omit=dev`: the demo page renders a QR code, and `qrcode` is a
# devDependency because the *library* does not use it — only `app/` does, and
# `dependencies` is what someone installing this package from npm gets. npm has
# no way to say "omit dev except this one", and naming qrcode's version a second
# time here would be a version to keep in sync, so the image takes the whole set.
COPY package.json package-lock.json ./
RUN npm ci

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
