# Builds the library, packs it exactly as it would be published, then installs that
# tarball into a minimal runtime image. The container therefore runs the packed
# artifact, not the source tree, which is what catches packaging mistakes.
FROM node:26-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts tsup.example.config.ts ./
COPY src ./src
COPY examples ./examples
RUN npm run build && npm run build:example && npm pack --pack-destination /tmp

FROM node:26-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /tmp/authcore-ts-*.tgz /tmp/
RUN npm init -y >/dev/null \
 && npm install --omit=dev --no-audit --no-fund /tmp/authcore-ts-*.tgz pg@8 \
 && rm -rf /tmp/*.tgz /root/.npm
COPY --from=build /src/examples/server/dist/server.mjs ./server.mjs
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "server.mjs"]
