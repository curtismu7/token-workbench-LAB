# Stage 1 builds web/dist; stage 2 is the runtime: API server + the built UI. Same pattern as mcp-discovery.
# Mock mode only: the stubs run inside this container, on its own loopback. Stub signing keys are generated in memory at startup;
# no key or secret is copied into the image. No ps, lsof or docker CLI is installed.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY server/package.json server/
RUN npm ci --ignore-scripts
COPY web web
RUN npm run build -w web

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production TW_PORT=5910
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY server/package.json server/
RUN npm ci --omit=dev -w server --ignore-scripts && npm cache clean --force
COPY server/src server/src
COPY --from=build /app/web/dist web/dist
USER node
EXPOSE 5910
# Inside the container the API must listen on all interfaces, so TW_BIND is set here on purpose.
# The compose file publishes the port on 127.0.0.1 only; do not publish it more widely.
ENV TW_BIND=0.0.0.0
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:5910/api/health').then(r=>r.json()).then(j=>process.exit(j.state==='ready'?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server/src/index.js"]
