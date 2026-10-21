# Server only: this image ships NO web UI (web/dist is not copied), so GET / is a JSON 404 inside the container. Mock mode: the stubs run inside this container, on its own loopback.
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production TW_PORT=5910
COPY package.json package-lock.json ./
COPY server/package.json server/
RUN npm ci --omit=dev -w server --ignore-scripts && npm cache clean --force
COPY server/src server/src
USER node
EXPOSE 5910
# Inside the container the API must listen on all interfaces, so TW_BIND is set here on purpose.
# The compose file publishes the port on 127.0.0.1 only; do not publish it more widely.
ENV TW_BIND=0.0.0.0
CMD ["node", "server/src/index.js"]
