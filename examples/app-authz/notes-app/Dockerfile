FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY server.js .
# Listen on all interfaces inside the container only. Do not publish the port:
# only the NetBird proxy should reach this app.
ENV HOST=0.0.0.0 NODE_ENV=production
USER node
EXPOSE 8003
CMD ["node", "server.js"]
