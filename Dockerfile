FROM oven/bun:1-alpine

WORKDIR /app

# Copy only what the proxy needs
COPY proxy.ts .
COPY package.json .

# No npm deps needed — proxy.ts only uses Bun built-ins + child_process
# (child_process is Node-compatible in Bun)

EXPOSE 3099

ENV PROXY_PORT=3099

CMD ["bun", "run", "proxy.ts"]
