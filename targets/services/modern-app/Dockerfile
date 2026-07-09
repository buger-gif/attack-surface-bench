# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
# modern-app Dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm config set registry https://registry.npmmirror.com && npm install --legacy-peer-deps express jsonwebtoken mongodb axios express-graphql graphql
COPY . .
EXPOSE 3000
CMD ["sh", "-c", "node seed.js && node app.js"]
