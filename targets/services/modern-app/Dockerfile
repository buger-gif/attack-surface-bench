# modern-app Dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm config set registry https://registry.npmmirror.com && npm install --legacy-peer-deps
COPY . .
EXPOSE 3000
CMD ["sh", "-c", "node seed.js && node app.js"]
