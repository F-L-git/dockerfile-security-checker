# Частично хороший пример (есть USER, но есть замечания)
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 -G nodejs

USER nextjs

EXPOSE 3000

CMD ["node", "server.js"]
