FROM node:20-bullseye

WORKDIR /app

COPY . .

RUN npm install

RUN npx prisma generate

EXPOSE 25

CMD ["sh", "-c", "npx prisma db push && npm run start"]