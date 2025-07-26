FROM oven/bun:debian

WORKDIR /app

COPY . .

RUN bun install

RUN apt update && apt install -y nodejs

RUN bunx prisma generate

EXPOSE 587

CMD ["sh", "-c", "bunx prisma db push && bun run start"]