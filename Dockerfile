FROM node:lts-alpine

WORKDIR /app

COPY package.json ./
COPY package-lock.json ./
COPY tsconfig.json ./
COPY src/ ./src/

RUN npm install

EXPOSE 25

CMD ["npm", "run", "start"]