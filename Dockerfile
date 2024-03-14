FROM node:21-alpine

WORKDIR /app

COPY package.json /app
COPY package-lock.json /app
COPY lib /app/lib

RUN npm install

CMD ["node", "index.js"]
