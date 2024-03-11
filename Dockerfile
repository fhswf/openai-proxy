FROM node:21-alpine

WORKDIR /app

COPY package.json /app
COPY package-lock.json /app
COPY index.js /app

RUN npm install

CMD ["node", "index.js"]
