
FROM node:21-alpine


WORKDIR /app

COPY package.json /app
COPY package-lock.json /app
COPY tsconfig.json /app
COPY src /app/src

RUN npm install --ignore-scripts
RUN npm run build

RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot \
    && chown -R nonroot:nonroot /app

USER nonroot

CMD ["node", "dist/index.js"]
