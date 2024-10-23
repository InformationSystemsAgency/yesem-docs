FROM node:lts-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app/nodejs

COPY ["./nodejs/package.json", "./nodejs/package-lock.json*", "./nodejs/npm-shrinkwrap.json*", "./"]
RUN npm install --production=false --silent && mv node_modules ../

COPY ./nodejs .
COPY ./public /usr/src/app/public

RUN npm run build
RUN npm prune --production

RUN chown -R node /usr/src/app
USER node

CMD ["npm", "start"]
