FROM node:lts-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app

COPY ["package.json", "package-lock.json*", "npm-shrinkwrap.json*", "./"]
RUN npm install --production=false --silent && mv node_modules ../

COPY . .

RUN npm run build
RUN npm prune --production

RUN chown -R node /usr/src/app
USER node

CMD ["npm", "start"]
