# syntax=docker/dockerfile:1

# Next.js inlines every NEXT_PUBLIC_* variable into the client bundle at BUILD
# time. Setting NEXT_PUBLIC_API_BASE_URL as a runtime environment variable on
# the container does nothing at all — the value was already frozen into the
# JavaScript when `next build` ran. The previous version of this file took no
# build argument, so every image ever produced from it called
# http://localhost:8000/api/v1 regardless of what docker-compose said. That
# happens to work when you browse from the same machine the backend runs on,
# and fails silently everywhere else.
#
# The API base URL is therefore a build argument. Building an image for a
# deployment means passing the URL that deployment's browsers will use.

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# npm ci installs exactly the tree in package-lock.json and fails if the lock
# and the manifest disagree, so an image cannot quietly resolve to different
# dependency versions than the ones that were tested.
RUN npm ci --legacy-peer-deps

FROM node:20-alpine AS builder
WORKDIR /app

ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Run as the unprivileged user the node image already ships rather than root.
RUN chown -R node:node /app

COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/.next ./.next
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/package.json ./package.json
COPY --from=builder --chown=node:node /app/next.config.mjs ./next.config.mjs

USER node
EXPOSE 3000
CMD ["npm", "start"]
