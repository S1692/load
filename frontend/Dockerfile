## Dockerfile for the Next.js frontend
#
# This Dockerfile performs a multi‑stage build to install dependencies,
# compile the production assets, and run the application using the
# built‑in Next.js server. The image expects the environment variable
# `NEXT_PUBLIC_API_BASE_URL` to point at the FastAPI backend (e.g.
# `http://backend:8000`) so that the front‑end can send login requests.

FROM node:20-alpine AS deps

WORKDIR /app

# Install pnpm and dependencies based on the package.json and pnpm-lock.yaml.
COPY frontend/package.json ./
COPY frontend/pnpm-lock.yaml ./

RUN npm install -g pnpm \
    && pnpm install --frozen-lockfile

FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY frontend .

# Build the production version of the app. This will output files into
# the `.next` directory.
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app

# Copy built assets and node modules
COPY --from=builder /app /.next /.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules

# Expose the port that Next.js listens on
EXPOSE 3000

ENV NODE_ENV=production

# Start the server
CMD ["npm", "start"]