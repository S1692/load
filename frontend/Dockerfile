# Stage 1: Build the Next.js application
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package.json and lock files
# Using npm ci for faster, more reliable builds in CI/CD environments
COPY package*.json ./
RUN npm ci

# Copy the rest of the application source code
COPY . .

# Build the application
# The NEXT_PUBLIC_API_BASE_URL is passed in docker-compose, but it's better to
# make it available during build time if needed for static generation.
RUN npm run build

# Stage 2: Production image, using standalone output for smaller size
FROM node:20-alpine

WORKDIR /app

# We need to set this user to avoid running as root
# Create a non-root user and group
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Copy the standalone output from the builder stage.
# This requires `output: 'standalone'` in next.config.js
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Set the owner of the files to the non-root user
USER nextjs

# Expose the port the app runs on
EXPOSE 3000

# The command to run the application
# The port is specified here, matching the EXPOSE instruction
CMD ["node", "server.js"]
