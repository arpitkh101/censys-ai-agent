FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install curl for health checks
RUN apk add --no-cache curl

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install --silent

# Copy source code
COPY . .

# Fix any potential file permission issues
RUN chmod -R 755 /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S reactjs -u 1001

# Change ownership
RUN chown -R reactjs:nodejs /app

# Switch to non-root user
USER reactjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000 || exit 1

# Start the application
CMD ["npm", "start"]
