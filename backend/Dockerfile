FROM node:18-alpine

# Install Chromium for Playwright
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV CHROMIUM_PATH=/usr/bin/chromium-browser

WORKDIR /app
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --only=production
COPY frontend/build ./frontend/build
COPY backend ./backend
RUN mkdir -p backend/screenshots backend/reports

EXPOSE 5000
CMD ["node", "backend/src/server.js"]
