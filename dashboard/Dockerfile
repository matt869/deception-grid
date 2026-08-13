# Dashboard image: build the static bundle, serve it from nginx.

FROM node:20-alpine AS build
WORKDIR /app
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

FROM nginx:1.27-alpine
# SPA routing: fall back to index.html, and proxy /api to the api service.
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
