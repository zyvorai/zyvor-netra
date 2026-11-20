FROM node:26-bookworm-slim AS web
WORKDIR /src
# The lockfile is copied and `npm ci` used so the build resolves exactly what CI
# tested: an unlocked `npm install` floats @novnc/novnc to a release whose
# package "exports" breaks vite's resolver, and the image stops building.
COPY web/package.json web/package-lock.json web/tsconfig.json web/vite.config.ts web/index.html ./web/
COPY web/src ./web/src
# Static files served as-is (the logo, the favicon). Vite copies web/public into dist, but only if it
# is in the build context: leaving it out ships a controller whose UI shows a broken-image logo.
COPY web/public ./web/public
RUN cd web && npm ci && npm run build

FROM golang:1.27-bookworm AS go
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/netrad ./cmd/netrad

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/netrad /netrad
COPY --from=web /src/web/dist /web
ENV NETRA_WEB_DIR=/web
EXPOSE 8080
ENTRYPOINT ["/netrad"]
