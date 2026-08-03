# Hardened counterpart. The build stage intentionally uses a floating tag and
# runs as root - both are routine at build time and are discarded with the
# stage, so a final-stage-scoped scanner must stay silent about them.
FROM golang:latest AS build
USER root
WORKDIR /src
COPY . .
RUN go build -o /out/app ./cmd/app

# Final image: pinned base, dedicated unprivileged user, no secrets, no SSH.
FROM alpine:3.20 AS runtime
RUN addgroup -S app && adduser -S app -G app
COPY --from=build /out/app /usr/local/bin/app
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/app"]
