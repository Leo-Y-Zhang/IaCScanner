# Intentionally INSECURE Dockerfile for scanner testing - all values synthetic.
# The build stage below is deliberately clean and pinned: every finding in this
# file must be attributed to the final image stage, never the builder.
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app ./cmd/app

# Final image: mutable base tag, baked secret, SSH exposed, runs as root.
FROM ubuntu:latest AS runtime
ENV APP_DB_PASSWORD="hunter2-not-real"
EXPOSE 22
COPY --from=build /out/app /usr/local/bin/app
USER root
ENTRYPOINT ["/usr/local/bin/app"]
