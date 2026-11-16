# jsharvest with a pinned Chrome for Testing, for headless runs and for a
# login by hand through noVNC (docs/gd5-container-design.md).
#   mkdir -p output profiles
#   docker build -t jsharvest .
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/output:/output" -v "$PWD/profiles:/profiles" jsharvest crawl -u https://target/
# Base images are pinned by digest; Chrome by version and checksum, from
# Chrome for Testing, which keeps every version (the .deb pool of Google
# keeps the current one only).

FROM golang:1.25.4-bookworm@sha256:e17419604b6d1f9bc245694425f0ec9b1b53685c80850900a376fb10cb0f70cb AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/jsharvest ./cmd/jsharvest

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ARG TARGETARCH
# The Chrome jsharvest is developed and gated with (amd64 uses pinned Chrome for Testing;
# other architectures fall back to Debian's Chromium package).
ARG CHROME_VERSION=156.0.8078.79
ARG CHROME_SHA256=7088865f510de22a83226817266274a1a4a57157d78ab429e6315701b19669f7
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip tini xvfb xauth x11vnc novnc python3-websockify \
      fonts-liberation fonts-noto-core fonts-noto-cjk fonts-noto-color-emoji \
 && if [ "${TARGETARCH:-amd64}" = "amd64" ]; then \
      curl -fsSLo /tmp/chrome.zip "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip" \
      && echo "${CHROME_SHA256}  /tmp/chrome.zip" | sha256sum -c - \
      && unzip -q /tmp/chrome.zip -d /opt \
      && apt-get install -y --no-install-recommends \
           $(sed -E 's/ \(.*//; s/ \|.*//' /opt/chrome-linux64/deb.deps | grep -vE '^(wget|xdg-utils)$') \
      && ln -s /opt/chrome-linux64/chrome /usr/local/bin/chrome \
      && rm -rf /tmp/chrome.zip; \
    else \
      apt-get install -y --no-install-recommends chromium \
      && ln -s /usr/bin/chromium /usr/local/bin/chrome; \
    fi \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get purge -y unzip \
 && groupadd -g 1000 jsharvest && useradd -m -u 1000 -g 1000 -s /bin/sh jsharvest \
 && install -d -o 1000 -g 1000 -m 0700 /output /profiles
COPY --from=build /out/jsharvest /usr/local/bin/jsharvest
COPY docker/entrypoint.sh /usr/local/bin/jsharvest-entrypoint
USER 1000:1000
WORKDIR /tmp
# JSHARVEST_NO_SANDBOX is set by the entrypoint: Chrome's sandbox when the
# container may make user namespaces, else --no-sandbox, with a warning.
ENV JSHARVEST_OUTPUT=/output JSHARVEST_PROFILES=/profiles JSHARVEST_CHROME=/usr/local/bin/chrome
VOLUME ["/output", "/profiles"]
EXPOSE 6080
# Not tini -g: a signal for the group would reach Chrome with jsharvest,
# and cut the ordered shutdown; when jsharvest ends, the rest goes with
# the container.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/jsharvest-entrypoint"]
CMD ["help"]
