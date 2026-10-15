FROM ubuntu:24.04
# Bootstrap certificates from Ubuntu's signature-verified package repositories
# before enabling HTTPS; the minimal base image has no CA trust store.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates strace coreutils \
    && sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
