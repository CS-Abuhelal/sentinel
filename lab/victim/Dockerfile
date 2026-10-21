FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends passwd procps nftables netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

RUN for user in jdoe svc_backup labadmin; do \
      useradd --create-home --shell /bin/bash "$user" \
      && echo "$user:$(head -c 18 /dev/urandom | base64)" | chpasswd; \
    done

CMD ["sleep", "infinity"]
