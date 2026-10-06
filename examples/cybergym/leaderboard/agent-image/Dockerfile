FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        bash \
        build-essential \
        ca-certificates \
        clang \
        clangd \
        libclang-rt-14-dev \
        gdb \
        git \
        openssh-client \
        openssh-server \
        python3 \
        python3-venv \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --user-group --shell /bin/bash agent \
    && passwd -d agent \
    && rm -rf /root /srv \
    && mkdir -p /workspace/src /workspace/output /run/ssh /run/sshd \
    && ! command -v sudo \
    && ! command -v docker

RUN printf '%s\n' \
    'Port 2222' \
    'ListenAddress 0.0.0.0' \
    'HostKey /run/ssh/ssh_host_ed25519_key' \
    'AuthorizedKeysFile /run/ssh/authorized_keys' \
    'AllowUsers agent' \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'AuthenticationMethods publickey' \
    'PubkeyAuthentication yes' \
    'PermitEmptyPasswords no' \
    'UsePAM no' \
    'PermitUserEnvironment no' \
    'AllowAgentForwarding no' \
    'AllowTcpForwarding local' \
    'PermitOpen 127.0.0.1:* localhost:*' \
    'AllowStreamLocalForwarding local' \
    'X11Forwarding no' \
    'PermitTunnel no' \
    'GatewayPorts no' \
    'Subsystem sftp /usr/lib/openssh/sftp-server' \
    > /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/cybergym-entrypoint
COPY extract_archive.py /usr/local/bin/cybergym-extract
RUN chmod 0755 /usr/local/bin/cybergym-entrypoint

EXPOSE 2222/tcp
ENTRYPOINT ["/usr/local/bin/cybergym-entrypoint"]
