FROM alpine:3.15
LABEL maintainer="AmneziaVPN"

ARG XRAY_RELEASE="v1.8.6"

RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz && \
    apk --update upgrade --no-cache

RUN mkdir -p /opt/myvpn

RUN curl -L https://github.com/XTLS/Xray-core/releases/download/${XRAY_RELEASE}/Xray-linux-64.zip -o /root/xray.zip && \
    unzip /root/xray.zip -d /usr/bin/ && \
    chmod a+x /usr/bin/xray && \
    rm /root/xray.zip

# Tune network  
RUN echo -e "\
fs.file-max = 51200\n\
net.core.rmem_max = 67108864\n\
net.core.wmem_max = 67108864\n\
net.core.netdev_max_backlog = 250000\n\
net.core.somaxconn = 4096\n\
net.core.default_qdisc=fq\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv4.tcp_tw_reuse = 1\n\
net.ipv4.tcp_tw_recycle = 0\n\
net.ipv4.tcp_fin_timeout = 30\n\
net.ipv4.tcp_keepalive_time = 1200\n\
net.ipv4.ip_local_port_range = 10000 65000\n\
net.ipv4.tcp_max_syn_backlog = 8192\n\
net.ipv4.tcp_max_tw_buckets = 5000\n\
net.ipv4.tcp_fastopen = 3\n\
net.ipv4.tcp_mem = 25600 51200 102400\n\
net.ipv4.tcp_rmem = 4096 87380 67108864\n\
net.ipv4.tcp_wmem = 4096 65536 67108864\n\
net.ipv4.tcp_mtu_probing = 1\n\
net.ipv4.tcp_congestion_control = bbr" | tee -a /etc/sysctl.conf

RUN mkdir -p /etc/security && \
    echo -e "\
* soft nofile 51200\n\
* hard nofile 51200" | tee -a /etc/security/limits.conf

ENV TZ=Asia/Shanghai

COPY config.json /opt/myvpn/config.json

ENTRYPOINT ["dumb-init", "/usr/bin/xray", "run", "-c", "/opt/myvpn/config.json"]
