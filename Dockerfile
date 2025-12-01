# multi_func_security_mcp_full/Dockerfile

# 使用官方 Python 镜像
FROM python:3.11-slim-bookworm

# 设置工作目录
WORKDIR /app

# 安装系统依赖（psutil、whois 等可能需要编译）
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        procps \
        net-tools \
        iproute2 \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# 复制源码
COPY multi_func_security_mcp_full.py .
COPY custom_iocs.yaml ./custom_iocs.yaml  # 可选；若不存在则忽略

# 安装 Python 依赖（仅安装可用项，避免因缺失可选库失败）
RUN pip install --no-cache-dir \
    psutil \
    pyyaml \
    aiohttp \
    python-whois \
    fastmcp \
    && mkdir -p /var/log

# 创建非 root 用户（推荐在非特权模式下运行）
RUN useradd --create-home --shell /bin/bash secuser
USER secuser
ENV HOME=/home/secuser
WORKDIR /home/secuser/app

# 暴露端口（MCP + Web UI）
EXPOSE 8000 8080

# 启动命令
CMD ["python3", "multi_func_security_mcp_full.py", \
     "--host", "0.0.0.0", \
     "--mcp-port", "8000", \
     "--web-port", "8080", \
     "--ioc-file", "custom_iocs.yaml"]

