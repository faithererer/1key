#!/bin/bash

# 拉取最新镜像并部署
echo "Pulling latest image..."
docker-compose pull

echo "Starting services..."
docker-compose up -d

echo "Deployment completed!"
docker-compose ps