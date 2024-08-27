#!/bin/bash

# Test block_proto endpoint
echo "Testing block_proto endpoint..."
response=$(curl -s -X POST http://localhost:8080/block_proto \
-H "Content-Type: application/json" \
-H "Authorization: Bearer APITOKEN" \
-d '{"protocol": "udp"}')
echo "Response: $response"

# Test block_ip endpoint
echo "Testing block_ip endpoint..."
response=$(curl -s -X POST http://localhost:8080/block_ip \
-H "Content-Type: application/json" \
-H "Authorization: Bearer APITOKEN" \
-d '{"ip": "192.168.1.1"}')
echo "Response: $response"

# Test get_block_handler endpoint
echo "Testing get_block_handler endpoint..."
response=$(curl -s -X GET http://localhost:8080/block/192.168.1.1 \
-H "Authorization: Bearer APITOKEN")
echo "Response: $response"

# Test health endpoint
echo "Testing health endpoint..."
response=$(curl -s -X GET http://localhost:8080/health)
echo "Response: $response"
