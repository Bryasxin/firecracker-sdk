generate-api-client:
  openapi-generator generate --input-spec resources/firecracker.yaml --generator-name rust --output api_client