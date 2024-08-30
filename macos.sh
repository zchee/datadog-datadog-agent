#!/bin/zsh
set -uxo pipefail

CI_UPLOADER_VERSION=2.38.1
CI_UPLOADER_ARM64_SHA=6af61464cf3ad7b58e7fa45b4df035f7d1bd77b077df4a127478dc023f802c7f
CI_UPLOADER_AMD64_SHA=703d368a50cc7a3825fb8fc10744f2b6cf508facf970728441d8671105e8301b
CODECOV_VERSION=0.6.1
CODECOV_SHA=62ba56f0f0d62b28e955fcfd4a3524c7c327fcf8f5fcb5124cccf88db358282e

ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
  CI_UPLOADER_SHA=$CI_UPLOADER_ARM64_SHA
  CI_UPLOADER_BINARY="datadog-ci_darwin-arm64"
else
  CI_UPLOADER_SHA=$CI_UPLOADER_AMD64_SHA
  CI_UPLOADER_BINARY="datadog-ci_darwin-x64"
fi

echo 'Installing datadog-ci...'
curl -fsSL https://github.com/DataDog/datadog-ci/releases/download/v${CI_UPLOADER_VERSION}/${CI_UPLOADER_BINARY} --output "/usr/local/bin/datadog-ci"
echo "${CI_UPLOADER_SHA} */usr/local/bin/datadog-ci" | shasum -a 256 --check
chmod +x /usr/local/bin/datadog-ci

# Codecov uploader is only released on amd64 macOS
if [ "$ARCH" = "x86_64" ]; then
    echo 'Installing Codecov uploader...'
    curl -fsSL https://uploader.codecov.io/v${CODECOV_VERSION}/macos/codecov --output "/usr/local/bin/codecov"
    echo "${CODECOV_SHA} */usr/local/bin/codecov" | shasum -a 256 --check
    chmod +x /usr/local/bin/codecov
fi


datadog-ci --help
codecov --help
