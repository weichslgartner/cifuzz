#!/bin/sh

# detect os to get the correct url for the installer
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  DOWNLOAD_URL="https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  if [[ $(uname -m) == 'arm64' ]]; then
    DOWNLOAD_URL="https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_darwin_arm64"
  else
    DOWNLOAD_URL="https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_darwin"
  fi
elif [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" ]]; then
  DOWNLOAD_URL="https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_windows"
else
  echo "No installer available for this operating system '$OSTYPE'"
  exit 1
fi

echo -n "Downloading installer... "
curl -fsSL -o cifuzz_installer $DOWNLOAD_URL
echo "ok"

echo "Starting installer..."
chmod u+x cifuzz_installer
./cifuzz_installer
