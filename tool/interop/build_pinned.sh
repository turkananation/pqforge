#!/bin/sh
# Build the OpenSSL and BoringSSL releases named in pins.env.
# Skips the work when tool/interop/.build/STAMP already matches the pin.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
pins=$root/tool/interop/pins.env
prefix=${PINNED_TLS_PREFIX:-$root/tool/interop/.build}
# shellcheck disable=SC1090
. "$pins"

stamp=$prefix/STAMP
want="$OPENSSL_TAG $OPENSSL_SHA256 $BORINGSSL_TAG $BORINGSSL_COMMIT"
if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ] \
  && [ -x "$prefix/openssl/bin/openssl" ] \
  && [ -x "$prefix/boringssl/bin/boringssl_verify" ]; then
  echo "pinned TLS already built: $want"
  exit 0
fi

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
src=$prefix/src
rm -rf "$prefix"
mkdir -p "$src"
cd "$src"

curl -fsSL -o openssl.tar.gz \
  "https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/openssl-${OPENSSL_TAG#openssl-}.tar.gz"
printf '%s  openssl.tar.gz\n' "$OPENSSL_SHA256" | sha256sum -c -
tar -xzf openssl.tar.gz
cd "openssl-${OPENSSL_TAG#openssl-}"
./Configure --prefix="$prefix/openssl" --libdir=lib \
  --openssldir="$prefix/openssl/ssl" shared
make -j"$jobs"
make install_sw
# install_sw leaves OPENSSLDIR empty. req refuses to run without openssl.cnf.
make install_ssldirs
cd "$src"

git clone --depth 1 --branch "$BORINGSSL_TAG" \
  https://github.com/google/boringssl boringssl
cd boringssl
got=$(git rev-parse HEAD)
if [ "$got" != "$BORINGSSL_COMMIT" ]; then
  echo "BoringSSL $BORINGSSL_TAG is $got, pin says $BORINGSSL_COMMIT" >&2
  exit 1
fi
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix/boringssl"
# crypto and ssl alone are not enough. cmake --install also installs the
# bssl tool, and that target is not built unless it is named.
ninja -C build bssl
cmake --install build
mkdir -p "$prefix/boringssl/bin"
# libcrypto.a is C++. The C driver must be linked with the C++ runtime or
# sized operator delete is missing.
c++ -O2 -o "$prefix/boringssl/bin/boringssl_verify" \
  "$root/tool/interop/boringssl_verify.c" \
  -I"$prefix/boringssl/include" \
  "$prefix/boringssl/lib/libcrypto.a" \
  -pthread
printf '%s\n' "$BORINGSSL_COMMIT" > "$prefix/boringssl/COMMIT"
printf '%s\n' "$want" > "$stamp"
echo "pinned TLS built: $want"
