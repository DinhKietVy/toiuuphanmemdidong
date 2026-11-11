#!/usr/bin/env bash
# Build tracee-android (Go part) for the x86_64 Android emulator.
# Same toolchain settings as used previously by hand.
set -euo pipefail
cd "$(dirname "$0")/.."

export NDK="$HOME/Android/ndk/android-ndk-r30"
export TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export ELF_PREFIX="$HOME/android-deps/elfutils-android"
export CC="$TOOLCHAIN/x86_64-linux-android24-clang"
export CGO_ENABLED=1
export GOOS=android
export GOARCH=amd64
export CGO_CFLAGS="-I$PWD/dist/libbpf/usr/include -I$ELF_PREFIX/include"
export CGO_LDFLAGS="-L$ELF_PREFIX/lib -Wl,--start-group $PWD/dist/libbpf/libbpf.a $ELF_PREFIX/lib/libelf.a -Wl,--end-group -lz"

gofmt -l tracee/tracee.go
go vet ./tracee/ 2>&1 | grep -v '^#' | head -20 || true
go build -o dist/tracee-android \
  -ldflags "-X main.bpfBundleInjected=$(base64 -w 0 dist/tracee.bpf.tar.gz) -X main.version=dev" .
ls -l dist/tracee-android
