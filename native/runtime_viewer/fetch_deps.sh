#!/bin/sh
set -eu

viewer_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deps_root="$viewer_root/.deps"
mkdir -p "$deps_root"

fetch_archive() {
    dep_name=$1
    dep_url=$2
    dep_sha256=$3
    dep_destination="$deps_root/$dep_name"
    dep_stamp="$dep_destination/.pwnc-source-sha256"
    if [ -f "$dep_stamp" ] && [ "$(sed -n '1p' "$dep_stamp")" = "$dep_sha256" ]; then
        return
    fi

    dep_temporary=$(mktemp -d "$deps_root/.fetch-${dep_name}.XXXXXX")
    dep_archive="$dep_temporary/source.tar.gz"
    dep_extract="$dep_temporary/extract"
    mkdir "$dep_extract"
    curl -fsSL "$dep_url" -o "$dep_archive"
    printf '%s  %s\n' "$dep_sha256" "$dep_archive" | sha256sum -c -
    tar -xzf "$dep_archive" --strip-components=1 -C "$dep_extract"

    case "$dep_destination" in
        "$deps_root"/*) ;;
        *) echo "refusing unsafe dependency destination: $dep_destination" >&2; exit 1 ;;
    esac
    if [ -e "$dep_destination" ]; then
        rm -rf -- "$dep_destination"
    fi
    mv "$dep_extract" "$dep_destination"
    printf '%s\n' "$dep_sha256" > "$dep_stamp"
    rm -rf -- "$dep_temporary"
}

fetch_archive \
    imgui \
    https://codeload.github.com/ocornut/imgui/tar.gz/8936b58fe26e8c3da834b8f60b06511d537b4c63 \
    a1e4443190d78976e0901039dd2207e1d59a4b5b818489232568bdb69ff79ce6
fetch_archive \
    sdl2 \
    https://codeload.github.com/libsdl-org/SDL/tar.gz/859844eae358447be8d66e6da59b6fb3df0ed778 \
    750da7568827352ecede4cd080445cffd42f76daf794519ed84675b59f9b3c39
fetch_archive \
    json \
    https://codeload.github.com/nlohmann/json/tar.gz/55f93686c01528224f448c19128836e7df245f72 \
    67f4cdd9ca930c9c1e130af4a437c7fc98fab77a2846fc2d2a14b4943831f8ef
