#!/bin/bash
# P/M build pipeline — corrected version
# NOTE: must run on x86_64 Linux (aapt2 + NDK are x86_64-only binaries).
set -e
cd "$(dirname "$0")"

# System dependencies (fixed package names for Debian/Kali/Ubuntu 24.04+)
# Non-fatal: bail-outs here merely skip redundant installs if tools already exist
dpkg --configure -a >/dev/null 2>&1 || true
apt-get update >/dev/null 2>&1 || true
apt-get install -y \
    build-essential git ffmpeg libsdl2-dev libsdl2-image-dev \
    libsdl2-mixer-dev libsdl2-ttf-dev libportmidi-dev libswscale-dev \
    libavformat-dev libavcodec-dev zlib1g-dev libgstreamer1.0-dev \
    gstreamer1.0-plugins-base gstreamer1.0-plugins-good libsqlite3-dev \
    sqlite3 bzip2 libbz2-dev libssl-dev openssl libgdbm-dev \
    libgdbm-compat-dev liblzma-dev libreadline-dev libncursesw5-dev \
    libncurses-dev libffi-dev uuid-dev unzip zip \
    autoconf automake libtool pkg-config \
    || echo "WARNING: apt phase failed — continuing on already-present tools"

# JDK: prefer 17 (required by modern AGP); fall back where the distro lacks it
apt-get install -y openjdk-17-jdk \
    || apt-get install -y default-jdk 2>/dev/null \
    || true

# Pick the newest compatible JDK already present (Gradle ≤8.x cannot run on Java 21+)
for cand in /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-11-openjdk-* /usr/lib/jvm/java-1.11.0-openjdk-* /usr/lib/jvm/java-21-openjdk-*; do
    [ -x "$cand/bin/java" ] && export JAVA_HOME="$cand" && break
done

# Python build tooling (was missing in original script)
export PIP_BREAK_SYSTEM_PACKAGES=1
pip3 install --quiet --break-system-packages buildozer cython

yes y | buildozer android debug
