#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="LicenseManager"
OUTPUT_DIR="${SCRIPT_DIR}/output"
APPDIR="${SCRIPT_DIR}/AppDir"

# Parse -m flag (compile only, skip packaging)
BUILD_ONLY=false
if [ "$1" = "-m" ]; then
    BUILD_ONLY=true
fi

# ============================================================
# Auto-detect architecture
# ============================================================
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64|AMD64|x64)
        GMSSL_ARCH="x86_64"
        LABEL="x86_64"
        LDD_DIR="linuxdeployqt-x86_64"
        OUTPUT_SUFFIX="-x86_64"
        ;;
    aarch64|arm64)
        GMSSL_ARCH="arm"
        LABEL="arm64"
        LDD_DIR="linuxdeployqt-arm"
        OUTPUT_SUFFIX="-arm"
        ;;
    *)
        echo "Error: unsupported architecture: $ARCH"
        exit 1
        ;;
esac
echo "Detected architecture: $LABEL"

# ============================================================
# 1. Environment check
# ============================================================
echo "=============================================="
echo " LicenseManager Linux ${LABEL} Build Script"
if [ "$BUILD_ONLY" = true ]; then
    echo " Mode: Compile only (-m)"
fi
echo "=============================================="

NEEDS_INSTALL=()

if ! command -v patchelf &> /dev/null; then
    NEEDS_INSTALL+=("patchelf")
fi

if ! command -v fusermount &> /dev/null && ! command -v fusermount3 &> /dev/null; then
    NEEDS_INSTALL+=("fuse")
fi

if [ ${#NEEDS_INSTALL[@]} -gt 0 ]; then
    echo "Installing missing dependencies: ${NEEDS_INSTALL[*]}"
    sudo apt-get install -y "${NEEDS_INSTALL[@]}"
fi

LINUXDEPLOYQT="${SCRIPT_DIR}/${LDD_DIR}/linuxdeployqt"
if [ ! -f "${LINUXDEPLOYQT}" ]; then
    echo "Error: linuxdeployqt not found at ${LINUXDEPLOYQT}"
    exit 1
fi
chmod +x "${LINUXDEPLOYQT}"
echo "  linuxdeployqt: OK"

# ============================================================
# 2. Build Release
# ============================================================
echo ""
echo "[1/4] Building Release..."
cd "${PROJECT_DIR}"

mkdir -p build_release
cd build_release
qmake ../licensemanager.pro CONFIG+=release
make -j$(nproc)
cd "${PROJECT_DIR}"

APP_BIN=""
[ -f "release/${APP_NAME}" ] && APP_BIN="release/${APP_NAME}"
[ -z "${APP_BIN}" ] && [ -f "build_release/${APP_NAME}" ] && APP_BIN="build_release/${APP_NAME}"
if [ -z "${APP_BIN}" ]; then
    echo "Error: build output not found"
    exit 1
fi
echo "  Binary: ${APP_BIN}"

# If -m flag, stop here
if [ "$BUILD_ONLY" = true ]; then
    echo ""
    echo "=============================================="
    echo " Build-only complete"
    echo " Binary: ${APP_BIN}"
    echo "=============================================="
    exit 0
fi

# ============================================================
# 3. Prepare AppDir (FHS structure)
# ============================================================
echo ""
echo "[2/4] Preparing AppDir..."
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/lib"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

cp "${APP_BIN}" "${APPDIR}/usr/bin/"

# Copy GmSSL libs BEFORE linuxdeployqt
GMSSL_LIB="${PROJECT_DIR}/gmssl/${GMSSL_ARCH}/lib"
if [ -d "${GMSSL_LIB}" ]; then
    cp -f "${GMSSL_LIB}"/*.so* "${APPDIR}/usr/lib/" 2>/dev/null || true
    echo "  GmSSL libs: ${GMSSL_LIB}"
fi

ICON_FILE="${PROJECT_DIR}/images/icon.png"
if [ -f "${ICON_FILE}" ]; then
    cp "${ICON_FILE}" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png"
fi

cat > "${APPDIR}/usr/share/applications/${APP_NAME}.desktop" << EOF
[Desktop Entry]
Type=Application
Name=${APP_NAME}
Comment=License Management Tool
Exec=${APP_NAME}
Icon=${APP_NAME}
Categories=Utility;
Terminal=false
EOF

# ============================================================
# 4. Run linuxdeployqt (no -appimage flag)
# ============================================================
echo ""
echo "[3/4] Running linuxdeployqt..."
cd "${PROJECT_DIR}"

export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"

${LINUXDEPLOYQT} "${APPDIR}/usr/bin/${APP_NAME}" \
    -verbose=2 \
    -unsupported-allow-new-glibc \
    -bundle-non-qt-libs

# ============================================================
# 5. Package output as tar.gz
# ============================================================
echo ""
echo "[4/4] Packaging output..."
mkdir -p "${OUTPUT_DIR}"

TARBALL="${OUTPUT_DIR}/${APP_NAME}${OUTPUT_SUFFIX}.tar.gz"
cd "${SCRIPT_DIR}"
# Copy usr to licensemanager (works on all tar implementations)
# cp -r + rm -rf is more portable than mv or --transform on ARM/x86_64
cp -r "${APPDIR}/usr" "${APPDIR}/licensemanager"
rm -rf "${APPDIR}/usr"
tar -czf "${TARBALL}" -C "${APPDIR}" licensemanager/
cd "${PROJECT_DIR}"

echo ""
echo "=============================================="
echo " Build complete"
echo " Platform: ${LABEL}"
echo " Output: ${TARBALL}"
echo " Size: $(du -h "${TARBALL}" | cut -f1)"
echo ""
echo " Usage:"
echo "   tar -xzf ${TARBALL}"
echo "   ./licensemanager/bin/${APP_NAME}"
echo "=============================================="
