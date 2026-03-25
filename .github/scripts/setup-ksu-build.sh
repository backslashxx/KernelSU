# shellcheck shell=bash
TRIPLE=$1
ANDROID_SDK_LEVEL=$2
LLVM_PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

NDK_TRIPLE=$TRIPLE
if [ "$NDK_TRIPLE" = "armv7-linux-androideabi" ]; then
	NDK_TRIPLE="armv7a-linux-androideabi"
fi

CLANG_PATH="$LLVM_PATH/${NDK_TRIPLE}${ANDROID_SDK_LEVEL}-clang"
UTRIPLE="$(echo $TRIPLE | sed 's/-/_/g')"
UUTRIPLE="$(echo $UTRIPLE | tr a-z A-Z)"

export CC_$UTRIPLE="$CLANG_PATH"
export CXX_$UTRIPLE="${CLANG_PATH}++"
export AR_$UTRIPLE="$LLVM_PATH/llvm-ar"
export CARGO_TARGET_${UUTRIPLE}_LINKER="$CLANG_PATH"
