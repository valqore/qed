#!/bin/sh
# Collect the shared libraries the runtime image needs (deploy/Dockerfile).
#
# Run inside the builder, which still has a shell and `ldd`. The distroless
# runtime has neither, so what the loader will be able to find there is decided
# here -- and the only way to get it right is to ask the objects themselves
# rather than keep a list of Debian package names in a comment.
set -eu

STAGE=/stage/libs
mkdir -p "$STAGE"

# Every ELF object that will be in the runtime image: the interpreter, the
# standard library's own extension modules in lib-dynload, and the compiled
# extensions in the installed tree.
#
# lib-dynload is the one that is easy to leave out, and the symptom is remote
# from the cause: `import base64` fails on a missing libz, because `binascii`
# is one of those extensions.
find /install /usr/local/lib/python3.12 /usr/local/bin/python3.12 -type f \
	\( -name 'python3.12' -o -name '*.so' -o -name '*.so.*' \) > /tmp/objects

# Resolve each one's dependencies. `ldd` prints some entries with no path at
# all -- linux-vdso, the loader itself -- so only absolute ones are kept.
while read -r object; do
	ldd "$object" 2>/dev/null |
		awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }'
done < /tmp/objects | sort -u > /tmp/libs

# Two exclusions.
#
# glibc and the dynamic loader come from the distroless base, which is built
# from the same Debian 12 release. Copying ours over them would replace a base
# the image is signed against with one it is not.
#
# Anything inside the Python tree or the installed tree arrives with it: a
# wheel's bundled libraries (psycopg's, for one) are found through its own
# RPATH, and flattening them into a system directory would put a second copy
# somewhere nothing looks.
#
# Note how narrow the second pattern is. `/usr/local/` as a whole would also
# exclude libpython3.12.so.1.0, which sits in /usr/local/lib beside the tree
# rather than inside it -- and without it the interpreter does not start at
# all: `error while loading shared libraries: libpython3.12.so.1.0`.
grep -vE '/(ld-linux|libc|libm|libdl|libpthread|librt|libresolv|libnsl|libutil)[-.]' /tmp/libs |
	grep -vE '^(/usr/local/lib/python3[.]12/|/install/)' > /tmp/extra || true

# Fail here rather than at import time in a cluster: an empty list means `ldd`
# found nothing, which cannot be true and would otherwise produce an image that
# builds cleanly and cannot start.
test -s /tmp/extra

# -L because several of these are symlinks into the same directory; the runtime
# image wants the real file under the soname the loader asks for.
while read -r lib; do
	cp -L "$lib" "$STAGE/$(basename "$lib")"
done < /tmp/extra

echo "staged $(wc -l < /tmp/extra) libraries into $STAGE"
