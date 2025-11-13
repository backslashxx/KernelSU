#!/bin/sh

# KernelSU: adapt to CONFIG_UIDGID_STRICT_TYPE_CHECKS=n
# this is meant for 3.0, 3.4 and 3.10 where uid is uid itself not uid.val

# remove all .val
sed -i 's|\.val||g' *.c *.h

# since cmd.value will be affected, we have to restore it
sed -i 's|cmdue|cmd.value|g' *.c *.h

# EOF
