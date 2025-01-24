set -xe
# ttyS0 is used for logging
# the init in initramfs seem to support autodetect_serial=0 then console=ttyS0
# but setting kernel flags probably doesn't worth the trouble.
# see https://wiki.debian.org/initramfs, the script which writes ttyS1 is in
# /init
sed -i -e 's/ttyS0::respawn:/ttyS0::off:/g' /etc/inittab
echo 'SYSLOGD_OPTS=\"-tO/dev/ttyS0\"' >/etc/conf.d/syslog
rc-update add klogd boot

# configure local scripts on boot
rc-update add local default
echo 'rc_verbose=yes' >> /etc/conf.d/local
# echo 'rc_verbose=yes' >> /etc/rc.conf
echo 'rc_logger=yes' >> /etc/rc.conf

for fn in /mnt/*.start /mnt/*.stop; do 
    [ -e "$fn" ] || continue
    cp "$fn" "/etc/local.d"
    chmod +x "/etc/local.d/`basename "$fn"`"
done

# install alpine, this step will succeed in all steps except writing disk
# we do this now to initialize networking and apk smoothly
ERASE_DISKS=/dev/sda setup-alpine -e -f /mnt/setup-alpine.ans

# configure additional repos
apk add --no-progress -q nfs-utils zfs

echo 'OPTS_RPC_NFSD="--no-udp -N3 8"' >> /etc/conf.d/nfs
echo 'OPTS_RPC_MOUNTD="--no-udp -N3"' >> /etc/conf.d/nfs
rc-update add nfs default
rc-update add zfs-import default
rc-update add zfs-mount default

# this writes to disk after everything configured
DEFAULT_DISK=none ERASE_DISKS=/dev/sda setup-disk -q -m sys -s0 /dev/sda
