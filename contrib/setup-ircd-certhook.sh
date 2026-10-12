#!/bin/bash
#
# setup-ircd-certhook.sh
#
# Creates the certbot deploy hook that installs renewed Let's Encrypt
# certificates for ircd (irc2.11.2p3+0PN with native TLS) and reloads it.
# Run once as root:   sudo bash setup-ircd-certhook.sh
#
# Settings can be overridden on the command line, e.g.:
#   sudo DOMAIN=other.speakz.org bash setup-ircd-certhook.sh

set -euo pipefail

# ---- settings -------------------------------------------------------
DOMAIN="${DOMAIN:-eden.speakz.org}"           # certificate name in certbot
IRCD_HOME="${IRCD_HOME:-/home/ircd/ircd}"     # the --prefix used for ircd
IRCD_USER="${IRCD_USER:-ircd}"                # user the ircd runs as
LE_DIR="${LE_DIR:-/etc/letsencrypt}"          # certbot's directory
# ---------------------------------------------------------------------

IRCD_ETC="$IRCD_HOME/etc"
PIDFILE="$IRCD_HOME/var/run/ircd.pid"
HOOK_DIR="$LE_DIR/renewal-hooks/deploy"
HOOK="$HOOK_DIR/ircd.sh"
LIVE="$LE_DIR/live/$DOMAIN"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (sudo bash $0)"
id "$IRCD_USER" >/dev/null 2>&1 || die "user '$IRCD_USER' does not exist"
[ -d "$IRCD_ETC" ] || die "$IRCD_ETC not found - is IRCD_HOME right?"
[ -f "$IRCD_ETC/ircd.conf" ] || echo "WARNING: no ircd.conf in $IRCD_ETC yet"

echo "Creating $HOOK_DIR"
mkdir -p "$LE_DIR/renewal-hooks/pre" "$LE_DIR/renewal-hooks/post" "$HOOK_DIR"
chmod 755 "$LE_DIR/renewal-hooks" "$HOOK_DIR"

echo "Writing $HOOK"
cat > "$HOOK" <<EOF
#!/bin/sh
#
# certbot deploy hook: install the renewed certificate for ircd and
# reload it with SIGHUP (connected users are not disconnected).
# Created by setup-ircd-certhook.sh.  certbot sets RENEWED_LINEAGE.

DOMAIN="$DOMAIN"
IRCD_ETC="$IRCD_ETC"
IRCD_USER="$IRCD_USER"
PIDFILE="$PIDFILE"

# Only act on our certificate (certbot runs every hook for every cert).
case "\$RENEWED_LINEAGE" in
    */live/"\$DOMAIN") ;;
    *) exit 0 ;;
esac

log() { logger -t ircd-certhook "\$*" 2>/dev/null; echo "ircd-certhook: \$*"; }

for f in fullchain.pem privkey.pem; do
    if [ ! -s "\$RENEWED_LINEAGE/\$f" ]; then
        log "missing \$RENEWED_LINEAGE/\$f, nothing installed"
        exit 1
    fi
done

# Install via temporary files so ircd never sees a half-written file.
install -m 644 -o "\$IRCD_USER" "\$RENEWED_LINEAGE/fullchain.pem" "\$IRCD_ETC/ircd.crt.new" &&
install -m 600 -o "\$IRCD_USER" "\$RENEWED_LINEAGE/privkey.pem"   "\$IRCD_ETC/ircd.key.new" &&
mv -f "\$IRCD_ETC/ircd.crt.new" "\$IRCD_ETC/ircd.crt" &&
mv -f "\$IRCD_ETC/ircd.key.new" "\$IRCD_ETC/ircd.key" || {
    log "failed to install certificate into \$IRCD_ETC"
    exit 1
}
log "installed certificate for \$DOMAIN into \$IRCD_ETC"

if [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
    kill -HUP "\$(cat "\$PIDFILE")" && log "ircd reloaded (SIGHUP)"
else
    log "ircd not running, it will use the new certificate when started"
fi
exit 0
EOF
chmod 755 "$HOOK"

echo
if [ -s "$LIVE/fullchain.pem" ]; then
    echo "Certificate found, installing it now:"
    RENEWED_LINEAGE="$LIVE" "$HOOK"
    ls -l "$IRCD_ETC/ircd.crt" "$IRCD_ETC/ircd.key"
else
    echo "No certificate in $LIVE yet. Get one first:"
    echo "    certbot certonly --standalone -d $DOMAIN"
    echo "then run:"
    echo "    RENEWED_LINEAGE=$LIVE $HOOK"
fi
echo
echo "Done. certbot will run $HOOK after every renewal."
