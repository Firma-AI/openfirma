#!/bin/bash
set -e

echo "firma-agent: Waiting for CA certificate..."

TIMEOUT=30
while [ ! -f /certs/firma-ca.pem ] || [ ! -s /certs/firma-ca.pem ]; do
    if [ "$TIMEOUT" -le 0 ]; then
        echo "firma-agent: ERROR - Timed out waiting for CA certificate"
        exit 1
    fi
    sleep 1
    ((TIMEOUT--))
done

echo "firma-agent: CA certificate found, building combined bundle..."

cat /etc/ssl/certs/ca-certificates.crt /certs/firma-ca.pem > /tmp/combined-ca.pem
chmod 0644 /tmp/combined-ca.pem

export SSL_CERT_FILE=/tmp/combined-ca.pem
echo "firma-agent: SSL_CERT_FILE set to $SSL_CERT_FILE"

mkdir -p /data/database /data/emails
chown -R agent:agent /data/database /data/emails

exec su -s /bin/bash agent -c "SSL_CERT_FILE=$SSL_CERT_FILE python -m agent.main"
