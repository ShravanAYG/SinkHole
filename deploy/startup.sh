#!/bin/sh
set -e

echo "======================================================"
echo "         SinkHole Bot Detection Gateway                "
echo "======================================================"
echo "  Protecting: ${UPSTREAM_URL}"
echo "  Botwall:    ${BOTWALL_URL}"
echo "======================================================"

# Render the Nginx template with environment variables
envsubst '${UPSTREAM_URL} ${BOTWALL_URL}' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/sites-available/default

# Ensure the site is enabled
ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Start Supervisor (which manages both Nginx and Botwall)
exec supervisord -c /etc/supervisor/conf.d/supervisord.conf
