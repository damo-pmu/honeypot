#!/bin/bash
# Inject PG_PASS into config and start Cowrie
sed "s/{{PG_PASS}}/${PG_PASS}/" /cowrie/cowrie.cfg.template > /cowrie/cowrie-git/etc/cowrie.cfg
exec /cowrie/cowrie-env/bin/twistd -n --umask=0022 --pidfile= cowrie