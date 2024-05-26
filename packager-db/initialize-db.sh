#!/bin/sh -ex

# Check if the liquibase.properties file exists
if [ ! -e ./liquibase.properties ]; then
  echo "Unable to read /config/liquibase.properties!"
  exit 1
fi

/usr/local/bin/docker-entrypoint.sh postgres &

# Wait for PostgreSQL to be ready
until pg_isready -U $POSTGRES_USER -p 5432; do
  echo 'Waiting for PostgreSQL to become available...'
  sleep 5
done

# Run Liquibase update
liquibase --changelog-file=master.xml update

# Use tail to keep the container running
tail -f /dev/null