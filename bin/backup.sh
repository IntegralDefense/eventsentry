#!/bin/bash

# Get the path to this backup script.
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

# Turn that into the Event Sentry "home" directory.
ESHOME=$SCRIPTPATH/..

# Check if we were given a backup path. Otherwise default to save the backup in the Event Sentry directory.
if [ -z "$1" ]; then
    BACKUP_PATH=$ESHOME/backup.tar.gz
    touch $BACKUP_PATH
else
    BACKUP_PATH=$1/backup.tar.gz
fi

tar --exclude='.git' --exclude='.gitignore' --exclude='venv' --exclude='*__pycache__*' --exclude='*.tar.gz' -zcvf $BACKUP_PATH $ESHOME
