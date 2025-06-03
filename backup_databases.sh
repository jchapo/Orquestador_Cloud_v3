#!/bin/bash
# PUCP Cloud Orchestrator - Database Backup

BACKUP_DIR="/opt/pucp-orchestrator/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

echo "Backing up databases..."

# Backup each service database
services=("auth_service" "slice_service" "template_service" "network_service" "image_service")

for service in "${services[@]}"; do
    db_file="/opt/pucp-orchestrator/${service}/${service}.db"
    if [ -f "$db_file" ]; then
        cp "$db_file" "$BACKUP_DIR/${service}_${DATE}.db"
        echo "✓ Backed up $service database"
    else
        echo "⚠ Database not found: $db_file"
    fi
done

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.db" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR"