#!/bin/bash

# ============================================================
# C3A: Custom Automation Script
# Author: Peter Mwangi
# Course: AH 200 Cohort 6 - Africahackon Training
# Description: A system automation script that performs
#              maintenance, notifications, file organisation,
#              cleanup, and backup tasks.
# ============================================================

# --- CONFIGURATION ---
LOG_FILE="$HOME/script_log.txt"
BACKUP_DIR="$HOME/backups"
ORGANISE_DIR="$HOME/organised_files"
TXT_DIR="$ORGANISE_DIR/text_files"
LOG_DIR_SORTED="$ORGANISE_DIR/log_files"
TIMESTAMP=$(date "+%Y-%m-%d_%H-%M-%S")

# --- LOGGING FUNCTION ---
log_message() {
    local MESSAGE="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$MESSAGE"
    echo "$MESSAGE" >> "$LOG_FILE"
}

# --- PROGRESS BAR FUNCTION (Bonus Challenge) ---
progress_bar() {
    local DURATION=$1
    local BAR=""
    for i in $(seq 1 20); do
        BAR="${BAR}#"
        printf "\r  Progress: [%-20s] %d%%" "$BAR" $((i * 5))
        sleep $(echo "$DURATION / 20" | bc -l)
    done
    echo ""
}

# ============================================================
# BONUS CHALLENGE: User Input Prompt
# ============================================================
echo ""
echo "============================================"
echo "   C3A System Automation Script"
echo "   By Peter Mwangi | AH 200 Cohort 6"
echo "============================================"
echo ""

read -p "Do you want to continue? (y/n): " USER_CHOICE

if [[ "$USER_CHOICE" != "y" && "$USER_CHOICE" != "Y" ]]; then
    echo "Script cancelled by user. Exiting."
    exit 0
fi

echo ""
log_message "===== Script started by user: $USER ====="

# ============================================================
# TASK 1: SYSTEM MAINTENANCE
# Checks disk usage and deletes log files older than 7 days
# ============================================================
log_message "TASK 1: Starting system maintenance..."
echo ""
echo "[1/5] Running system maintenance..."

DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')
log_message "  Current disk usage on /: $DISK_USAGE"
echo "  Disk usage on /: $DISK_USAGE"

DELETED_COUNT=0
while IFS= read -r OLD_LOG; do
    log_message "  Deleting old log: $OLD_LOG"
    rm -f "$OLD_LOG"
    ((DELETED_COUNT++))
done < <(find /tmp -name "*.log" -type f -mtime +7 2>/dev/null)

if [ "$DELETED_COUNT" -eq 0 ]; then
    log_message "  No log files older than 7 days found in /tmp."
else
    log_message "  Deleted $DELETED_COUNT old log file(s)."
fi

progress_bar 1
log_message "TASK 1: System maintenance complete."
echo ""

# ============================================================
# TASK 2: USER NOTIFICATIONS
# Displays a system message before performing a package update
# ============================================================
log_message "TASK 2: Starting user notifications..."
echo "[2/5] Sending user notification..."

echo "  System will reboot soon"
log_message "  Notification sent: 'System will reboot soon'"

log_message "  Checking for available package updates..."
echo "  Checking for updates (this may take a moment)..."

if command -v apt &>/dev/null; then
    UPDATE_INFO=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
    log_message "  Packages available for update: $UPDATE_INFO"
    echo "  Packages available for update: $UPDATE_INFO"
else
    log_message "  apt not available — skipping update check."
    echo "  apt not available on this system."
fi

progress_bar 1
log_message "TASK 2: User notification complete."
echo ""

# ============================================================
# TASK 3: FILE ORGANISATION
# Moves .txt and .log files from HOME into sorted directories
# ============================================================
log_message "TASK 3: Starting file organisation..."
echo "[3/5] Organising files..."

mkdir -p "$TXT_DIR" "$LOG_DIR_SORTED"
log_message "  Destination folders ready: $TXT_DIR | $LOG_DIR_SORTED"

TXT_MOVED=0
for FILE in "$HOME"/*.txt; do
    if [ -f "$FILE" ]; then
        mv -f "$FILE" "$TXT_DIR/"
        log_message "  Moved: $FILE -> $TXT_DIR/"
        ((TXT_MOVED++))
    fi
done

LOG_MOVED=0
for FILE in "$HOME"/*.log; do
    if [ -f "$FILE" ]; then
        mv -f "$FILE" "$LOG_DIR_SORTED/"
        log_message "  Moved: $FILE -> $LOG_DIR_SORTED/"
        ((LOG_MOVED++))
    fi
done

log_message "  Files moved — .txt: $TXT_MOVED | .log: $LOG_MOVED"
echo "  .txt files moved: $TXT_MOVED | .log files moved: $LOG_MOVED"

progress_bar 1
log_message "TASK 3: File organisation complete."
echo ""

# ============================================================
# TASK 4: SCHEDULED CLEANUP
# Deletes temporary files from /tmp every time the script runs
# ============================================================
log_message "TASK 4: Starting scheduled cleanup..."
echo "[4/5] Cleaning up temporary files..."

TEMP_DELETED=0
while IFS= read -r TEMP_FILE; do
    rm -f "$TEMP_FILE"
    log_message "  Deleted temp file: $TEMP_FILE"
    ((TEMP_DELETED++))
done < <(find /tmp -maxdepth 1 -type f -name "tmp_*" 2>/dev/null)

if [ "$TEMP_DELETED" -eq 0 ]; then
    log_message "  No temporary files matching 'tmp_*' found in /tmp."
    echo "  No matching temp files found."
else
    log_message "  Deleted $TEMP_DELETED temporary file(s)."
    echo "  Deleted $TEMP_DELETED temporary file(s)."
fi

progress_bar 1
log_message "TASK 4: Scheduled cleanup complete."
echo ""

# ============================================================
# TASK 5: BACKUP AUTOMATION
# Copies important files to a timestamped backup folder
# ============================================================
log_message "TASK 5: Starting backup automation..."
echo "[5/5] Running backup..."

BACKUP_DEST="$BACKUP_DIR/backup_$TIMESTAMP"
mkdir -p "$BACKUP_DEST"
log_message "  Backup destination created: $BACKUP_DEST"

if [ -d "$ORGANISE_DIR" ]; then
    cp -r "$ORGANISE_DIR" "$BACKUP_DEST/"
    log_message "  Backed up: $ORGANISE_DIR -> $BACKUP_DEST/"
    echo "  Backed up organised_files to: $BACKUP_DEST"
else
    log_message "  No organised_files directory found — skipping backup of that folder."
fi

cp "$LOG_FILE" "$BACKUP_DEST/script_log_backup_$TIMESTAMP.txt" 2>/dev/null
log_message "  Log file backed up to: $BACKUP_DEST/"

progress_bar 1
log_message "TASK 5: Backup automation complete."
echo ""

# ============================================================
# SCRIPT COMPLETE
# ============================================================
log_message "===== All tasks completed successfully. ====="
echo "============================================"
echo "  All tasks completed!"
echo "  Log saved to: $LOG_FILE"
echo "  Backup saved to: $BACKUP_DEST"
echo "============================================"
echo ""
