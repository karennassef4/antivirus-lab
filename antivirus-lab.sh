./antivirus.sh dir malicious_dir interval-secs
#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: $0 <dir> <malicious_dir> <interval_secs>"
    exit 1
fi

DIR="$1"
MALICIOUS_DIR="$2"
INTERVAL="$3"

FLAGGED_EXTENSIONS=".exe .bat .vbs .scr .ps1"
FLAGGED_KEYWORDS="virus trojan malware worm ransomware"

is_malicious() {
    local file="$1"
    
    for ext in $FLAGGED_EXTENSIONS; do
        if [[ "$file" == *"$ext" ]]; then
            return 0  
        fi
    done
    
    for keyword in $FLAGGED_KEYWORDS; do
        if grep -qi "$keyword" "$file" 2>/dev/null; then
            return 0  
        fi
    done
    
    return 1  

}


LAST_FILE="directory-info.last"
NEW_FILE="directory-info.new"


if [ ! -f "$LAST_FILE" ]; then
    echo "First run: scanning $DIR"
    scan_and_quarantine
    ls -l "$DIR" > "$LAST_FILE"
fi

# Infinite loop 34an yfdal 3ala tol
while true; do
    sleep "$INTERVAL"
    
    # ka2eno bya5od screenshot 7alan
    ls -l "$DIR" > "$NEW_FILE"
    
    if ! diff -q "$LAST_FILE" "$NEW_FILE" > /dev/null 2>&1; then
        
        echo "Change detected in $DIR, scanning..."
        scan_and_quarantine
        
        cp "$NEW_FILE" "$LAST_FILE"
    fi
done

./restore.sh dir malicious_dir

#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <dir> <malicious_dir>"
    exit 1
fi

DIR="$1"
MALICIOUS_DIR="$2"

if [ -z "$(ls -A "$MALICIOUS_DIR" 2>/dev/null)" ]; then
    echo "No malicious files to review."
    exit 0
fi

while true; do
    files=("$MALICIOUS_DIR"/*)
    
    # Check if empty after restores
    if [ ${#files[@]} -eq 0 ] || [ ! -e "${files[0]}" ]; then
        echo "No malicious files to review."
        break
    fi
    
    echo ""
    echo " Quarantined Files"
    i=1
    for f in "${files[@]}"; do
        [ -e "$f" ] || continue
        echo "$i) $(basename "$f")"
        ((i++))
    done
    echo "0) Exit"
    
    read -p "Pick a file by number: " choice
    
    if [ "$choice" -eq 0 ] 2>/dev/null; then
        echo "Exiting restore tool."
        break
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#files[@]} ]; then
        echo "Invalid choice."
        continue
    fi
    
    selected="${files[$((choice-1))]}"
    
    if [ ! -e "$selected" ]; then
        echo "File no longer exists."
        continue
    fi
    
    filename=$(basename "$selected")
    
    echo ""
    echo "Selected: $filename"
    echo "1) Restore this file back into $DIR (false positive)"
    echo "2) Permanently delete this file (genuinely malicious)"
    echo "3) Leave as-is and go back"
    
    read -p "Choose option: " action
    
    case "$action" in
        1)
            cp "$selected" "$DIR/$filename"
            rm "$selected"
            echo "Restored $filename to $DIR."
            ;;
        2)
            rm "$selected"
            echo "$filename permanently deleted."
            ;;
        3)
            echo "Leaving $filename as-is."
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done


# Makefile

DIR = dir
MALICIOUS_DIR = malicious_dir
INTERVAL = 5

# Pre-build
$(MALICIOUS_DIR):
	mkdir -p $(MALICIOUS_DIR)

prebuild: $(MALICIOUS_DIR)
	@echo "Pre-build done: $(MALICIOUS_DIR) ready."

antivirus: prebuild
	./antivirus.sh $(DIR) $(MALICIOUS_DIR) $(INTERVAL)

restore: prebuild
	./restore.sh $(DIR) $(MALICIOUS_DIR)

clean:
	rm -f directory-info.last directory-info.new
	rm -rf $(MALICIOUS_DIR)

.PHONY: antivirus restore prebuild clean

make antivirus   
make restore      
make clean        

#cron
crontab -e
23 * * * * /path/to/antivirus-cron.sh /path/to/dir /path/to/malicious_dir
1 0 * * 5#3 /path/to/antivirus-cron.sh /path/to/dir /path/to/malicious_dir

#whitelist

WHITELIST_FILE="whitelist.txt"

is_whitelisted() {
    local filename="$1"
    [ -f "$WHITELIST_FILE" ] && grep -qx "$filename" "$WHITELIST_FILE"
}

scan_and_quarantine() {
    for file in "$DIR"/*; do
        [ -f "$file" ] || continue
        filename=$(basename "$file")
        
        # Skip whitelisted
        if is_whitelisted "$filename"; then
            continue
        fi
        
        if is_malicious "$file"; then
            echo "$filename is malicious and it is DELETED"
            cp "$file" "$MALICIOUS_DIR/$filename"
            rm "$file"
        fi
    done
}

if [ "$action" = "1" ]; then
    cp "$selected" "$DIR/$filename"
    rm "$selected"
    echo "Restored $filename to $DIR."
    echo "$filename" >> whitelist.txt
fi
