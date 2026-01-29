#!/bin/bash

# Get the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Navigate to the project root (assuming the script is in the scripts folder)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Define the pattern to identify <package_name>fakes folders
FAKE_FOLDER_PATTERN="*fakes"

# Find and delete all <package_name>fakes folders
echo "Searching for fakes to delete ..."
while IFS= read -r -d '' dir; do
    echo "Deleting: $dir"
    rm -rf "$dir"
done < <(find . -type d -name "$FAKE_FOLDER_PATTERN" -print0)

echo "Done."
