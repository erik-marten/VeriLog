#!/bin/sh

# Run the Java build from the repository root without duplicating its wrapper.
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/VeriLogJava" && pwd) || exit 1
exec "$project_dir/gradlew" --project-dir "$project_dir" "$@"
