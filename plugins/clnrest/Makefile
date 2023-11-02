upgrade-version:
	if [ -z "$(NEW_VERSION)" ]; then echo "Set NEW_VERSION!" >&2; exit 1; fi
	poetry version $(NEW_VERSION)