#!/usr/bin/env python3
# urllist_manager.py

import json
import os
import argparse
import sys
from typing import Dict, Any

DEFAULT_FILENAME = "urllist.json"

def load_data(filepath: str) -> Dict[str, Any]:
    """Loads the URL cache data from the specified JSON file."""
    if not os.path.exists(filepath):
        print(f"Info: Cache file '{filepath}' not found. Starting with empty data.", file=sys.stderr)
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                print(f"Error: Cache file '{filepath}' does not contain a valid JSON dictionary.", file=sys.stderr)
                sys.exit(1)
            print(f"Successfully loaded {len(data)} entries from '{filepath}'.")
            return data
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from cache file '{filepath}'.", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error: Could not read cache file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred while loading '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)

def save_data(filepath: str, data: Dict[str, Any]):
    """Saves the URL cache data to the specified JSON file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str) # Use default=str for safety
        print(f"Successfully saved {len(data)} entries to '{filepath}'.")
    except IOError as e:
        print(f"Error: Could not write cache file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except TypeError as e:
        print(f"Error: Failed to serialize data for '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred while saving '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)

def list_entries(data: Dict[str, Any]):
    """Lists all keys (normalized URLs) in the cache."""
    if not data:
        print("The URL cache is empty.")
        return

    print(f"\n--- Cached URLs ({len(data)} entries) ---")
    # Sort keys for consistent output
    sorted_keys = sorted(data.keys())
    for i, key in enumerate(sorted_keys):
        # Optionally display more info from the value dict if needed
        # risk_count = len(data[key].get('analysis_data', {}).get('overall_summary', {}).get('potential_risks', []))
        # llm_class = data[key].get('llm_classification', {}).get('classification', 'N/A')
        # print(f"{i+1}. {key} (Risks: {risk_count}, LLM: {llm_class})")
        print(f"{i+1}. {key}")
    print("--- End of List ---")

def search_entries(data: Dict[str, Any], term: str):
    """Searches for keys containing the given term (case-insensitive)."""
    if not data:
        print("The URL cache is empty. Cannot search.")
        return

    term_lower = term.lower()
    matches = {key: value for key, value in data.items() if term_lower in key.lower()}

    if not matches:
        print(f"\nNo cached URLs found containing '{term}'.")
        return

    print(f"\n--- URLs containing '{term}' ({len(matches)} matches) ---")
    sorted_keys = sorted(matches.keys())
    for i, key in enumerate(sorted_keys):
        print(f"{i+1}. {key}")
    print("--- End of Search Results ---")

def delete_entry(data: Dict[str, Any], key_to_delete: str, force: bool) -> bool:
    """Deletes a specific entry by its exact key."""
    if key_to_delete not in data:
        print(f"\nError: URL key '{key_to_delete}' not found in the cache.", file=sys.stderr)
        return False # Indicate no change was made

    print(f"\nFound entry for key: '{key_to_delete}'")

    if not force:
        confirm = input("Are you sure you want to delete this entry? (yes/No): ").lower().strip()
        if confirm not in ['y', 'yes']:
            print("Deletion cancelled.")
            return False # Indicate no change was made

    # Proceed with deletion
    try:
        del data[key_to_delete]
        print(f"Successfully deleted entry for '{key_to_delete}'.")
        return True # Indicate data was modified
    except Exception as e:
        print(f"Error: An unexpected error occurred during deletion: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description=f"Manage the URL analysis cache file ({DEFAULT_FILENAME})."
    )
    parser.add_argument(
        '-f', '--file',
        default=DEFAULT_FILENAME,
        help=f"Path to the URL cache JSON file (default: {DEFAULT_FILENAME})"
    )

    subparsers = parser.add_subparsers(dest='command', required=True, help='Action to perform')

    # --- List Command ---
    parser_list = subparsers.add_parser('list', help='List all cached URLs.')

    # --- Search Command ---
    parser_search = subparsers.add_parser('search', help='Search for cached URLs containing a specific term.')
    parser_search.add_argument(
        'term',
        help='The domain or text substring to search for within the cached URLs.'
    )

    # --- Delete Command ---
    parser_delete = subparsers.add_parser('delete', help='Delete a specific URL entry by its exact key.')
    parser_delete.add_argument(
        'key',
        help='The exact normalized URL key to delete (use list or search to find keys).'
    )
    parser_delete.add_argument(
        '--force',
        action='store_true',
        help='Force deletion without confirmation.'
    )

    args = parser.parse_args()

    # Load the data
    url_data = load_data(args.file)
    data_modified = False # Flag to track if saving is needed

    # Execute the chosen command
    if args.command == 'list':
        list_entries(url_data)
    elif args.command == 'search':
        search_entries(url_data, args.term)
    elif args.command == 'delete':
        data_modified = delete_entry(url_data, args.key, args.force)
    else:
        # Should not happen if subparsers are required=True
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        sys.exit(1)

    # Save data only if modified
    if data_modified:
        save_data(args.file, url_data)

if __name__ == "__main__":
    main()