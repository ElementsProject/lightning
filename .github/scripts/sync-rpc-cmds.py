import os
from time import sleep
import requests
import re
from enum import Enum

# readme url
BRANCH = "stable"
URL = f"https://api.readme.com/v2/branches/{BRANCH}"
CATEGORY_SLUG = "JSON-RPC"
NOTIFICATIONS_CATEGORY_SLUG = "Notifications"
HOOKS_CATEGORY_SLUG = "Hooks"


class Action(Enum):
    ADD = 'add'
    UPDATE = 'update'
    DELETE = 'delete'


def getListOfDocs(headers, category):
    response = requests.get(f"{URL}/categories/reference/{category}/pages", headers=headers)
    if response.status_code == 200:
        return response.json().get('data', [])
    else:
        print(f"❌ Failed to get pages: {response.status_code}")
        print(response.text)
        return []


def check_renderable(response, action, title):
    try:
        data = response.json()
    except Exception:
        print("Non-JSON response:")
        print(response.text)
        return False

    renderable = data.get("renderable")
    if renderable is None:
        # Some endpoints don't include renderable (e.g. DELETE)
        return True

    if not renderable.get("status", False):
        print(f"\n❌ RENDER FAILED for {action.value.upper()} '{title}'")
        print("Error  :", renderable.get("error"))
        print("Message:", renderable.get("message"))
        return False

    return True


def publishDoc(action, title, body, position, headers, category):
    payload = {
        "title": get_display_name(title),
        "type": "basic",
        "content": {
            "body": body,
        },
        "category": {
            "uri": f"/branches/{BRANCH}/categories/reference/{category}"
        },
        "hidden": False,
        "position": position,
    }

    if action == Action.ADD:
        payload["slug"] = title
        response = requests.post(URL + "/reference", json=payload, headers=headers)
        if response.status_code != 201:
            print(f"❌ HTTP ERROR ({response.status_code}):", title)
            print(response.text)
            return

        if not check_renderable(response, action, title):
            raise RuntimeError(f"Renderable check failed for {title}")

        print(f"✅ Created '{title}' at position {position + 1}")

    elif action == Action.UPDATE:
        response = requests.patch(f"{URL}/reference/{title}", json=payload, headers=headers)
        if response.status_code != 200:
            print(f"❌ HTTP ERROR ({response.status_code}):", title)
            print(response.text)
            return

        if not check_renderable(response, action, title):
            raise RuntimeError(f"Renderable check failed for {title}")

        print(f"✅ Updated '{title}' to position {position + 1}")

    elif action == Action.DELETE:
        response = requests.delete(f"{URL}/reference/{title}", headers=headers)

        if response.status_code != 204:
            print(f"❌ DELETE FAILED ({response.status_code}):", title)
            print(response.text)
        else:
            print(f"🗑️  Deleted '{title}' from position {position + 1}")

    else:
        print("Invalid action")


def extract_all_from_rst(rst_content):
    manpages_block = re.search(
        r"\.\. block_start manpages(.*?)\.\. block_end manpages",
        rst_content,
        re.DOTALL,
    )

    if not manpages_block:
        return [], [], []

    entries = re.findall(
        r"^\s*([a-zA-Z0-9_-]+)\s+<([^>]+)>",
        manpages_block.group(1),
        re.MULTILINE,
    )

    rpc_commands = []
    notifications = []
    hooks = []

    for name, target in entries:
        if name.startswith("notification-"):
            notifications.append((name, target))
        elif name.startswith("hook-"):
            hooks.append((name, target))
        else:
            rpc_commands.append((name, target))

    return rpc_commands, notifications, hooks


def sync_docs(local_items, readme_items, category_slug, headers, label):
    local_titles = {name for name, _ in local_items}
    readme_titles = {item['slug'] for item in readme_items}

    to_delete = readme_titles - local_titles
    to_add = local_titles - readme_titles

    # Deletions
    for name in to_delete:
        publishDoc(Action.DELETE, name, "", 0, headers, category_slug)
        sleep(1)

    # Add / Update
    if not local_items:
        print(f"⚠️  No {label} found in the Manpages block.")
        return

    position = 0
    for name, file in local_items:
        file_path = os.path.join("doc", file)

        if not os.path.exists(file_path):
            print(f"⚠️  WARNING: File not found: {file_path}, skipping {name}")
            continue

        with open(file_path) as f:
            body = f.read()

        action = Action.ADD if name in to_add else Action.UPDATE
        publishDoc(action, name, body, position, headers, category_slug)

        position += 1
        sleep(1)


def get_display_name(name):
    if name.startswith("notification-"):
        return name[len("notification-"):]
    if name.startswith("hook-"):
        return name[len("hook-"):]
    return name


def main():
    # define headers for requests
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": "Bearer " + os.environ.get("README_API_KEY"),
    }

    # Validate API key exists
    if not os.environ.get("README_API_KEY"):
        print("❌ ERROR: README_API_KEY environment variable not set")
        return

    # path to the rst file from where we fetch all the RPC commands
    path_to_rst = "doc/index.rst"

    if not os.path.exists(path_to_rst):
        print(f"❌ ERROR: File not found: {path_to_rst}")
        return

    with open(path_to_rst, "r") as file:
        rst_content = file.read()

    commands_from_local, notifications_from_local, hooks_from_local = extract_all_from_rst(rst_content)
    commands_from_readme = getListOfDocs(headers, CATEGORY_SLUG)
    notifications_from_readme = getListOfDocs(headers, NOTIFICATIONS_CATEGORY_SLUG)
    hooks_from_readme = getListOfDocs(headers, HOOKS_CATEGORY_SLUG)

    sync_docs(
        commands_from_local,
        commands_from_readme,
        CATEGORY_SLUG,
        headers,
        "commands"
    )

    sync_docs(
        notifications_from_local,
        notifications_from_readme,
        NOTIFICATIONS_CATEGORY_SLUG,
        headers,
        "notifications"
    )

    sync_docs(
        hooks_from_local,
        hooks_from_readme,
        HOOKS_CATEGORY_SLUG,
        headers,
        "hooks"
    )

    print("\n✨ Sync complete!")


if __name__ == "__main__":
    main()
