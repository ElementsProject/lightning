import os
from time import sleep
import requests
import re
from enum import Enum

# readme url
URL = "https://api.readme.com/v2/branches/stable"
CATEGORY_SLUG = "JSON-RPC"


class Action(Enum):
    ADD = 'add'
    UPDATE = 'update'
    DELETE = 'delete'


def getListOfRPCDocs(headers):
    response = requests.get(f"{URL}/categories/reference/{CATEGORY_SLUG}/pages", headers=headers)
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


def publishDoc(action, title, body, position, headers):
    payload = {
        "title": title,
        "type": "basic",
        "content": {
            "body": body,
        },
        "category": {
            "uri": f"/branches/stable/categories/reference/{CATEGORY_SLUG}"
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


def extract_rpc_commands(rst_content):
    manpages_block = re.search(
        r"\.\. block_start manpages(.*?)" r"\.\. block_end manpages",
        rst_content,
        re.DOTALL,
    )
    if manpages_block:
        commands = re.findall(
            r"\b([a-zA-Z0-9_-]+)" r"\s+<([^>]+)>\n", manpages_block.group(1)
        )
        return commands
    return []


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

    commands_from_local = extract_rpc_commands(rst_content)
    commands_from_readme = getListOfRPCDocs(headers)

    # Compare local and server commands list to get the list of command to add or delete
    commands_local_title = set(command[0] for command in commands_from_local)
    commands_readme_title = set(command['slug'] for command in commands_from_readme)
    commands_to_delete = commands_readme_title - commands_local_title
    commands_to_add = commands_local_title - commands_readme_title
    for name in commands_to_delete:
        publishDoc(Action.DELETE, name, "", 0, headers)
        sleep(1)

    if commands_from_local:
        position = 0
        for name, file in commands_from_local:
            file_path = "doc/" + file
            if not os.path.exists(file_path):
                print(f"⚠️  WARNING: File not found: {file_path}, skipping {name}")
                continue

            with open(file_path) as f:
                body = f.read()
                action = Action.ADD if name in commands_to_add else Action.UPDATE
                publishDoc(action, name, body, position, headers)
            position += 1
            sleep(1)
    else:
        print("⚠️  No commands found in the Manpages block.")

    print("\n✨ Sync complete!")


if __name__ == "__main__":
    main()
