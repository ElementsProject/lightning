import os
from time import sleep
import requests
import re
from enum import Enum

# readme url
URL = "https://dash.readme.com/api/v1"
# category id for API reference
CATEGORY_ID = "63e4e160c60b2e001dd1cc4e"
CATEGORY_SLUG = "json-rpc-apis"


class Action(Enum):
    ADD = 'add'
    UPDATE = 'update'
    DELETE = 'delete'


def getListOfRPCDocs(headers):
    response = requests.get(f"{URL}/categories/{CATEGORY_SLUG}/docs", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return []


def publishDoc(action, title, body, order, headers):
    payload = {
        "title": title,
        "type": "basic",
        "body": body,
        "category": CATEGORY_ID,
        "hidden": False,
        "order": order,
    }
    # title == slug
    if action == Action.ADD:
        # create doc
        response = requests.post(URL + "/docs", json=payload, headers=headers)
        if response.status_code != 201:
            print(response.text)
        else:
            print("Created ", title)
    elif action == Action.UPDATE:
        # update doc
        response = requests.put(f"{URL}/docs/{title}", json=payload, headers=headers)
        if response.status_code != 200:
            print(response.text)
        else:
            print("Updated ", title)
    elif action == Action.DELETE:
        # delete doc
        response = requests.delete(f"{URL}/docs/{title}", headers=headers)
        if response.status_code != 204:
            print(response.text)
        else:
            print("Deleted ", title)
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
        "authorization": "Basic " + os.environ.get("README_API_KEY"),
    }

    # path to the rst file from where we fetch all the RPC commands
    path_to_rst = "doc/index.rst"
    with open(path_to_rst, "r") as file:
        rst_content = file.read()

    commands_from_local = extract_rpc_commands(rst_content)
    commands_from_readme = getListOfRPCDocs(headers)

    # Compare local and server commands list to get the list of command to add or delete
    commands_local_title = set(command[0] for command in commands_from_local)
    commands_readme_title = set(command['title'] for command in commands_from_readme)
    commands_to_delete = commands_readme_title - commands_local_title
    commands_to_add = commands_local_title - commands_readme_title
    for name in commands_to_delete:
        publishDoc(Action.DELETE, name, "", 0, headers)
        sleep(3)

    if commands_from_local:
        order = 0
        for name, file in commands_from_local:
            # print(f"{name}\t\t{file}")
            with open("doc/" + file) as f:
                body = f.read()
                publishDoc(Action.ADD if name in commands_to_add else Action.UPDATE, name, body, order, headers)
            order = order + 1
            sleep(3)
    else:
        print("No commands found in the Manpages block.")


if __name__ == "__main__":
    main()
