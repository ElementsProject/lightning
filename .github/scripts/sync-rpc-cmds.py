import os
from time import sleep
import requests
import re

# readme url
URL = "https://dash.readme.com/api/v1/docs"
# category id for API reference
CATEGORY_ID = "63e4e160c60b2e001dd1cc4e"


def checkIfDocIsPresent(title, headers):

    check_url = URL + "/" + title
    response = requests.get(check_url, headers=headers)

    if response.status_code == 200:
        return True
    else:
        return False


def publishDoc(title, body, order):
    key = os.environ.get("README_API_KEY")
    payload = {
        "title": title,
        "type": "basic",
        "body": body,
        "category": CATEGORY_ID,
        "hidden": False,
        "order": order,
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": "Basic " + key,
    }

    isDocPresent = checkIfDocIsPresent(title, headers)
    if isDocPresent:
        # update doc
        update_url = URL + "/" + title  # title == slug
        response = requests.put(update_url, json=payload, headers=headers)
        if response.status_code != 200:
            print(response.text)
        else:
            print("Updated ", title)
    else:
        # create doc
        response = requests.post(URL, json=payload, headers=headers)
        if response.status_code != 201:
            print(response.text)
        else:
            print("Created ", title)


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
    # path to the rst file from where we fetch all the RPC commands
    path_to_rst = "doc/index.rst"
    with open(path_to_rst, "r") as file:
        rst_content = file.read()

    commands = extract_rpc_commands(rst_content)
    if commands:
        order = 0
        for name, file in commands:
            print(f"{name}\t\t{file}")
            with open("doc/" + file) as f:
                body = f.read()
                publishDoc(name, body, order)
            order = order + 1
            sleep(3)
    else:
        print("No commands found in the Manpages block.")


if __name__ == "__main__":
    main()
