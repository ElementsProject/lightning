#!/usr/bin/env python3
from sh import git, rm, mv
import re
import os

rm = rm.bake("-rf")
grm = git.bake("rm", "--cached")
commit = git.bake("commit", "-am")
gclone = git.bake("clone", "--recursive")
gadd = git.bake("add")
# Read the gitmodules file
submodules = {}

for l in git("submodule").split("\n"):
    if " " not in l:
        continue
    h, d = l.split(" ")
    h = h[1:]
    submodules[d] = {"path": d, "hash": h, "name": None, "url": None}

curr = None
name = None
r = re.compile(r"(submodule|path|url) [=]?[ ]?\"?([^\"]+)\"?")
for l in open(".gitmodules", "r"):
    matches = r.search(l.strip())
    if not matches:
        continue
    if matches[1] == "submodule":
        name = matches[2]
    elif matches[1] == "path":
        curr = matches[2]
        submodules[curr]["name"] = name
    elif matches[1] == "url":
        submodules[curr]["url"] = matches[2]

grm(".gitmodules")
for module in submodules.values():
    grm(module["path"])
    rm(module["path"])

commit("scripted: Remove submodules for materialization")
mv(".gitignore", ".gitignore.bak")

for module in submodules.values():
    gclone(module["url"], module["path"])
    d = os.getcwd()
    os.chdir(module["path"])
    git("checkout", module["hash"])
    os.chdir(d)
    rm(f"{module['path']}/.git")
    gadd(module["path"])

mv(".gitignore.bak", ".gitignore")
commit("scripted: Materialize submodules")
