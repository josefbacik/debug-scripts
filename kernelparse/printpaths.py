from __future__ import print_function
from kernelparse import FileParser,FunctionTree
import os
import argparse

def find_all_paths(func, destination, path, visited):
    path = path + [func.name]
    if func.name == destination:
        return [path]
    visited.append(func.name)
    if len(func.calls) == 0:
        return []
    paths = []
    for c in func.calls.keys():
        if c in visited:
            continue
        newpaths = find_all_paths(func.calls[c]['func'], destination, path, visited)
        for newpath in newpaths:
            paths.append(newpath)
    return paths

parser = argparse.ArgumentParser(description="Find paths between two functions")
parser.add_argument("-d", "--destination", help="Destination function")
parser.add_argument("-s", "--source", help="Source function")
parser.add_argument("directory", help="The directory to search")
args = parser.parse_args()

if not args.source or not args.destination:
    print("You must specify a source and destination")
    exit(1)

p = FileParser()
ft = FunctionTree()

p.parse_path(args.directory, ft)

func = ft.functions[args.source]
paths = find_all_paths(func, args.destination, [], [])
psorted = sorted(paths, key=lambda x:len(x))
for i in psorted:
    print(i)
