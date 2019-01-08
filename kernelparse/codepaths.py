from __future__ import print_function
from kernelparse import FileParser,FunctionTree
import os
import argparse

def find_all_paths(func, path, visited):
    path = path + [func.name]
    visited.append(func.name)
    if len(func.callers) == 0:
        return [path]
    paths = []
    for c in func.callers.keys():
        if c in visited:
            continue
        newpaths = find_all_paths(func.callers[c], path, visited)
        for newpath in newpaths:
            paths.append(newpath)
    return paths

parser = argparse.ArgumentParser(description="Find the callers of a specific function")
parser.add_argument("-d", "--directory", action='append',
                    help="Directories to scan")
parser.add_argument("function", help="The function to find")
args = parser.parse_args()

directories = ["."]
if args.directory is not None:
    directories = args.directory

p = FileParser()
ft = FunctionTree()

for d in directories:
    p.parse_path(d, ft)

if args.function not in ft.functions:
    print("Couldn't find the function call {}".format(args.function))
    print(ft.functions.keys())
else:
    paths = find_all_paths(ft.functions[args.function], [], [])
    psorted = sorted(paths, key=lambda x:len(x))
    for i in psorted:
        print(i[-1])
