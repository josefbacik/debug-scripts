import subprocess
import time
import sys
import argparse

class CodeTree:
    def __init__(self):
        self.root = None
        self.remaining = 0
        self.processed = 0
        self.avg = 0.0
        self.total = 0.0
        self.discovered = []

    def contains(self, name):
        if name in self.discovered:
            return True
        self.discovered.append(name)
        return False

    def _print_path(self, node, path):
        path += " " + node.name
        ret = ""
        if len(node.children) == 0:
            return path + "\n"
        for i in node.children:
            ret += self._print_path(i, path)
        return ret

    def __str__(self):
        if self.root is None:
            return ""
        return self._print_path(self.root, "")

    def _print_leaves(self, node):
        ret = ""
        if len(node.children) == 0:
            return node.name + "\n"
        for i in node.children:
            ret += self._print_leaves(i)
        return ret

    def _find_all_paths(self, node, path):
        path = path + [node.name]
        if len(node.children) == 0:
            return [path]
        paths = []
        for n in node.children:
            newpaths = self._find_all_paths(n, path)
            for newpath in newpaths:
                paths.append(newpath)
        return paths

    def paths(self):
        if self.root is None:
            return []
        return self._find_all_paths(self.root, [])

    def leaves(self):
        if self.root is None:
            return ""
        return self._print_leaves(self.root)

class CodeNode:
    def __init__(self, name):
        self.children = []
        self.name = name

    def add_child(self, child):
        self.children.append(child)

def find_callers(func, cscopedb):
    p = subprocess.Popen(["cscope", "-d", "-f", cscopedb, "-L3", func],
                         stdout=subprocess.PIPE)
    (output, error) = p.communicate()
    output = output.rstrip()
    ret = []
    for l in output.split('\n'):
        ret.append(l.split(' ')[:2])
    return ret

def get_paths(tree, node, cscopedb, directories, exclude, dupes):
    tree.processed += 1
    t0 = time.time()
    callers = find_callers(node.name, cscopedb)
    tree.total += time.time() - t0
    tree.processed += 1
    tree.remaining -= 1
    tree.remaining += len(callers)
    avg = tree.total / tree.processed
    remain = tree.remaining * (tree.total / tree.processed)
    sys.stderr.write("\r{} elapsed, {} possible remaining".format(tree.total, remain))
    sys.stderr.flush()
    for c in callers:
        skip = True
        for i in directories:
            if i in c[0]:
                skip = False
                break
        if skip:
            tree.remaining -= 1
            continue

        for i in exclude:
            if i in c[0]:
                skip = True
                break
        if skip:
            tree.remaining -= 1
            continue

        if not dupes and tree.contains(c[1]):
            tree.remaining -= 1
            continue

        child = CodeNode(c[1])
        node.add_child(child)
        tree.processed += 1
        get_paths(tree, child, cscopedb, directories, exclude, dupes)

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--cscopedb", default="cscope.out", help="Location of cscope.out")
parser.add_argument("-e", "--exclude", action='append',
                    help="Exclude this component of the path")
parser.add_argument("-d", "--directory", action='append',
                    help="Only deal with functions in this directory (can just be one part of the path)")
parser.add_argument("-p", "--duplicates", action='store_true',
                        help="Don't filter out duplicate leaves (ie have a->b->c as well as a->d->c)")
parser.add_argument("-t", "--tree", action='store_true',
                    help="Print all of the paths of the whole tree")
parser.add_argument("function", help="Function to build the code paths from")

args = parser.parse_args()

exclude = []
directories = []

if args.directory is not None:
    directories = args.directory
if args.exclude is not None:
    exclude = args.exclude

tree = CodeTree()
node = CodeNode(args.function)
tree.root = node
get_paths(tree, node, args.cscopedb, directories, exclude, args.duplicates)

sys.stderr.write("\nProccessed {} functions in {} seconds\n".format(tree.processed, tree.total))
sys.stderr.flush()

leaves = tree.paths()
lsorted = sorted(leaves, key=lambda x:len(x))

if args.tree:
    print(tree)
else:
    for i in lsorted:
        print(i[-1])
