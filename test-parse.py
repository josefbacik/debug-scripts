from kernelparse import FileParser

f = open("test.c")
p = FileParser()
cg = p.parse_file(f)

funcs = ['box', 'bean', 'boo', 'baz', 'foo', 'main']
if set(funcs) != set(cg.functions.keys()):
    print("FAILED: didn't find all the functions {}",format(cg.functions))
    exit(1)
print("SUCCESS!")
