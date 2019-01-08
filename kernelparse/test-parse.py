from kernelparse import FileParser,FunctionTree

testfile = open("test.c")
p = FileParser()
ft = FunctionTree()
p.parse_file(testfile, ft)

funcs = ['box', 'bean', 'boo', 'baz', 'foo', 'main', 'duper',
         'comment_in_front', 'multiline_comment_in_front', 'recurse',
         'multiline_if', 'multiline_if_2']
for f in funcs:
    if f not in ft.functions:
        print("FAILED: {} not found".format(f))
        exit(1)
    if not ft.functions[f].defined:
        print("FAILED: {} definition wasn't found, have {}".format(f,
            ft.functions.keys()))
        exit(1)
print("PASSED: basic checks")

func = ft.functions['main']
calls = ['foo', 'bar', 'baz', 'boo', 'bean', 'box', 'multiline_if',
         'multiline_if_2', 'funky']
if set(calls) != set(func.calls.keys()):
    print("FAILED: didn't find all the calls {}".format(func.calls.keys()))
    exit(1)
if len(calls) != len(func.calls.keys()):
    print("FAILED: too many calls {}".format(func.calls.keys()))
    exit(1)
print("PASSED: call checks")
