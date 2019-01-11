from kernelparse import FileParser,FunctionTree

testfile = open("test.c")
p = FileParser()
ft = FunctionTree()
p.parse_file(testfile, ft)

funcs = {
          'box' : 'int box(void)',
          'bean': 'int bean(void)',
          'boo' : 'int boo(int a, int b)',
          'baz' : 'int baz(int a)',
          'foo' : 'int foo(int a)',
          'duper' : 'int duper(void *obnoxious, int we)',
          'comment_in_front' : 'int comment_in_front(void)',
          'multiline_comment_in_front' : 'int multiline_comment_in_front(void)',
          'funky' : 'int funky(char *foo)',
          'recurse' : 'int recurse(int a)',
          'multiline_if' : 'int multiline_if(void)',
          'multiline_if_2' : 'int multiline_if_2(void)',
          'main' : 'int main(int argc, char **argv)',
          'pointer' : 'int pointer(void *blah)',
          'ifcall' : 'int ifcall(void)'}

for name in funcs.keys():
    if name not in ft.functions:
        print("FAILED: {} not found".format(name))
        exit(1)
    if not ft.functions[name].defined:
        print("FAILED: {} definition wasn't found, have {}".format(name,
            ft.functions.keys()))
        exit(1)
    if ft.functions[name].definition != funcs[name]:
        print("FAILED: {} definition '{}' doesn't match '{}'".format(name,
            ft.functions[name].definition, funcs[name]))
        exit(1)
print("PASSED: basic checks")

func = ft.functions['main']
content = """  int i = 0;
  if (foo(bar()) > baz(boo(bean(), box())))
  {
    return 1;
  }
  if (multiline_if() > multiline_if_2())
  {
    return 0;
  }
  if (i == 1)
  {
    ifcall();
  }
  if (multiline_if() > multiline_if_2())
  {
    return 0;
  }
  funky(STRING);
  boo(1, 2);
  pointer(&some->weirdness);
  if (i == 1)
  {
    ifcall();
  }
  do {
    boo(1, 2);
  } while (i++ < 10);
  if (i == 1)
  {
    boo(2, 1);
  }
  else
  {
    boo(1, 2);
  }
  return 0;"""

if func.content != content:
    print("FAILED: the content didn't match!")
    print("'{}'".format(func.content))
    exit(1)

calls = ['foo', 'bar', 'baz', 'boo', 'bean', 'box', 'multiline_if',
         'multiline_if_2', 'funky', 'pointer', 'ifcall']
if set(calls) != set(func.calls.keys()):
    print("FAILED: didn't find all the calls".format(func.calls.keys()))
    print("Missing '{}'".format(list(set(calls) - set(func.calls.keys()))))
    print("Extra '{}'".format(list(set(func.calls.keys()) - set(calls))))
    exit(1)
if len(calls) != len(func.calls.keys()):
    print("FAILED: too many calls {}".format(func.calls.keys()))
    exit(1)
print("PASSED: call checks")

valid_args = { 'foo'            : ['bar()'],
               'bar'            : [''],
               'baz'            : ['boo(bean(), box())'],
               'boo'            : ['bean(), box()', '1, 2', '2, 1'],
               'bean'           : [''],
               'box'            : [''],
               'funky'          : ['STRING'],
               'multiline_if'   : [''],
               'multiline_if_2' : [''],
               'pointer'        : ['&some->weirdness'],
               'ifcall'         : ['']}

for c in func.calls.keys():
    call = func.calls[c]
    name = call['func'].name
    if name not in valid_args.keys():
        print("FAILED: {} not in the valid_args list".format(name))
        exit(1)
    if set(call['args']) != set(valid_args[name]):
        print("FAILED: {} call did not have the right args".format(name))
        print("call args {}".format(call['args']))
        print("valid args {}".format(valid_args[name]))
        exit(1)
print("PASSED: args checks")
