import os
import re

class Function:
    def __init__(self, name, definition, defined=False):
        self.name = name
        self.defined = defined
        self.calls = {}
        self.callers = {}
        self.args = []
        self.recurses = False
        self.definition = definition
        self.content = ""

    def add_content(self, buf):
        self.content += buf

    def add_call(self, call, args):
        if call.name in self.calls:
            self.calls[call.name]['count'] += 1
            if args not in self.calls[call.name]['args']:
                self.calls[call.name]['args'].extend([args])
            return
        self.calls[call.name] = {}
        self.calls[call.name]['func'] = call
        self.calls[call.name]['count'] = 1
        self.calls[call.name]['args'] = [args]

    def add_caller(self, caller):
        if caller.name == self.name:
            return
        if caller.name in self.callers:
            return
        self.callers[caller.name] = caller

    def add_args(self, args):
        if args not in self.args:
            self.args.extend([args])

    def contains_calls(self, funcs):
        if len(self.calls) == 0:
            return False
        if not set(funcs).isdisjoint(self.calls.keys()):
            return True
        for f in self.calls.keys():
            if self.calls[f]['func'].contains_calls(funcs):
                return True
        return False

    def _count_calls(self, func, seen):
        if self.name in seen:
            return 0
        seen.append(self.name)
        if len(self.calls.keys()) == 0:
            return 0
        count = 0
        for f in self.calls.keys():
            if f == func:
                count += self.calls[f]['count']
                continue
            count += self.calls[f]['func']._count_calls(func, seen)
        return count

    def count_calls(self, func):
        return self._count_calls(func, [])

class FunctionTree:
    def __init__(self, debug=False):
        self.debug = debug
        self.functions = {}

    def add_function(self, name, definition):
        if name in self.functions:
            self.functions[name].defined = True
            self.functions[name].definition = definition
            return
#        print("adding function '{}'".format(name))
        f = Function(name, definition, True)
        self.functions[name] = f

    def add_func_call(self, func, call, args):
        c = None
#        print("adding call '{}'".format(call))
        # From
        if func.name == call:
            self.recurses = True
            return
        if call not in self.functions:
            c = Function(call, "")
            self.functions[call] = c
        else:
            c = self.functions[call]
        func.add_call(c, args)
        c.add_caller(func)

class FileParser:
    _GLOBAL = 0
    _IN_BLOCK = 1
    _IN_FUNCTION = 2
#    _IN_COMMENT = 2
    _IN_DIRECTIVE = 3
    _IN_PAREN = 4
    _keywords = ['auto', 'break', 'case', 'char', 'const', 'continue',
                 'default', 'do', 'double', 'else', 'enum', 'extern',
                 'float', 'for', 'goto', 'if', 'int', 'long', 'register',
                 'return', 'short', 'signed', 'sizeof', 'static',
                 'struct', 'switch', 'typedef', 'union', 'unsigned', 'void',
                 'volatile', 'while']

    def __init__(self, debug=False):
        self.state = []

        self._function_re = re.compile("[\s\w]+\s+(\w+)\s*\(.*\).*{", re.DOTALL)
        self._directive_re = re.compile("^\s*\#.*")
        self._comment_block_start_re = re.compile("^\s*\/\*")
        self._comment_block_end_re = re.compile(".*\*/")
        self._call_re = re.compile("[-()=+/*!|&<>%~^\s,]*(\w+)\s*(\(.*\))",
                                   re.DOTALL|re.MULTILINE)
        self._statement_re = re.compile(".*[;{}]+\s*(?:/\*)*.*(?:\*/)*$",
                                        re.DOTALL|re.MULTILINE)
        self.debug = debug

    def _grab_args(self, line):
        end_pos = 0
        cur_paren_count = 1
        for i in range(1, len(line)):
            if line[i] == '(':
                cur_paren_count += 1
            elif line[i] == ')':
                cur_paren_count -= 1
            if cur_paren_count == 0:
                end_pos = i
                break
        if end_pos == 0:
            return ""
        return line[1:end_pos]

    def _skip_line(self, line):
        cur = self.state[-1]
        if self._directive_re.match(line):
            if '\\' in line:
                self.state.append(self._IN_DIRECTIVE)
            return True
        if cur == self._IN_DIRECTIVE and '\\' not in line:
            self.state.pop()
            return True

#        if self._comment_block_start_re.match(line):
#            if cur != self._IN_COMMENT:
#                self.state.append(self._IN_COMMENT)
#                cur = self._IN_COMMENT
#        if cur == self._IN_COMMENT and self._comment_block_end_re.match(line):
#            self.state.pop()
#            return True
#        if cur == self._IN_COMMENT:
#            return True

        if cur == self._GLOBAL and ';' in line:
            return True
        return False

    def _handle_block(self, line):
        if '}' not in line and '{' not in line:
            return

        if '{' in line:
            self.state.append(self._IN_BLOCK)
        if '}' in line:
            self.state.pop()
        if self.cur_function is None:
            return
        if self._IN_FUNCTION not in self.state:
            content = self.cur_function.content
            content = "".join(content.rsplit('}', 1))
            content = re.sub("^\s*$", '', content, flags=re.MULTILINE)
            content = re.sub('\t', '    ', content)
            self.cur_function.content = content

    def _handle_function_call(self, ft, buf):
        if self._IN_FUNCTION not in self.state:
            return

        # Kill any string literals since they can mess with us if they are in
        # the function format
        buf = re.sub("[\"\'].*[\"\']", "STRING", buf)

        m = self._call_re.match(buf)
        if m is None:
            return
        remaining = m.group(2)
        if m.group(1) not in self._keywords:
            # grab the args to save into this call
            args = self._grab_args(m.group(2))
            ft.add_func_call(self.cur_function, m.group(1), args);
            self._handle_function_call(ft, args)
            remaining = m.group(2).replace(args, "", 1)
        else:
            # strip the first and last ()
            remaining = m.group(2).replace("(", "", 1)
            remaining = "".join(remaining.rsplit(")", 1))
        self._handle_function_call(ft, remaining)

    def _handle_function_def(self, ft, buf):
        if self.state[-1] != self._GLOBAL:
            return False

        m = self._function_re.match(buf)
        if m is None:
            if self.debug:
                print("Couldn't match '{}'".format(buf))
            return False
        definition = "".join(buf.replace('\n', ' ').rsplit('{', 1)).strip()
        definition = re.sub('\s+', ' ', definition)
        definition = re.sub('\( ', '(', definition)
        ft.add_function(m.group(1), definition)
        self.state.append(self._IN_FUNCTION)
        self.cur_function = ft.functions[m.group(1)]
        return True

    def _strip_comments(self, buf):
        buf = re.sub("/\*.*\*/", "", buf)

        # no more comments, return
        if re.search("/\*.*\*/", buf, flags=re.DOTALL) is None:
            return buf

        bufarray = buf.split('\n')
        final = []
        incomment = False
        for b in bufarray:
            if incomment and re.search("\*/", b) is not None:
                final.append(re.sub(".*\*/", "", b))
                incomment = False
                continue
            if re.search("/\*", b) is not None:
                final.append(re.sub("/\*.*", "", b))
                incomment = True
                continue
            if not incomment:
                final.append(b)
        return "\n".join(final)

    def parse_file(self, f, ft):
        infunction = 0
        self.state = [self._GLOBAL]
        self.cur_function = None
        buf = ""
        for line in f:
#            print(self.state)
            if self._skip_line(line):
                buf = ""
                continue

            buf += line

            if self._statement_re.match(buf) is None:
                continue

            buf = self._strip_comments(buf)
            if self._handle_function_def(ft, buf):
                buf = ""
                continue
            if self.cur_function != None:
                self.cur_function.add_content(buf)
            self._handle_function_call(ft, buf)
            self._handle_block(buf)
            buf = ""

    def parse_path(self, path, ft):
        if os.path.isdir(path):
            for f in os.listdir(path):
                self.parse_path(os.path.join(path, f), ft)
        elif os.path.isfile(path):
            if path.endswith('.c') or path.endswith('.h'):
                infile = open(path)
                self._parse_file(infile, ft)
                infile.close()

if __name__ == "__main__":
    p = FileParser()
    ft = FunctionTree()
    p.parse_path("fs/xfs/xfs_buf.c", ft)
    print(ft.functions.keys())
