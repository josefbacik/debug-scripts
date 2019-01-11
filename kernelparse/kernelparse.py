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
        #self._statement_re = re.compile(".*[;{}]+\s*(?:/\*)*.*(?:\*/)*$",
        #                                re.DOTALL|re.MULTILINE)
        self._statement_re = re.compile(".*[;{}]$",
                                        re.DOTALL|re.MULTILINE)
        self._special_eol_re = re.compile("\)$", re.MULTILINE)
        self._single_line_cond_re = re.compile("^.+\(.*\).+;$")
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

    def _collapse_nonblock_statement(self, content):
        ret = ""
        cur = ""
        for s in content.split('\n'):
            tmp = cur + s;
            open_count = tmp.count('(')
            close_count = tmp.count(')')
            if open_count == close_count:
                if cur == "":
                    cur = s
                else:
                    cur += " " + s.strip()
                ret += cur + '\n'
                cur = ""
                continue
            if cur == "":
                cur = s
            else:
                cur += " " + s.strip()
        ret += cur + '\n'
        return ret

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

            # strip the tailing } if there is one
            content = "".join(content.rsplit('}', 1))
            # Strip the excess whitespace, this makes testcases easier to write.
            self.cur_function.content = content.rstrip()

    def _handle_function_call(self, ft, buf):
        if self._IN_FUNCTION not in self.state:
            return

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
        final = [l for l in final if re.search("^\s*$", l) is None]
        return "\n".join(final) + "\n"

    def _make_pretty(self, buf):
        ret = ""
        indent = 0
        for l in buf.split('\n'):
            l = l.strip()
            if '}' in l:
                indent -= 1
            ret += '\n' + '  ' * indent + l
            if '{' in l:
                indent += 1
        return ret

    def parse_file(self, f, ft):
        infunction = 0
        self.state = [self._GLOBAL]
        self.cur_function = None
        buf = ""

        # Strip the file down to a reasonable set of statements
        content = f.read()

        # First strip all the comments
        content = self._strip_comments(content)

        # Cull any string literals, they could have problematic things and we
        # just don't care
        content = re.sub("[\"\'].*[\"\']", "STRING", content)

        # Strip any empty lines
        content = re.sub("^\s*$", '', content, flags=re.MULTILINE)

        # Just for consistency with testing replace tabs with spaces
        content = re.sub('\t', '    ', content)

        # Make sure open braces are on their own line, otherwise it confuses the
        # statement stuff.
        content = re.sub('\{(?!\n)', '{\n', content)

        # We want to make sure that logical statements are all on one line, so
        # things like
        #   if (a >
        #       b)
        #
        # gets turned into
        #   if (a > b)
        content = re.sub('(?<![;{})])\n\s*', ' ', content)

        # The above doesn't handle the case of
        #   if (foo()
        #       > bar())
        # So we handle that special case here.
        if self._special_eol_re.search(content) is not None:
            content = self._collapse_nonblock_statement(content)

        # Turn any 2 line conditional into a block as well, which is
        #   if (foo)
        #     bar();
        # becomes
        #   if (foo)
        #   {
        #      bar();
        #   }
        content = re.sub("^(.+\)(?!;))\s(.+;)$", r'\1\n{\n\2\n}', content,
                         flags=re.MULTILINE)

        # And now the same thing above, except for else, cause it's special
        content = re.sub("^(.*else)\s(.+;)$", r'\1\n{\n\2\n}', content,
                         flags=re.MULTILINE)

        content.strip()

        content = self._make_pretty(content)

        for line in content.split('\n'):
            if self._skip_line(line):
                buf = ""
                continue

            buf += line + "\n"

            if self._statement_re.match(buf) is None:
                continue

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
                self.parse_file(infile, ft)
                infile.close()

if __name__ == "__main__":
    p = FileParser()
    ft = FunctionTree()
    p.parse_path("fs/xfs/xfs_buf.c", ft)
    print(ft.functions.keys())
