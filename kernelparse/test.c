int box(void)
{
    return 3;
}

int bean(void)
{
    return 2;
}

int boo(int a, int b)
{
    return a > b;
}

/*
 * bing bang boom
 */
int baz(int a)
{
    return 1;
}

int foo(int a)
{   /* foo bar */
    return a;
}

struct abc {
    int a;
    u64 b;
};

/*
 * Just to be super
 */
int
duper(
        void *obnoxious, /* because */
        int we) /* can
                   be
                   really
                   bad
                   */
{
    return 2;
}

/* comment in front */int comment_in_front(void)
{
    return 1;
}

typedef struct foo_s;

struct foo_r {
    foo_s (*call)(int b);
};

/* multiline
 * comment
 * in
 * front*/int multiline_comment_in_front(void)
{
    return 1;
}

int funky(char *foo)
{
    return 1;
}

int recurse(int a)
{
    if (++a < 10)
        return recurse(a);
    return a;
}

int main(int argc, char **argv)
{
    /*
     * a multiline comment to make(sure)
     * we don't accidentally grab(these as fucntions)
     */
    if (foo(bar()) > baz(boo(bean(), box())))
        return 1;
    funky("blahblah(boo)");
    return 0;
}
