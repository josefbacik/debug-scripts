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

int multiline_if(void)
{
    return 2;
}

int multiline_if_2(void)
{
    return 3;
}

int pointer(void *blah)
{
    return 2;
}

int ifcall(void)
{
    return 1;
}

int main(int argc, char **argv)
{
    int i = 0;
    /*
     * a multiline comment to make(sure)
     * we don't accidentally grab(these as fucntions)
     * or ignore stuff;
     */
    if (foo(bar()) > baz(boo(bean(), box())))
        return 1;
    if (multiline_if() >
        multiline_if_2())
        return 0;

    if (i == 1)
        ifcall();

    /* This is for the content stuff to make sure it all ends up on the same
     * line.
     */
    if (multiline_if()
        > multiline_if_2())
        return 0;
    funky("blahblah(boo)");
    boo(1, 2);
    pointer(&some->weirdness);

    if (i == 1) ifcall();

    do {
        boo(1, 2);
    } while (i++ < 10);

    if (i == 1)
        boo(2, 1);
    else
        boo(1, 2);
    return 0;
}
