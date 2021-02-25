objs = dump_slab_objects(prog, prog['btrfs_bioset'].bio_slab, 'struct btrfs_io_bio')
for i in range(0, len(prog['page_wait_table'])):
    wait_t = prog['page_wait_table'][i]
    if not list_empty(wait_t.head.address_of_()):
        for entry in list_for_each_entry('wait_queue_entry_t', wait_t.head.address_of_(), 'entry'):
            page_entry = container_of(entry, 'struct wait_page_queue', 'wait')
            task = cast("struct task_struct *", entry.private)
            bio = None
            for b in objs:
                if b.bio.bi_vcnt < 0 or b.bio.bi_vcnt > 100:
                    continue
                for bvec in bio_for_each_bvec(prog, b.bio):
                    try:
                        if bvec.bv_page == page_entry.page:
                            bio = b
                            break
                    except FaultError:
                        break
                if bio:
                    break
            print("page {} mapping {} index {} bit {} pid {} flags {}".format(
                hex(page_entry.page.value_()),
                hex(page_entry.page.mapping.value_()),
                page_entry.page.index, page_entry.bit_nr, task.pid,
                page_bits(page_entry.page)))
            print(bio)

for t in for_each_task(prog):
    if t.state.value_() == 2:
        trace = prog.stack_trace(t)
        if len(trace) >= 3:
            if (trace[0].symbol().name == "__schedule" and
                "rwsem_down" in trace[2].symbol().name):
                continue
        if len(trace) > 4:
            if ("__mutex_lock" in trace[3].symbol().name and
                trace[4].symbol().name == "btrfs_start_delalloc_roots"):
                continue
        print("task {} is stuck".format(t.pid))
        prog.stack_trace(t)

def page_bits(page):
    ret = ""
    for name,value in prog.type('enum pageflags').enumerators:
        bit = 1 << value
        if (bit & page.flags):
            if ret == "":
                ret += name
            else:
                ret += "|{}".format(name)
    return ret

for t in for_each_task(prog):
    if t.state.value_() == 2:
        trace = prog.stack_trace(t)
        if len(trace) >= 3:
            if (trace[0].symbol().name == "__schedule" and
                "rwsem_down" in trace[2].symbol().name):
                continue
        if len(trace) > 4:
            if ("mutex_lock" in trace[3].symbol().name and
                trace[4].symbol().name == "btrfs_start_delalloc_roots"):
                continue
        print("task {} is stuck".format(t.pid))
        prog.stack_trace(t)
        print("")

def btrfs_get_fs_info(prog, path):
    mnt = None
    for m in for_each_mount(prog):
        if mount_dst(m) == path:
            mnt = m
            break
    if not mnt:
        return None
    return cast("struct btrfs_fs_info *", mnt.mnt.mnt_sb.s_fs_info)

def btrfs_dump_fs_infos(prog):
    for m in for_each_mount(prog):
        if mount_fstype(m) == b'btrfs':
            print("{} {}".format(mount_dst(m),
                                 hex(m.mnt.mnt_sb.s_fs_info.value_())))

for b in objs:
    if b.fs_info == fs_info:
        print(b)
