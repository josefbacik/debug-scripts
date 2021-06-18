for i in range(0, len(prog['page_wait_table'])):
    wait_t = prog['page_wait_table'][i]
    if not list_empty(wait_t.head.address_of_()):
        for entry in list_for_each_entry('wait_queue_entry_t', wait_t.head.address_of_(), 'entry'):
            page_entry = container_of(entry, 'struct wait_page_queue', 'wait')
            task = cast("struct task_struct *", entry.private)
            print("page {} mapping {} index {} bit {} pid {} flags {}".format(
                hex(page_entry.page.value_()),
                hex(page_entry.page.mapping.value_()),
                page_entry.page.index, page_entry.bit_nr, task.pid,
                page_bits(page_entry.page)))
#            find_compressed_bio(page_entry.page.mapping.host)
            for cb in cb_objs:
                if cb.inode == page_entry.page.mapping.host:
                    if cb.start == page_entry.page.index << 12:
                        print(cb)
                        find_bio_page(cb.compressed_pages[0])
            find_inode_mapping(page_entry.page.mapping.host, page_entry.page.index << 12)
            find_inode_ordered_extent(page_entry.page.mapping.host, page_entry.page.index << 12)

def find_bio_page(page):
    for b in objs:
        if b.bio.bi_vcnt < 0 or b.bio.bi_vcnt > 100:
            continue
        for bvec in bio_for_each_bvec(prog, b.bio):
            try:
                if bvec.bv_page == page:
                    return b
            except FaultError:
                break

def find_bio_private(value):
    for b in objs:
        if b.bio.bi_private.value_() == value:
            print(b)

def find_bio_sector(value):
    for b in objs:
        if b.bio.bi_iter.bi_sector.value_() == value:
            print(b)

def find_compressed_bio(inode):
    for b in objs:
        if b.bio.bi_vcnt < 0 or b.bio.bi_vcnt > 100:
            continue
        if b.bio.bi_end_io.value_() != prog['end_compressed_bio_write'].address_of_().value_():
            continue
        try:
            cb = cast("struct compressed_bio *", b.bio.bi_private)
            if cb.inode == inode:
                print(cb)
                print(b)
        except FaultError:
            break

def find_inode_ordered_extent(inode, offset):
    btrfs_inode = container_of(inode, 'struct btrfs_inode', 'vfs_inode')
    for ordered in rbtree_inorder_for_each_entry('struct btrfs_ordered_extent',
                                                 btrfs_inode.ordered_tree.tree,
                                                 'rb_node'):
        if ordered.file_offset <= offset and ordered.file_offset + ordered.num_bytes > offset:
            print(ordered)
            

def find_inode_mapping(inode, offset):
    btrfs_inode = container_of(inode, 'struct btrfs_inode', 'vfs_inode')
    for em in rbtree_inorder_for_each_entry('struct extent_map',
                                            btrfs_inode.extent_tree.map.rb_root,
                                            'rb_node'):
        if em.start <= offset and em.start + em.len > offset:
            print(f'{em.start} {em.block_start} {em.block_len}')

def dump_inode_ordered_extents(inode):
    btrfs_inode = container_of(inode, 'struct btrfs_inode', 'vfs_inode')
    for ordered in rbtree_inorder_for_each_entry('struct btrfs_ordered_extent',
                                                 btrfs_inode.ordered_tree.tree,
                                                 'rb_node'):
        print(ordered)

def dump_inode_extent_map(inode):
    btrfs_inode = container_of(inode, 'struct btrfs_inode', 'vfs_inode')
    for em in rbtree_inorder_for_each_entry('struct extent_map',
                                            btrfs_inode.extent_tree.map.rb_root,
                                            'rb_node'):
        print(f'{em.start} {em.block_start} {em.block_len}')
            
for b in objs:
    if b.bio.bi_vcnt < 0 or b.bio.bi_vcnt > 300:
        continue
    if b.bio.bi_end_io.value_() != prog['end_compressed_bio_write'].address_of_().value_():
        continue
    try:
        cb = cast("struct compressed_bio *", b.bio.bi_private)
        print(cb.start)
    except FaultError:
        break

our_dip = None
for d in dips:
    for bio in dio_bios:
        if bio.address_of_().value_() == d.dio_bio.value_():
            our_dip = d
            break

def find_wqs(wqs, endio):
    ret = []
    for w in wqs:
        if w.end_io.value_() == prog[endio].address_of_().value_():
            ret.append(w)
    return ret

def find_btrfs_bios(bios, endio):
    ret = []
    for b in bios:
        if b.bio.bi_vcnt < 0 or b.bio.bi_vcnt > 300:
            continue
        if b.bio.bi_end_io.value_() != prog[endio].address_of_().value_():
            if b.bio.bi_end_io.value_() != prog['btrfs_end_bio'].address_of_().value_():
                print(b.bio.bi_end_io)
                continue
            bbio = cast('struct btrfs_bio *', b.bio.bi_private)
            if bbio.end_io.value_() != prog[endio].address_of_().value_():
                if bbio.end_io.value_() != prog['end_workqueue_bio'].address_of_().value_():
#                    print(bbio.end_io)
                    continue
                end_io_wq = cast('struct btrfs_end_io_wq', bbio.private)
                if end_io_wq.end_io.value_() != prog[endio].address_of_().value_():
                    print(end_io_wq.end_io)
                    continue
                print(bbio.end_io)
                continue
        print("HOOOORAAAYYY")
        ret.append(b)
    return ret

objs = dump_slab_objects(prog, prog['btrfs_bioset'].bio_slab, 'struct btrfs_io_bio')

def find_dio_bios(bios):
    ret = []
    for b in bios:
        if b.bi_vcnt < 0 or b.bi_vcnt > 300:
            continue
        if b.bi_end_io.value_() != prog['dio_bio_end_io'].address_of_().value_():
            continue
        ret.append(b)
    return ret

bios = dump_slab_objects(prog, prog['fs_bio_set'].bio_slab, 'struct bio')

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

def dump_locked_page_waiters(prog):
    for i in range(0, len(prog['page_wait_table'])):
        wait_t = prog['page_wait_table'][i]
        if not list_empty(wait_t.head.address_of_()):
            for entry in list_for_each_entry('wait_queue_entry_t', wait_t.head.address_of_(), 'entry'):
                page_entry = container_of(entry, 'struct wait_page_queue', 'wait')
                task = cast("struct task_struct *", entry.private)
                print("page {} mapping {} index {} bit {} pid {} flags {}".format(
                    hex(page_entry.page.value_()),
                    hex(page_entry.page.mapping.value_()),
                    page_entry.page.index, page_entry.bit_nr, task.pid,
                    page_bits(page_entry.page)))

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

def btrfs_for_each_root(fs_info):
    for objectid,root_ptr in radix_tree_for_each(fs_info.fs_roots_radix.address_of_()):
        root = cast('struct btrfs_root *', root_ptr)
        yield root

for root in btrfs_for_each_root(fs_info):
    flag = 1 << prog['BTRFS_ROOT_DEAD_RELOC_TREE'].value_()
    if root.state & flag:
        print("root {} has it set".format(root.root_key.objectid))

def btrfs_dump_live_inodes(root):
    for inode in rbtree_inorder_for_each_entry('struct btrfs_inode',
                                               root.inode_tree, 'rb_node'):
        print(f"{inode.location.objectid} {inode.vfs_inode.i_count.counter} {inode.vfs_inode.i_state}")

def btrfs_get_root(fs_info, root_id):
    return cast('struct btrfs_root *',
                radix_tree_lookup(fs_info.fs_roots_radix.address_of_(), root_id))

def btrfs_get_fs_info(prog, path):
    mnt = None
    for m in for_each_mount(prog):
        if (mount_dst(m).decode('ascii') == path and
            mount_fstype(m).decode('ascii') == "btrfs"):
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
