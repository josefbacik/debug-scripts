from drgn import FaultError

def bio_for_each_bvec(prog, bio):
    for idx in range(0, bio.bi_vcnt):
        yield bio.bi_io_vec[idx]

def find_slab(name):
    for s in list_for_each_entry("struct kmem_cache", prog['slab_caches'].address_of_(), 'list'):
        if s.name.string_().decode("utf-8") == name:
            return s

def dump_slabs():
    for s in list_for_each_entry("struct kmem_cache", prog['slab_caches'].address_of_(), "list"):
        print("{} {}".format(s.name.string_().decode("utf-8"), hex(s.value_())))

def _slub_page_objects(prog, slab, page, obj_type):
    addr = page_to_virt(page).value_()
    addr += slab.red_left_pad
    ret = []
    end = addr + slab.size * page.objects
    while addr < end:
        ret.append(Object(prog, obj_type, address=addr))
        addr += slab.size
    return ret

def slab_page_objects(prog, slab, page, obj_type):
    try:
        return _slub_page_objects(prog, slab, page, obj_type)
    except AttributeError:
        pass
    ret = []
    offset = 0
    if prog.type('struct kmem_cache').has_member('obj_offset'):
        offset = slab.obj_offset
    for i in range(0, slab.num):
        addr = page.s_mem.value_() + i * slab.size + offset
        ret.append(Object(prog, obj_type, address=addr))
    return ret

def for_each_slab_page(prog):
    PGSlab = 1 << prog.constant('PG_slab')
    for p in for_each_page(prog):
        try:
            if p.flags.value_() & PGSlab:
                yield p
        except FaultError:
            pass

def dump_slab_objects(prog, slab, obj_type):
    ret = []
    for p in for_each_slab_page(prog):
        if p.slab_cache == slab:
            ret.extend(slab_page_objects(prog, slab, p, obj_type))
    return ret
