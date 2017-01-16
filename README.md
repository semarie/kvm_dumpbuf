OpenBSD: dump struct buf via kvm(3)
-----------------------------------

dump the *full content* of *all* `struct buf` from kernel image via kvm(3).

- full content : not only the valid bytes in the buffer but all the buffer
  (part of past use of the buffer could be leaked)
- all `struct buf` : not only active buffer, but also inactive ones (past use
  of the buffer could be leaked)

It generates lot of files in the current directory (one per buf).

File name format is: `dump-VNODE-BUF` with `VNODE` the vnode address and `BUF`
the buf address. vnode address is useful when used with pstat(1).
