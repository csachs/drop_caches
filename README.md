# drop_caches

## Rationale

These little programs will write `3` to `/proc/sys/vm/drop_caches` (cf. [Linux Kernel Documentation](https://www.kernel.org/doc/Documentation/sysctl/vm.txt)), which will flush the reclaimable slab objects and page cache.

Why programs for such a mundane task? – The necessary `/proc` entry is write-only by root, hence one either needs to `sudo` first, or the program performing it must be setuid root, which is not possible for an interpreted shell script.

Hence those little programs, which only have one purpose, dropping the kernel caches, which can be setuid root. No guarantees for bug-freeness or security tho. But I guess, the smaller, the less risk of bugs ;)

Why dropping the caches? To my observation, having too little free space, or too fragmented free space, can often affect other software's behavior, even if their allocations would theoretically still possible. Besides, it seems ZFS (ZFSonLinux) is lazily clearing its caches, often causing large user space allocations to fail. Besides, for certain cold start benchmarks, caches need to be emptied beforehand.

## Installation 

Pick one, compile it according to the comment at its beginning, copy where ever you like (e.g. `/usr/bin`), and `sudo chmod u+s drop_caches`.

## Usage

Run it, ideally after immediately running `sync`.

## License

MIT