#pragma once
#include <cstdint>

/* types of the type field in fcall struct */
enum class P9MsgType : uint8_t {
	P9_TLERROR = 6,
	P9_RLERROR,
	P9_TSTATFS = 8,
	P9_RSTATFS,
	P9_TLOPEN = 12,
	P9_RLOPEN,
	P9_TLCREATE = 14,
	P9_RLCREATE,
	P9_TSYMLINK = 16,
	P9_RSYMLINK,
	P9_TMKNOD = 18,
	P9_RMKNOD,
	P9_TRENAME = 20,
	P9_RRENAME,
	P9_TREADLINK = 22,
	P9_RREADLINK,
	P9_TGETATTR = 24,
	P9_RGETATTR,
	P9_TSETATTR = 26,
	P9_RSETATTR,
	P9_TXATTRWALK = 30,
	P9_RXATTRWALK,
	P9_TXATTRCREATE = 32,
	P9_RXATTRCREATE,
	P9_TREADDIR = 40,
	P9_RREADDIR,
	P9_TFSYNC = 50,
	P9_RFSYNC,
	P9_TLOCK = 52,
	P9_RLOCK,
	P9_TGETLOCK = 54,
	P9_RGETLOCK,
	P9_TLINK = 70,
	P9_RLINK,
	P9_TMKDIR = 72,
	P9_RMKDIR,
	P9_TRENAMEAT = 74,
	P9_RRENAMEAT,
	P9_TUNLINKAT = 76,
	P9_RUNLINKAT,
	P9_TVERSION = 100,
	P9_RVERSION,
	P9_TAUTH = 102,
	P9_RAUTH,
	P9_TATTACH = 104,
	P9_RATTACH,
	P9_TFLUSH = 108,
	P9_RFLUSH,
	P9_TWALK = 110,
	P9_RWALK,
	P9_TOPEN = 112,
	P9_ROPEN,
	P9_TREAD = 116,
	P9_RREAD,
	P9_TWRITE = 118,
	P9_RWRITE,
	P9_TCLUNK = 120,
	P9_RCLUNK,
	P9_TREMOVE = 122,
	P9_RREMOVE,
	P9_TSTAT = 124,
	P9_RSTAT,
	P9_TWSTAT = 126,
	P9_RWSTAT,
};

/* Structures for Protocol Operations */

/**
 * struct p9_str - length prefixed string type
 * @len: length of the string
 * @str: the string
 *
 * The protocol uses length prefixed strings for all
 * string data, so we replicate that for our internal
 * string members.
 */

struct p9_str {
	uint16_t len;
	char *str;
};

/**
 * struct p9_qid - file system entity information
 * @type: 8-bit type &p9_qid_t
 * @version: 16-bit monotonically incrementing version number
 * @path: 64-bit per-server-unique ID for a file system element
 *
 * qids are identifiers used by 9P servers to track file system
 * entities.  The type is used to differentiate semantics for operations
 * on the entity (ie. read means something different on a directory than
 * on a file).  The path provides a server unique index for an entity
 * (roughly analogous to an inode number), while the version is updated
 * every time a file is modified and can be used to maintain cache
 * coherency between clients and serves.
 * Servers will often differentiate purely synthetic entities by setting
 * their version to 0, signaling that they should never be cached and
 * should be accessed synchronously.
 *
 * See Also://plan9.bell-labs.com/magic/man2html/2/stat
 */

struct p9_qid {
	uint8_t type;
	uint32_t version;
	uint64_t path;
};

/*
 * response for any failed request for 9P2000.L
 * lerror replaces the reply message used in a successful call. ecode is a
 * numerical Linux errno.
 */
struct p9_rlerror {
	uint32_t ecode;
};

/*
 * file system status request
 * statfs is used to request file system information of the file system containing
 * fid.
 */
struct p9_tstatfs {
	uint32_t fid;
};

/*
 * file system status response
 * The Rstatfs response corresponds to the fields returned by the statfs(2) system
 * call.
 */
struct p9_rstatfs {
	uint32_t type;    /* type of file system (see below) */
	uint32_t bsize;   /* optimal transfer block size */
	uint64_t blocks;  /* total data blocks in file system */
	uint64_t bfree;   /* free blocks in fs */
	uint64_t bavail;  /* free blocks avail to non-superuser */
	uint64_t files;   /* total file nodes in file system */
	uint64_t ffree;   /* free file nodes in fs */
	uint64_t fsid;    /* file system id */
	uint32_t namelen; /* maximum length of filenames */
};

/*
 * prepare a handle for I/O on an existing file
 * lopen prepares fid for file I/O. flags contains Linux open(2) flags bits,
 * e.g. O_RDONLY, O_RDWR, O_WRONLY.
 */
struct p9_tlopen {
	uint32_t fid;
	uint32_t flags;
};
struct p9_rlopen {
	struct p9_qid qid;
	uint32_t iounit;
};

/*
 * prepare a handle for I/O on an new file for 9P2000.L
 * fid initially represents the parent directory of the new file. After the call it represents the new file.
 * mode contains Linux creat(2) mode bits.
 * flags is used to pass Linux kernel intent bits (FIXME: diod ignores flags)
 * gid is the effective gid of the caller.
 */
struct p9_tlcreate {
	uint32_t fid;
	struct p9_str name;
	uint32_t flags;
	uint32_t mode;
	uint32_t gid;
};
struct p9_rlcreate {
	struct p9_qid qid;
	uint32_t iounit;
};

/*
 * make symlink request
 * The link will point to symtgt.
 * gid is the effective group id of the caller.
 * The qid for the new symbolic link is returned in the reply.
 */
struct p9_tsymlink {
	uint32_t fid;
	struct p9_str name;
	struct p9_str symtgt;
	uint32_t gid;
};
struct p9_rsymlink {
	struct p9_qid qid;
};

/*
 * create a special file object request
 * mknod creates a device node name in directory dfid with major and minor numbers.
 * mode contains Linux mknod(2) mode bits.
 * gid is the effective group id of the caller.
 * The qid for the new device node is returned in the reply.
 */
struct p9_tmknod {
	uint32_t dfid;
	struct p9_str name;
	uint32_t mode;
	uint32_t major;
	uint32_t minor;
	uint32_t gid;
};
struct p9_rmknod {
	struct p9_qid qid;
};

/*
 * rename renames a file system object referenced by fid, to name in the
 * directory referenced by dfid.
 */
struct p9_trename {
	uint32_t fid;
	uint32_t dfid;
	struct p9_str name;
};
struct p9_rrename {
};

/*
 * readlink returns the contents of the symbolic link referenced by fid
 */
struct p9_treadlink {
	uint32_t fid;
};
struct p9_rreadlink {
	struct p9_str target;
};

/*
 * getattr gets attributes of a file system object referenced by fid. The
 * response is intended to follow pretty closely the fields returned by the stat(2)
 * system call
 */
struct p9_tgetattr {
	uint32_t fid;
	uint64_t request_mask;
};
struct p9_rgetattr {
	uint64_t valid;         /* bitmask */
	struct p9_qid qid;
	uint32_t mode;          /* protection */
	uint32_t uid;           /* user ID of owner */
	uint32_t gid;           /* group ID of owner */
	uint64_t nlink;         /* number of hard links */
	uint64_t rdev;          /* device ID (if special file) */
	uint64_t size;          /* total size, in bytes */
	uint64_t blksize;       /* blocksize for file system I/O */
	uint64_t blocks;        /* number of 512B blocks allocated */
	uint64_t atime_sec;     /* time of last access */
	uint64_t atime_nsec;
	uint64_t mtime_sec;     /* time of last modification */
	uint64_t mtime_nsec;
	uint64_t ctime_sec;     /* time of last status change */
	uint64_t ctime_nsec;

	// not used but reserved by 9P2000.L
	uint64_t btime_sec;
	uint64_t btime_nsec;
	uint64_t gen;
	uint64_t data_version;
};

/*
 * Not all fields are valid in every call. request_mask is a bitmask indicating
 * which fields are requested. valid is a bitmask indicating which fields are
 * valid in the response.
 */
constexpr uint64_t P9_GETATTR_MODE          = 0x00000001ULL;
constexpr uint64_t P9_GETATTR_NLINK         = 0x00000002ULL;
constexpr uint64_t P9_GETATTR_UID           = 0x00000004ULL;
constexpr uint64_t P9_GETATTR_GID           = 0x00000008ULL;
constexpr uint64_t P9_GETATTR_RDEV          = 0x00000010ULL;
constexpr uint64_t P9_GETATTR_ATIME         = 0x00000020ULL;
constexpr uint64_t P9_GETATTR_MTIME         = 0x00000040ULL;
constexpr uint64_t P9_GETATTR_CTIME         = 0x00000080ULL;
constexpr uint64_t P9_GETATTR_INO           = 0x00000100ULL;
constexpr uint64_t P9_GETATTR_SIZE          = 0x00000200ULL;
constexpr uint64_t P9_GETATTR_BLOCKS        = 0x00000400ULL;

constexpr uint64_t P9_GETATTR_BTIME         = 0x00000800ULL;
constexpr uint64_t P9_GETATTR_GEN           = 0x00001000ULL;
constexpr uint64_t P9_GETATTR_DATA_VERSION  = 0x00002000ULL;

constexpr uint64_t P9_GETATTR_BASIC         = 0x000007ffULL; /* Mask for fields up to BLOCKS */
constexpr uint64_t P9_GETATTR_ALL           = 0x00003fffULL; /* Mask for All fields above */

/*
 * setattr sets attributes of a file system object referenced by fid. As with
 * getattr, valid is a bitmask selecting which fields to set, which can be any
 * combination of:
 */
struct p9_tsetattr {
	uint32_t fid;
	uint32_t valid;      /* mask */
	uint32_t mode;       /* Linux chmod(2) mode bits. */
	uint32_t uid;        /* user ID of owner */
	uint32_t gid;        /* group ID of owner */
	uint64_t size;       /* New file size as handled by Linux truncate(2) */
	uint64_t atime_sec;  /* Time of last file access */
	uint64_t atime_nsec;
	uint64_t mtime_sec;  /* Time of last file modification */
	uint64_t mtime_nsec;
};
struct p9_rsetattr {
};

/*
 * If a time bit is set without the corresponding SET bit, the current system time
 * on the server is used instead of the value sent in the request.
 */
constexpr uint64_t P9_SETATTR_MODE          = 0x00000001UL;
constexpr uint64_t P9_SETATTR_UID           = 0x00000002UL;
constexpr uint64_t P9_SETATTR_GID           = 0x00000004UL;
constexpr uint64_t P9_SETATTR_SIZE          = 0x00000008UL;
constexpr uint64_t P9_SETATTR_ATIME         = 0x00000010UL;
constexpr uint64_t P9_SETATTR_MTIME         = 0x00000020UL;
constexpr uint64_t P9_SETATTR_CTIME         = 0x00000040UL;
constexpr uint64_t P9_SETATTR_ATIME_SET     = 0x00000080UL;
constexpr uint64_t P9_SETATTR_MTIME_SET     = 0x00000100UL;

/*
 * prepare to read/list extended attributes
 * xattrwalk gets a newfid pointing to xattr name. This fid can later be used to
 * read the xattr value. If name is NULL newfid can be used to get the list of
 * extended attributes associated with the file system object.
 */
struct p9_txattrwalk {
	uint32_t fid;
	uint32_t attrfid;
	struct p9_str name;
};
struct p9_rxattrwalk {
	uint64_t size;
};

/*
 * prepare to set extended attribute
 * xattrcreate gets a fid pointing to the xattr name. This fid can later be used to
 * set the xattr value

 * The actual setxattr operation happens when the fid is clunked. At that point
 * the written byte count and the attr_size specified in TXATTRCREATE should be
 * same otherwise an error will be returned.
 */
struct p9_txattrcreate {
	uint32_t fid;
	struct p9_str name;
	uint64_t size;
	uint32_t flag; /* flag is derived from set Linux setxattr */
};
struct p9_rxattrcreate {
};

/*
 * read a directory
 * readdir requests that the server return directory entries from the directory
 * represented by fid, previously opened with lopen. offset is zero on the first
 * call.
 */
struct p9_treaddir {
	uint32_t fid;
	uint64_t offset;
	uint32_t count;
};
struct p9_rreaddir {
	uint32_t count; /* If count is not zero in the response, more data is available. */
	uint8_t *data;
};

/*
 * flush any cached data to disk
 * fsync tells the server to flush any cached data associated with fid, previously
 * opened with lopen.
 */
struct p9_tfsync {
	uint32_t fid;
};
struct p9_rfsync {
};

/*
 * create hard link
 * link creates a hard link name in directory dfid. The link target is referenced
 * by fid.
 */
struct p9_tlink {
	uint32_t dfid;
	uint32_t fid;
	struct p9_str name;
};
struct p9_rlink {
};

/*
 * create directory
 * mkdir creates a new directory name in parent directory dfid.
 * mode contains Linux mkdir(2) mode bits.
 * gid is the effective group ID of the caller.
 * The qid of the new directory is returned in the response.
 */
struct p9_tmkdir {
	uint32_t fid;
	struct p9_str name;
	uint32_t mode;
	uint32_t gid;
};
struct p9_rmkdir {
	struct p9_qid qid;
};

/*
 * rename a file or directory
 * Change the name of a file from oldname to newname, possible moving it from old
 * directory represented by olddirfid to new directory represented by newdirfid.
 *
 * Prefer renameat over rename
 */
struct p9_trenameat {
	uint32_t olddirfid;
	struct p9_str oldname;
	uint32_t newdirfid;
	struct p9_str newname;
};
struct p9_rrenameat {
};

/*
 * unlink a file or directory
 * Unlink name from directory represented by dirfd. If the file is represented
 * by a fid, that fid is not clunked.
 */
struct p9_tunlinkat {
	uint32_t dirfid;
	struct p9_str name;
	uint32_t flags;
};
struct p9_runlinkat {
};

/*
 * negotiate protocol version
 * version establishes the msize, which is the maximum message size inclusive of
 * the size value that can be handled by both client and server.
 * It also establishes the protocol version.
 */
struct p9_tversion {
	uint32_t msize;
	struct p9_str version;
};
struct p9_rversion {
	uint32_t msize;
	struct p9_str version;
};



/*
 * afid can be P9_NOFID (~0) or the fid from a previous auth handshake. The afid
 * can be clunked immediately after the attach.
 *
 * n_uname, if not set to P9_NONUNAME (~0), is the uid of the user and is used in
 * preference to uname.
 *
 * auth initiates an authentication handshake for n_uname. Rlerror is returned if
 * authentication is not required. If successful, afid is used to read/write the
 * authentication handshake (protocol does not specify what is read/written), and
 * afid is presented in the attach.
 */
struct p9_tauth {
	uint32_t afid;
	struct p9_str uname;
	struct p9_str aname;
	uint32_t n_uname;		/* 9P2000.u extensions */
};
struct p9_rauth {
	struct p9_qid qid;
};

/*
 * attach introduces a new user to the server, and establishes fid as the root for
 * that user on the file tree selected by aname.
 */
struct p9_tattach {
	uint32_t fid;
	uint32_t afid;
	struct p9_str uname;
	struct p9_str aname;
	uint32_t n_uname;		/* 9P2000.u extensions */
};
struct p9_rattach {
	struct p9_qid qid;
};

/* flush aborts an in-flight request referenced by oldtag, if any. */
struct p9_tflush {
	uint16_t oldtag;
};
struct p9_rflush {
};

/*
 * descend a directory hierarchy
 * walk is used to descend a directory represented by fid using successive path
 * elements provided in the wname array. If successful, newfid represents the new
 * path.
 * fid can be cloned to newfid by calling walk with nwname set to zero.
 */

constexpr uint8_t P9_MAXWELEM = 16;

struct p9_twalk {
	uint32_t fid;
	uint32_t newfid;
	uint16_t nwname;
	struct p9_str wnames[P9_MAXWELEM];
};
struct p9_rwalk {
	uint16_t nwqid;
	struct p9_qid wqids[P9_MAXWELEM];
};

/*
 * read and write perform I/O on the file represented by fid.
 * can't be used on directories. see readdir
 */
struct p9_tread {
	uint32_t fid;
	uint64_t offset;
	uint32_t count;
};
struct p9_rread {
	uint32_t count;
	uint8_t *data;
};

struct p9_twrite {
	uint32_t fid;
	uint64_t offset;
	uint32_t count;
	uint8_t *data;
};
struct p9_rwrite {
	uint32_t count;
};

/*
 * destroy a fid
 * clunk signifies that fid is no longer needed by the client.
 */
struct p9_tclunk {
	uint32_t fid;
};
struct p9_rclunk {
};

/*
 * remove a file system object
 * remove removes the file system object represented by fid
 */
struct p9_tremove {
	uint32_t fid;
};
struct p9_rremove {
};
