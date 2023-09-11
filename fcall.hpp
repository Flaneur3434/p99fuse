#include <variant>
#include "9p.h"

/*
 * These routines convert messages in the machine–independent format of the Plan 9
 * file protocol, 9P, to and from a more convenient form, an Fcall structure:
 */


struct fcall {
		uint32_t size;
		uint8_t type;
		uint16_t tag;
		std::variant <
				p9_rlerror,
				p9_tstatfs,
				p9_rstatfs,
				p9_tlopen,
				p9_rlopen,
				p9_tlcreate,
				p9_rlcreate,
				p9_tsymlink,
				p9_rsymlink,
				p9_tmknod,
				p9_rmknod,
				p9_trename,
				p9_rrename,
				p9_treadlink,
				p9_rreadlink,
				p9_tgetattr,
				p9_rgetattr,
				p9_tsetattr,
				p9_rsetattr,
				p9_txattrwalk,
				p9_rxattrwalk,
				p9_txattrcreate,
				p9_rxattrcreate,
				p9_treaddir,
				p9_rreaddir,
				p9_tfsync,
				p9_rfsync,
				p9_tlock,
				p9_rlock,
				p9_tgetlock,
				p9_rgetlock,
				p9_tlink,
				p9_rlink,
				p9_tmkdir,
				p9_rmkdir,
				p9_trenameat,
				p9_rrenameat,
				p9_tunlinkat,
				p9_runlinkat,
				p9_tversion,
				p9_rversion,
				p9_tauth,
				p9_rauth,
				p9_tattach,
				p9_rattach,
				p9_tflush,
				p9_rflush,
				p9_twalk,
				p9_rwalk,
				p9_tread,
				p9_rread,
				p9_twrite,
				p9_rwrite,
				p9_tclunk,
				p9_rclunk,
				p9_tremove,
				p9_rremove
				> fcall;

};
