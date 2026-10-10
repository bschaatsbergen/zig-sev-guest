/* Compile-only check against the Linux UAPI headers shipped with Zig 0.17. */
#include <stddef.h>
#include <sys/ioctl.h>
#include <linux/sev-guest.h>

_Static_assert(sizeof(struct snp_report_req) == 96, "report request size");
_Static_assert(_Alignof(struct snp_report_req) == 4, "report request alignment");
_Static_assert(offsetof(struct snp_report_req, vmpl) == 64, "VMPL offset");
_Static_assert(offsetof(struct snp_report_req, rsvd) == 68, "reserved offset");
_Static_assert(sizeof(struct snp_report_resp) == 4000, "response size");
_Static_assert(_Alignof(struct snp_report_resp) == 1, "response alignment");
_Static_assert(sizeof(struct snp_guest_request_ioctl) == 32, "ioctl argument size");
_Static_assert(_Alignof(struct snp_guest_request_ioctl) == 8, "ioctl alignment");
_Static_assert(offsetof(struct snp_guest_request_ioctl, req_data) == 8, "request pointer offset");
_Static_assert(offsetof(struct snp_guest_request_ioctl, resp_data) == 16, "response pointer offset");
_Static_assert(offsetof(struct snp_guest_request_ioctl, exitinfo2) == 24, "error offset");
_Static_assert(sizeof(struct snp_ext_report_req) == 112, "extended request size");
_Static_assert(_Alignof(struct snp_ext_report_req) == 8, "extended request alignment");
_Static_assert(offsetof(struct snp_ext_report_req, certs_address) == 96, "certificate pointer offset");
_Static_assert(offsetof(struct snp_ext_report_req, certs_len) == 104, "certificate length offset");
_Static_assert(SNP_GET_REPORT == 0xc0205300U, "report ioctl");
_Static_assert(SNP_GET_EXT_REPORT == 0xc0205302U, "extended report ioctl");
