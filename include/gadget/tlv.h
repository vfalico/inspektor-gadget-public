/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __GADGET_TLV_H
#define __GADGET_TLV_H

#include <bpf/bpf_helpers.h>

/*
 * TLV (Type-Length-Value) encoding helpers for optional big fields.
 *
 * Instead of including large optional fields (like cwd, exepath) at fixed
 * offsets in the event struct, gadgets can append them as TLV entries after
 * the variable-length portion of the event. This avoids sending unused bytes
 * over perf/ring buffers when those fields are not requested or empty.
 *
 * Wire format (appended after the base event):
 *   [gadget_tlv_header][value bytes] [gadget_tlv_header][value bytes] ...
 *
 * The total TLV data length is derived from total_event_size - base_event_size.
 */

struct gadget_tlv_header {
	__u16 type;   /* field ID, assigned per-gadget, 1-based */
	__u16 length; /* length of value data following this header (NOT including header) */
};

#define GADGET_TLV_HDR_SIZE ((int)sizeof(struct gadget_tlv_header))

/*
 * gadget_tlv_append_str_from_kernel - Append a kernel string as a TLV entry.
 *
 * Reads the string directly into the TLV value area of the output buffer.
 *
 * @buf:       Pointer to the start of the event buffer
 * @buf_size:  Total size of the buffer (for bounds checking)
 * @offset:    Current write offset within buf (where the TLV header goes)
 * @type:      TLV field type/ID
 * @src:       Source kernel pointer for the string
 * @max_len:   Maximum bytes to read (must be bounded for verifier)
 *
 * Returns: New offset after the TLV entry, or the original offset on failure.
 */
static __always_inline __u32
gadget_tlv_append_str_from_kernel(void *buf, __u32 buf_size, __u32 offset,
				  __u16 type, const void *src, __u32 max_len)
{
	__u32 val_off = offset + GADGET_TLV_HDR_SIZE;
	long ret;

	/* Check there is room for at least the header + 1 byte */
	if (val_off + max_len > buf_size || val_off < offset)
		return offset;

	ret = bpf_probe_read_kernel_str((char *)buf + val_off, max_len, src);
	if (ret <= 0)
		return offset;

	struct gadget_tlv_header *hdr =
		(struct gadget_tlv_header *)((char *)buf + offset);
	hdr->type = type;
	hdr->length = (__u16)ret;

	return val_off + (__u32)ret;
}

/*
 * gadget_tlv_append_buf - Append a raw buffer as a TLV entry.
 *
 * Copies @len bytes from @data into the TLV value area.
 *
 * @buf:       Pointer to the start of the event buffer
 * @buf_size:  Total size of the buffer
 * @offset:    Current write offset
 * @type:      TLV field type/ID
 * @data:      Source data pointer
 * @len:       Length of data to copy
 *
 * Returns: New offset after the TLV entry, or the original offset on failure.
 */
static __always_inline __u32
gadget_tlv_append_buf(void *buf, __u32 buf_size, __u32 offset,
		      __u16 type, const void *data, __u16 len)
{
	__u32 needed = GADGET_TLV_HDR_SIZE + (__u32)len;

	if (offset + needed > buf_size || offset + needed < offset)
		return offset;

	struct gadget_tlv_header *hdr =
		(struct gadget_tlv_header *)((char *)buf + offset);
	hdr->type = type;
	hdr->length = len;

	if (len > 0)
		__builtin_memcpy((char *)buf + offset + GADGET_TLV_HDR_SIZE,
				 data, len);

	return offset + needed;
}

#endif /* __GADGET_TLV_H */
