#include "secure.h"

namespace RD_FUZZER
{
	VCHANNEL * RDP_SEC::channel_register(char * name, uint32 flags, void(*callback)(STREAM))
	{
		VCHANNEL *channel;

		if (!use_rdp5)
			return NULL;

		if (num_channels >= MAX_CHANNELS)
		{
			error("Channel table full, increase MAX_CHANNELS\n");
			return NULL;
		}

		channel = &channels[num_channels];
		channel->mcs_id = MCS_GLOBAL_CHANNEL + 1 + num_channels;
		strncpy_s(channel->name, 8, name, 8);
		channel->flags = flags;
		channel->process = callback;
		num_channels++;
		return channel;
	}

	STREAM RDP_SEC::channel_init(VCHANNEL * channel, uint32 length)
	{
		STREAM s;

		s = sec_init(encryption ? SEC_ENCRYPT : 0, length + 8);
		s_push_layer(s, channel_hdr, 8);
		return s;
	}

	void RDP_SEC::channel_send(STREAM s, VCHANNEL * channel)
	{
		uint32 length, flags;
		uint32 thislength, remaining;
		uint8 *data;

#ifdef WITH_SCARD
		scard_lock(SCARD_LOCK_CHANNEL);
#endif

		/* first fragment sent in-place */
		s_pop_layer(s, channel_hdr);
		length = s->end - s->p - 8;

		DEBUG_CHANNEL(("channel_send, length = %d\n", length));

		thislength = MIN(length, CHANNEL_CHUNK_LENGTH);
		/* Note: In the original clipboard implementation, this number was
		1592, not 1600. However, I don't remember the reason and 1600 seems
		to work so.. This applies only to *this* length, not the length of
		continuation or ending packets. */
		remaining = length - thislength;
		flags = (remaining == 0) ? CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST : CHANNEL_FLAG_FIRST;
		if (channel->flags & CHANNEL_OPTION_SHOW_PROTOCOL)
			flags |= CHANNEL_FLAG_SHOW_PROTOCOL;

		out_uint32_le(s, length);
		out_uint32_le(s, flags);
		data = s->end = s->p + thislength;
		DEBUG_CHANNEL(("Sending %d bytes with FLAG_FIRST\n", thislength));
		sec_send_to_channel(s, encryption ? SEC_ENCRYPT : 0, channel->mcs_id);

		/* subsequent segments copied (otherwise would have to generate headers backwards) */
		while (remaining > 0)
		{
			thislength = MIN(remaining, CHANNEL_CHUNK_LENGTH);
			remaining -= thislength;
			flags = (remaining == 0) ? CHANNEL_FLAG_LAST : 0;
			if (channel->flags & CHANNEL_OPTION_SHOW_PROTOCOL)
				flags |= CHANNEL_FLAG_SHOW_PROTOCOL;

			DEBUG_CHANNEL(("Sending %d bytes with flags %d\n", thislength, flags));

			s = sec_init(encryption ? SEC_ENCRYPT : 0, thislength + 8);
			out_uint32_le(s, length);
			out_uint32_le(s, flags);
			out_uint8p(s, data, thislength);
			s_mark_end(s);
			sec_send_to_channel(s, encryption ? SEC_ENCRYPT : 0, channel->mcs_id);

			data += thislength;
		}

#ifdef WITH_SCARD
		scard_unlock(SCARD_LOCK_CHANNEL);
#endif
	}

	void RDP_SEC::channel_process(STREAM s, uint16 mcs_channel)
	{
		uint32 length, flags;
		uint32 thislength;
		VCHANNEL *channel = NULL;
		unsigned int i;
		STREAM in;

		for (i = 0; i < num_channels; i++)
		{
			channel = &channels[i];
			if (channel->mcs_id == mcs_channel)
				break;
		}

		if (i >= num_channels)
			return;

		in_uint32_le(s, length);
		in_uint32_le(s, flags);
		if ((flags & CHANNEL_FLAG_FIRST) && (flags & CHANNEL_FLAG_LAST))
		{
			/* single fragment - pass straight up */
			channel->process(s);
		}
		else
		{
			/* add fragment to defragmentation buffer */
			in = &channel->in;
			if (flags & CHANNEL_FLAG_FIRST)
			{
				if (length > in->size)
				{
					in->data = (uint8 *)xrealloc(in->data, length);
					in->size = length;
				}
				in->p = in->data;
			}

			thislength = MIN(s->end - s->p, in->data + in->size - in->p);
			memcpy(in->p, s->p, thislength);
			in->p += thislength;

			if (flags & CHANNEL_FLAG_LAST)
			{
				in->end = in->p;
				in->p = in->data;
				channel->process(in);
			}
		}
	}
}

