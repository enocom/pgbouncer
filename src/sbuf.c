/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Copyright (c) 2007-2009  Marko Kreen, Skype Technologies OÜ
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Stream buffer
 *
 * The task is to copy data from one socket to another
 * efficiently, while allowing callbacks to look
 * at packet headers.
 */

#include "bouncer.h"
#include "usual/tls/tls.h"

#include <usual/safeio.h>
#include <usual/slab.h>
#include <usual/mbuf.h>

#ifdef USUAL_LIBSSL_FOR_TLS
#define USE_TLS
#endif

/* sbuf_main_loop() skip_recv values */
#define DO_RECV         false
#define SKIP_RECV       true

#define ACT_UNSET 0
#define ACT_SEND 1
#define ACT_SKIP 2
#define ACT_CALL 3

enum TLSState {
	SBUF_TLS_NONE,
	SBUF_TLS_DO_HANDSHAKE,
	SBUF_TLS_IN_HANDSHAKE,
	SBUF_TLS_OK,
};

enum WaitType {
	W_NONE = 0,
	W_CONNECT,
	W_RECV,
	W_SEND,
	W_ONCE
};

#define AssertSanity(sbuf) do { \
		Assert(iobuf_sane((sbuf)->io)); \
} while (0)

#define AssertActive(sbuf) do { \
		Assert((sbuf)->sock > 0); \
		AssertSanity(sbuf); \
} while (0)

/* declare static stuff */
static bool sbuf_queue_send(SBuf *sbuf) _MUSTCHECK;
static bool sbuf_send_pending_iobuf(SBuf *sbuf) _MUSTCHECK;
static bool sbuf_process_pending(SBuf *sbuf) _MUSTCHECK;
static void sbuf_connect_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_recv_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_send_cb(evutil_socket_t sock, short flags, void *arg);
static void sbuf_try_resync(SBuf *sbuf, bool release);
static bool sbuf_wait_for_data(SBuf *sbuf) _MUSTCHECK;
static void sbuf_main_loop(SBuf *sbuf, bool skip_recv);
static bool sbuf_call_proto(SBuf *sbuf, int event) /* _MUSTCHECK */;
static bool sbuf_actual_recv(SBuf *sbuf, size_t len)  _MUSTCHECK;
static bool sbuf_after_connect_check(SBuf *sbuf)  _MUSTCHECK;
static bool handle_tls_handshake(SBuf *sbuf) _MUSTCHECK;
static bool handle_tls_startup(SBuf *sbuf, bool is_unix) _MUSTCHECK;

/* regular I/O */
static ssize_t raw_sbufio_peek(struct SBuf *sbuf, void *buf, size_t len);
static ssize_t raw_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len);
static ssize_t raw_sbufio_send(struct SBuf *sbuf, const void *data, size_t len);
static int raw_sbufio_close(struct SBuf *sbuf);
static const SBufIO raw_sbufio_ops = {
	raw_sbufio_peek,
	raw_sbufio_recv,
	raw_sbufio_send,
	raw_sbufio_close
};

/* I/O over TLS */
#ifdef USE_TLS
static ssize_t tls_sbufio_peek(struct SBuf *sbuf, void *buf, size_t len);
static ssize_t tls_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len);
static ssize_t tls_sbufio_send(struct SBuf *sbuf, const void *data, size_t len);
static int tls_sbufio_close(struct SBuf *sbuf);
static const SBufIO tls_sbufio_ops = {
	tls_sbufio_peek,
	tls_sbufio_recv,
	tls_sbufio_send,
	tls_sbufio_close
};
static void sbuf_tls_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf);
static void sbuf_tls_startup_cb(evutil_socket_t fd, short flags, void *_sbuf);
#endif

/*
 *********************************
 * Public functions
 *********************************
 */

/* initialize SBuf with proto handler */
void sbuf_init(SBuf *sbuf, sbuf_cb_t proto_fn)
{
	memset(sbuf, 0, sizeof(SBuf));
	sbuf->proto_cb = proto_fn;
	sbuf->ops = &raw_sbufio_ops;
}

/* got new socket from accept() */
bool sbuf_accept(SBuf *sbuf, int sock, bool is_unix)
{
	bool res;

	Assert(iobuf_empty(sbuf->io) && sbuf->sock == 0);
	AssertSanity(sbuf);

	sbuf->sock = sock;
	if (!tune_socket(sock, is_unix))
		goto failed;

	if (!cf_reboot) {
		res = sbuf_wait_for_data(sbuf);
		if (!res)
			goto failed;
		if (!handle_tls_startup(sbuf, is_unix))
			goto failed;
		/* socket should already have some data (linux only) */
		if (sbuf->wait_type == W_RECV && cf_tcp_defer_accept && !is_unix) {
			sbuf_main_loop(sbuf, DO_RECV);
			if (!sbuf->sock)
				return false;
		}
	}
	return true;
failed:
	sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
	return false;
}

/* need to connect() to get a socket */
bool sbuf_connect(SBuf *sbuf, const struct sockaddr *sa, socklen_t sa_len, time_t timeout_sec)
{
	int res, sock;
	struct timeval timeout;
	char buf[128];
	bool is_unix = sa->sa_family == AF_UNIX;

	Assert(iobuf_empty(sbuf->io) && sbuf->sock == 0);
	AssertSanity(sbuf);

	/*
	 * common stuff
	 */
	sock = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock < 0) {
		/* probably fd limit */
		goto failed;
	}

	if (!tune_socket(sock, is_unix))
		goto failed;

	sbuf->sock = sock;

	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	/* launch connection */
	res = safe_connect(sock, sa, sa_len);
	if (res == 0) {
		/* unix socket gives connection immediately */
		sbuf_connect_cb(sock, EV_WRITE, sbuf);
		return true;
	} else if (errno == EINPROGRESS || errno == EAGAIN) {
		/* tcp socket needs waiting */
		event_assign(&sbuf->ev, pgb_event_base, sock, EV_WRITE, sbuf_connect_cb, sbuf);
		res = event_add(&sbuf->ev, &timeout);
		if (res >= 0) {
			sbuf->wait_type = W_CONNECT;
			return true;
		}
	}

failed:
	log_warning("sbuf_connect failed to connect to %s: %s",
		    sa2str(sa, buf, sizeof(buf)), strerror(errno));

	if (sock >= 0)
		safe_close(sock);
	sbuf->sock = 0;
	sbuf_call_proto(sbuf, SBUF_EV_CONNECT_FAILED);
	return false;
}

/* don't wait for data on this socket */
bool sbuf_pause(SBuf *sbuf)
{
	AssertActive(sbuf);
	Assert(sbuf->wait_type == W_RECV);

	if (event_del(&sbuf->ev) < 0) {
		log_warning("event_del: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_NONE;
	return true;
}

/* resume from pause, start waiting for data */
void sbuf_continue(SBuf *sbuf)
{
	bool do_recv = DO_RECV;
	bool res;
	AssertActive(sbuf);

	res = sbuf_wait_for_data(sbuf);
	if (!res) {
		/* drop if problems */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return;
	}

	/*
	 * It's tempting to try to avoid the recv() but that would
	 * only work if no code wants to see full packet.
	 *
	 * This is not true in ServerParameter case.
	 */
	/*
	 * if (sbuf->recv_pos - sbuf->pkt_pos >= SBUF_SMALL_PKT)
	 *	do_recv = false;
	 */

	sbuf_main_loop(sbuf, do_recv);
}

/*
 * Resume from pause and give socket over to external
 * callback function.
 *
 * The callback will be called with arg given to sbuf_init.
 */
bool sbuf_continue_with_callback(SBuf *sbuf, event_callback_fn user_cb)
{
	int err;

	AssertActive(sbuf);

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ | EV_PERSIST,
		     user_cb, sbuf);

	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_continue_with_callback: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_RECV;
	return true;
}

bool sbuf_use_callback_once(SBuf *sbuf, short ev, event_callback_fn user_cb)
{
	int err;
	AssertActive(sbuf);

	if (sbuf->wait_type != W_NONE) {
		err = event_del(&sbuf->ev);
		sbuf->wait_type = W_NONE;	/* make sure its called only once */
		if (err < 0) {
			log_warning("sbuf_queue_once: event_del failed: %s", strerror(errno));
			return false;
		}
	}

	/* setup one one-off event handler */
	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, ev, user_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_queue_once: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_ONCE;
	return true;
}

/* socket cleanup & close: keeps .handler and .arg values */
bool sbuf_close(SBuf *sbuf)
{
	if (sbuf->wait_type) {
		Assert(sbuf->sock);
		/* event_del() acts funny occasionally, debug it */
		errno = 0;
		if (event_del(&sbuf->ev) < 0) {
			if (errno) {
				log_warning("event_del: %s", strerror(errno));
			} else {
				log_warning("event_del: libevent error");
			}
			/* we can retry whole sbuf_close() if needed */
			/* if (errno == ENOMEM) return false; */
		}
	}
	sbuf_op_close(sbuf);
	sbuf->dst = NULL;
	sbuf->sock = 0;
	sbuf->pkt_remain = 0;
	sbuf->pkt_action = sbuf->wait_type = 0;
	if (sbuf->io) {
		slab_free(iobuf_cache, sbuf->io);
		sbuf->io = NULL;
	}
	mbuf_free(&sbuf->extra_packets);
	return true;
}

/* proto_fn tells to send some bytes to socket */
void sbuf_prepare_send(SBuf *sbuf, SBuf *dst, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || sbuf->pkt_action == ACT_SEND || iobuf_amount_pending(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_SEND;
	sbuf->pkt_remain = amount;
	sbuf->dst = dst;
}

/* proto_fn tells to skip some amount of bytes */
void sbuf_prepare_skip(SBuf *sbuf, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || iobuf_send_pending_avail(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_SKIP;
	sbuf->skip_remain = amount;
	sbuf->pkt_remain = amount;
}

/*
 * proto_fn tells to send some bytes to socket, but before doing that skip
 * some of the bytes first.
 */
void sbuf_prepare_skip_then_send_leftover(SBuf *sbuf, SBuf *dst, unsigned skip_amount, unsigned total_amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || sbuf->pkt_action == ACT_SEND || iobuf_amount_pending(&sbuf->io)); */
	Assert(total_amount > 0);
	Assert(total_amount >= skip_amount);

	sbuf->pkt_action = ACT_SKIP;
	sbuf->pkt_remain = total_amount;
	sbuf->skip_remain = skip_amount;
	sbuf->dst = dst;
}

/*
 * proto_fn tells to skip some amount of bytes and call a callback with those
 * bytes instead
 */
void sbuf_prepare_fetch(SBuf *sbuf, unsigned amount)
{
	AssertActive(sbuf);
	Assert(sbuf->pkt_remain == 0);
	/* Assert(sbuf->pkt_action == ACT_UNSET || iobuf_send_pending_avail(&sbuf->io)); */
	Assert(amount > 0);

	sbuf->pkt_action = ACT_CALL;
	sbuf->skip_remain = amount;
	sbuf->pkt_remain = amount;
}

/*
 * queue a packet for sending and free it too (on both failure and success)
 *
 * This is used to inject custom packets into the stream of packets from source
 * to clients. The packet is sent before the packet that is currently being
 * processed, unless src->extra_packet_queue_after is set to true (then it is
 * sent right after the current one). By calling sbuf_prepare_skip after
 * sbuf_queue_packet, you effectively repalce the current packet with the one
 * that you're passing into sbuf_queue_packet.
 */
bool sbuf_queue_packet(SBuf *src, SBuf *dst, PktBuf *pkt)
{
	bool res;
	AssertActive(src);
	Assert(dst);

	/*
	 * If we're queueing the packet before the packet that we're currently
	 * handling, we need to make sure that any pending data in iobuf is
	 * flushed. One important reason to do so is because we might want to
	 * call sbuf_prepare_skip later (to skip sending the current packet and
	 * completely replace it with this packet). Then the resulting ACT_SKIP
	 * will trigger a flush of iobuf too. By making sure we're flush here
	 * already, we make sure that its impossible for the flush caused by
	 * ACT_SKIP to fail. And knowing that significantly reduces the already
	 * complex failure scenarios we need to consider, because any failure
	 * will cause a rerun of the code that queues these packets.
	 */
	Assert(src->extra_packet_queue_after
	       || src->io == NULL
	       || iobuf_amount_pending(src->io) == 0);

	if (!pkt || pkt->failed) {
		pktbuf_free(pkt);
		return false;
	}
	src->dst = dst;
	res = mbuf_write(&src->extra_packets, pkt->buf, pkt->write_pos);
	pktbuf_free(pkt);
	return res;
}

/*
 * queue the packet in PktHdr for sending
 *
 * This is pretty much the same as sbuf_queue_packet, but it works with a PktHdr
 * instead of a PktBuf. Apart from that the only difference is that it does not
 * free the passed in packet.
 */
bool sbuf_queue_full_packet(SBuf *src, SBuf *dst, PktHdr *pkt)
{
	bool res;
	AssertActive(src);
	Assert(dst);

	/*
	 * If we're queueing the packet before the packet that we're currently
	 * handling, we need to make sure that any pending data in iobuf is
	 * flushed. One important reason to do so is because we might want to
	 * call sbuf_prepare_skip later (to skip sending the current packet and
	 * completely replace it with this packet). Then the resulting ACT_SKIP
	 * will trigger a flush of iobuf too. By making sure we're flush here
	 * already, we make sure that its impossible for the flush caused by
	 * ACT_SKIP to fail. And knowing that significantly reduces the already
	 * complex failure scenarios we need to consider, because any failure
	 * will cause a rerun of the code that queues these packets.
	 */
	Assert(src->extra_packet_queue_after
	       || src->io == NULL
	       || iobuf_amount_pending(src->io) == 0);
	Assert(!incomplete_pkt(pkt));
	Assert(pkt->data.read_pos == 0);
	src->dst = dst;
	res = mbuf_write(&src->extra_packets, pkt->data.data, pkt->data.write_pos);
	return res;
}


/*
 *************************
 * Internal functions
 *************************
 */

/*
 * Call proto callback with proper struct MBuf.
 *
 * If callback returns true it used one of sbuf_prepare_* on sbuf,
 * and processing can continue.
 *
 * If it returned false it used sbuf_pause(), sbuf_close() or simply
 * wants to wait for next event loop (e.g. too few data available).
 * Callee should not touch sbuf in that case and just return to libevent.
 */
static bool sbuf_call_proto(SBuf *sbuf, int event)
{
	struct MBuf mbuf;
	IOBuf *io = sbuf->io;
	bool res;

	AssertSanity(sbuf);
	Assert(event != SBUF_EV_READ || iobuf_amount_parse(io) > 0);

	/* if pkt callback, limit only with current packet */
	if (event == SBUF_EV_PKT_CALLBACK) {
		iobuf_parse_limit(io, &mbuf, sbuf->pkt_remain);
	} else if (event == SBUF_EV_READ) {
		iobuf_parse_all(io, &mbuf);
	} else {
		memset(&mbuf, 0, sizeof(mbuf));
	}
	res = sbuf->proto_cb(sbuf, event, &mbuf);

	AssertSanity(sbuf);
	Assert(event != SBUF_EV_READ || !res || sbuf->sock > 0);

	return res;
}

/* let's wait for new data */
static bool sbuf_wait_for_data(SBuf *sbuf)
{
	int err;

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ | EV_PERSIST, sbuf_recv_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_wait_for_data: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_RECV;
	return true;
}

static void sbuf_recv_forced_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;

	sbuf->wait_type = W_NONE;

	if (sbuf_wait_for_data(sbuf)) {
		sbuf_recv_cb(sock, flags, arg);
	} else {
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
	}
}

static bool sbuf_wait_for_data_forced(SBuf *sbuf)
{
	int err;
	struct timeval tv_min;

	tv_min.tv_sec = 0;
	tv_min.tv_usec = 1;

	if (sbuf->wait_type != W_NONE) {
		event_del(&sbuf->ev);
		sbuf->wait_type = W_NONE;
	}

	event_assign(&sbuf->ev, pgb_event_base, sbuf->sock, EV_READ, sbuf_recv_forced_cb, sbuf);
	err = event_add(&sbuf->ev, &tv_min);
	if (err < 0) {
		log_warning("sbuf_wait_for_data: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_ONCE;
	return true;
}

/* libevent EV_WRITE: called when dest socket is writable again */
static void sbuf_send_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;
	bool res;
	log_noise("Socket is writable again");

	/* sbuf was closed before in this loop */
	if (!sbuf->sock)
		return;

	AssertSanity(sbuf);
	Assert(sbuf->wait_type == W_SEND);

	sbuf->wait_type = W_NONE;

	/* prepare normal situation for sbuf_main_loop */
	res = sbuf_wait_for_data(sbuf);
	if (res) {
		/* here we should certainly skip recv() */
		sbuf_main_loop(sbuf, SKIP_RECV);
	} else {
		/* drop if problems */
		sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
	}
}

/* socket is full, wait until it's writable again */
static bool sbuf_queue_send(SBuf *sbuf)
{
	int err;
	AssertActive(sbuf);
	Assert(sbuf->wait_type == W_RECV);

	/* if false is returned, the socket will be closed later */

	/* stop waiting for read events */
	err = event_del(&sbuf->ev);
	sbuf->wait_type = W_NONE;	/* make sure its called only once */
	if (err < 0) {
		log_warning("sbuf_queue_send: event_del failed: %s", strerror(errno));
		return false;
	}

	/* instead wait for EV_WRITE on destination socket */
	event_assign(&sbuf->ev, pgb_event_base, sbuf->dst->sock, EV_WRITE, sbuf_send_cb, sbuf);
	err = event_add(&sbuf->ev, NULL);
	if (err < 0) {
		log_warning("sbuf_queue_send: event_add failed: %s", strerror(errno));
		return false;
	}
	sbuf->wait_type = W_SEND;

	return true;
}

/*
 * flush all pending data in the iobuf. This should be called before calling
 * needed before calling sbuf_queue_packet.
 */
bool sbuf_flush(SBuf *sbuf)
{
	if (sbuf->io) {
		log_noise("sbuf_flush");
		return sbuf_send_pending_iobuf(sbuf);
	}
	return true;
}

/*
 * There's data in buffer to be sent. Returns bool if processing can continue.
 *
 * Does not look at pkt_pos/remain fields, expects them to be merged to send_*
 */
static bool sbuf_send_pending_iobuf(SBuf *sbuf)
{
	int avail;
	ssize_t res;
	IOBuf *io = sbuf->io;

	AssertActive(sbuf);
	Assert(sbuf->dst || iobuf_amount_pending(io) == 0);
	log_noise("sbuf_send_pending_iobuf");

try_more:
	/* how much data is available for sending */
	avail = iobuf_amount_pending(io);
	if (avail == 0)
		return true;

	if (sbuf->dst->sock == 0) {
		log_error("sbuf_send_pending_iobuf: no dst sock?");
		sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		return false;
	}

	/* actually send it */
	//res = iobuf_send_pending(io, sbuf->dst->sock);
	res = sbuf_op_send(sbuf->dst, io->buf + io->done_pos, avail);
	if (res > 0) {
		io->done_pos += res;
	} else if (res < 0) {
		if (errno == EAGAIN) {
			if (!sbuf_queue_send(sbuf)) {
				/* drop if queue failed */
				sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
			}
		} else {
			sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		}
		return false;
	}

	AssertActive(sbuf);

	/*
	 * Should do sbuf_queue_send() immediately?
	 *
	 * To be sure, let's run into EAGAIN.
	 */
	goto try_more;
}

/*
 * There's data in extra_packets buffer to be sent. Returns bool if processing
 * can continue.
 */
static bool sbuf_send_pending_extra_packets(SBuf *sbuf)
{
	int avail;
	ssize_t res;
	struct MBuf *mbuf = &sbuf->extra_packets;

	AssertActive(sbuf);
	Assert(sbuf->dst || mbuf_avail_for_read(mbuf) == 0);
	log_noise("sbuf_send_pending_extra_packets ");

try_more:
	/* how much data is available for sending */
	avail = mbuf_avail_for_read(mbuf);
	if (avail == 0)
		return true;

	if (sbuf->dst->sock == 0) {
		log_error("sbuf_send_pending_extra_packets: no dst sock?");
		sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		return false;
	}

	/* actually send it */
	//res = iobuf_send_pending(io, sbuf->dst->sock);
	res = sbuf_op_send(sbuf->dst, mbuf->data + mbuf->read_pos, avail);
	if (res > 0) {
		mbuf->read_pos += res;
	} else if (res < 0) {
		if (errno == EAGAIN) {
			if (!sbuf_queue_send(sbuf)) {
				/* drop if queue failed */
				sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
			}
		} else {
			sbuf_call_proto(sbuf, SBUF_EV_SEND_FAILED);
		}
		return false;
	}

	AssertActive(sbuf);

	/*
	 * Should do sbuf_queue_send() immediately?
	 *
	 * To be sure, let's run into EAGAIN.
	 */
	goto try_more;
}


/* process as much data as possible */
static bool sbuf_process_pending(SBuf *sbuf)
{
	unsigned avail;
	IOBuf *io = sbuf->io;
	struct MBuf *extra_packets = &sbuf->extra_packets;
	bool full = iobuf_amount_recv(io) <= 0;
	int loop_number = 0;
	log_noise("sbuf_process_pending: start");

	while (1) {
		/*
		 * If there's still queued extra packets from a previous packet, make
		 * sure to flush those first. Otherwise the packet we process next
		 * might add even more packets there, which would be bad because it
		 * would mean they get delivered out of order.
		 */
		if (mbuf_avail_for_read(extra_packets)) {
			if (sbuf->extra_packet_queue_after) {
				if (!sbuf_send_pending_iobuf(sbuf)) {
					log_noise("sbuf_process_pending failed to send all pending data");
					return false;
				}
			}

			if (!sbuf_send_pending_extra_packets(sbuf)) {
				log_noise("sbuf_process_pending ended early because of not being able to send the queued extra packets");
				return false;
			}
			/*
			 * To avoid frequent allocations we try to reuse the
			 * extra_packets MBuf. But if it has grown to more than
			 * 4 times pkt_buf, we free it to avoid wasting memory.
			 * Otherwise one huge packet can cause a lot of memory
			 * to stay allocated for the lifetime of the
			 * connection. The most common case where this might
			 * occur is a huge query in a prepared statement.
			 *
			 * We use 4 times pkt_buf as an arbitrary but
			 * reosanable limit.
			 */
			if (extra_packets->alloc_len > (unsigned) cf_sbuf_len * 4) {
				mbuf_free(extra_packets);
			} else {
				mbuf_rewind_writer(extra_packets);
			}
		}

		AssertActive(sbuf);
		loop_number++;
		log_noise("sbuf_process_pending: loop %d", loop_number);

		/*
		 * Enough for now?
		 *
		 * The (avail <= SBUF_SMALL_PKT) check is to avoid partial pkts.
		 * As SBuf should not assume knowledge about packets,
		 * the check is not done in !full case.  Packet handler can
		 * then still notify about partial packet by returning false.
		 */
		avail = iobuf_amount_parse(io);
		if (avail == 0 || (full && avail <= SBUF_SMALL_PKT))
			break;

		/*
		 * If start of packet, process packet header.
		 */
		if (sbuf->pkt_remain == 0) {
			if (!sbuf_call_proto(sbuf, SBUF_EV_READ)) {
				goto need_more_data;
			}
			Assert(sbuf->pkt_remain > 0);
		}

		if (sbuf->pkt_action == ACT_SKIP || sbuf->pkt_action == ACT_CALL) {
			/* send any pending data before skipping */
			if (iobuf_amount_pending(io) > 0) {
				if (!sbuf_send_pending_iobuf(sbuf))
					return false;
			}
		}

		if (avail > sbuf->pkt_remain)
			avail = sbuf->pkt_remain;

		switch (sbuf->pkt_action) {
		case ACT_SEND:
			iobuf_tag_send(io, avail);
			break;
		case ACT_CALL:
			if (!sbuf_call_proto(sbuf, SBUF_EV_PKT_CALLBACK)) {
				goto need_more_data;
			}
		/* fallthrough */
		/* after callback, skip pkt */
		case ACT_SKIP:
			if (sbuf->skip_remain >= avail) {
				iobuf_tag_skip(io, avail);
				sbuf->skip_remain -= avail;
			} else {
				if (sbuf->skip_remain != 0) {
					iobuf_tag_skip(io, sbuf->skip_remain);
				}
				iobuf_tag_send(io, avail - sbuf->skip_remain);
				sbuf->skip_remain = 0;
			}
			break;
		}
		sbuf->pkt_remain -= avail;
	}

	log_noise("sbuf_process_pending: done looping");
	if (!sbuf_send_pending_iobuf(sbuf)) {
		log_noise("sbuf_process_pending failed to send all pending data");
		return false;
	}
	log_noise("sbuf_process_pending: end");
	return true;

need_more_data:
	/*
	 * We need to wait for more data before we can handle the current
	 * packet. We'll call the handler for this packet again after receiving
	 * more data and then all of the extra packets that were generated this
	 * time will be regenerated again, so clean the ones up that were
	 * generated this time.
	 */
	mbuf_rewind_writer(extra_packets);

	if (sbuf->sock && io && sbuf->wait_type == W_RECV) {
		/*
		 * There might still be some previous packets that we're able
		 * to send though. Let's do that now to create some extra space
		 * in the buffer.
		 */
		if (iobuf_amount_pending(io) > 0) {
			if (!sbuf_send_pending_iobuf(sbuf))
				return false;
		}

		/*
		 * If we've filled the whole buffer, but the packet handler
		 * still needs more data, we should force a resync to make some
		 * space.
		 */
		if (io && io->recv_pos == (unsigned) cf_sbuf_len) {
			log_noise("resync(%d): done=%u, parse=%u, recv=%u, forced",
				  sbuf->sock,
				  io->done_pos, io->parse_pos, io->recv_pos);
			iobuf_try_resync(io, cf_sbuf_len);
		}
	}

	return false;
}

/* reposition at buffer start again */
static void sbuf_try_resync(SBuf *sbuf, bool release)
{
	IOBuf *io = sbuf->io;

	if (io) {
		log_noise("resync(%d): done=%u, parse=%u, recv=%u",
			  sbuf->sock,
			  io->done_pos, io->parse_pos, io->recv_pos);
	}
	AssertActive(sbuf);

	if (!io)
		return;

	if (release && iobuf_empty(io)) {
		slab_free(iobuf_cache, io);
		sbuf->io = NULL;
	} else {
		iobuf_try_resync(io, SBUF_SMALL_PKT);
	}
}

/* actually ask kernel for more data */
static bool sbuf_actual_recv(SBuf *sbuf, size_t len)
{
	ssize_t got;
	IOBuf *io = sbuf->io;
	uint8_t *dst = io->buf + io->recv_pos;
	unsigned avail = iobuf_amount_recv(io);
	if (len > avail)
		len = avail;
	got = sbuf_op_recv(sbuf, dst, len);
	if (got > 0) {
		io->recv_pos += got;
	} else if (got == 0) {
		/* eof from socket */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return false;
	} else if (got < 0 && errno != EAGAIN) {
		/* some error occurred */
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return false;
	}
	return true;
}

/* callback for libevent EV_READ */
static void sbuf_recv_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;
	sbuf_main_loop(sbuf, DO_RECV);
}

static bool allocate_iobuf(SBuf *sbuf)
{
	if (sbuf->io == NULL) {
		sbuf->io = slab_alloc(iobuf_cache);
		if (sbuf->io == NULL) {
			sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
			return false;
		}
		iobuf_reset(sbuf->io);
	}
	return true;
}

/*
 * Main recv-parse-send-repeat loop.
 *
 * Reason for skip_recv is to avoid extra recv().  The problem with it
 * is EOF from socket.  Currently that means that the pending data is
 * dropped.  Fortunately server sockets are not paused and dropping
 * data from client is no problem.  So only place where skip_recv is
 * important is sbuf_send_cb().
 */
static void sbuf_main_loop(SBuf *sbuf, bool skip_recv)
{
	unsigned free, ok;
	int loopcnt = 0;

	/* sbuf was closed before in this event loop */
	if (!sbuf->sock)
		return;

	/* reading should be disabled when waiting */
	Assert(sbuf->wait_type == W_RECV);
	AssertSanity(sbuf);

	if (!allocate_iobuf(sbuf))
		return;

	/* avoid recv() if asked */
	if (skip_recv)
		goto skip_recv;

try_more:
	/* make room in buffer */
	sbuf_try_resync(sbuf, false);

	/* avoid spending too much time on single socket */
	if (cf_sbuf_loopcnt > 0 && loopcnt >= cf_sbuf_loopcnt) {
		bool _ignore;

		log_debug("loopcnt full");
		/*
		 * sbuf_process_pending() avoids some data if buffer is full,
		 * but as we exit processing loop here, we need to retry
		 * after resync to process all data. (result is ignored)
		 */
		_ignore = sbuf_process_pending(sbuf);
		(void) _ignore;

		sbuf_wait_for_data_forced(sbuf);
		return;
	}
	loopcnt++;

	/*
	 * here used to be if (free > SBUF_SMALL_PKT) check
	 * but with skip_recv switch its should not be needed anymore.
	 */
	free = iobuf_amount_recv(sbuf->io);
	if (free > 0) {
		/*
		 * When suspending, try to hit packet boundary ASAP.
		 */
		if (cf_pause_mode == P_SUSPEND
		    && sbuf->pkt_remain > 0
		    && sbuf->pkt_remain < free) {
			free = sbuf->pkt_remain;
		}

		/* now fetch the data */
		ok = sbuf_actual_recv(sbuf, free);
		if (!ok)
			return;
	}

skip_recv:
	/* now handle it */
	ok = sbuf_process_pending(sbuf);
	if (!ok)
		return;

	/* if the buffer is full, there can be more data available */
	if (iobuf_amount_recv(sbuf->io) <= 0)
		goto try_more;

	/* clean buffer */
	sbuf_try_resync(sbuf, true);

	/* notify proto that all is sent */
	if (sbuf_is_empty(sbuf))
		sbuf_call_proto(sbuf, SBUF_EV_FLUSH);

	if (sbuf->tls_state == SBUF_TLS_DO_HANDSHAKE) {
		sbuf->pkt_action = SBUF_TLS_IN_HANDSHAKE;
		if (!handle_tls_handshake(sbuf))
			sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
	}
}

/* check if there is any error pending on socket */
static bool sbuf_after_connect_check(SBuf *sbuf)
{
	int optval = 0, err;
	socklen_t optlen = sizeof(optval);

	err = getsockopt(sbuf->sock, SOL_SOCKET, SO_ERROR, (void *)&optval, &optlen);
	if (err < 0) {
		log_debug("sbuf_after_connect_check: getsockopt: %s",
			  strerror(errno));
		return false;
	}
	if (optval != 0) {
		log_debug("sbuf_after_connect_check: pending error: %s",
			  strerror(optval));
		return false;
	}
	return true;
}

/* callback for libevent EV_WRITE when connecting */
static void sbuf_connect_cb(evutil_socket_t sock, short flags, void *arg)
{
	SBuf *sbuf = arg;

	Assert(sbuf->wait_type == W_CONNECT || sbuf->wait_type == W_NONE);
	sbuf->wait_type = W_NONE;

	if (flags & EV_WRITE) {
		if (!sbuf_after_connect_check(sbuf))
			goto failed;
		if (!sbuf_call_proto(sbuf, SBUF_EV_CONNECT_OK))
			return;
		if (!sbuf_wait_for_data(sbuf))
			goto failed;
		return;
	}
failed:
	sbuf_call_proto(sbuf, SBUF_EV_CONNECT_FAILED);
}

/* send some data to listening socket */
bool sbuf_answer(SBuf *sbuf, const void *buf, size_t len)
{
	ssize_t res;
	if (sbuf->sock <= 0)
		return false;
	res = sbuf_op_send(sbuf, buf, len);
	if (res < 0) {
		log_debug("sbuf_answer: error sending: %s", strerror(errno));
	} else if ((unsigned)res != len) {
		log_debug("sbuf_answer: partial send: len=%zu sent=%zd", len, res);
	}
	return (unsigned)res == len;
}

/*
 * Standard IO ops.
 */

static ssize_t raw_sbufio_peek(struct SBuf *sbuf, void *buf, size_t len)
{
	return safe_recv(sbuf->sock, buf, len, 0x02);
}

static ssize_t raw_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
	return safe_recv(sbuf->sock, dst, len, 0);
}

static ssize_t raw_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	return safe_send(sbuf->sock, data, len, 0);
}

static int raw_sbufio_close(struct SBuf *sbuf)
{
	if (sbuf->sock > 0) {
		safe_close(sbuf->sock);
		sbuf->sock = 0;
	}
	return 0;
}

/*
 * TLS support.
 */

#ifdef USE_TLS

/*
 * These global variables contain the currently applied TLS configurations.
 * They might differ from the current configuration if there was an error
 * applying the configured parameters (e.g. cert file not found).
 */
static struct tls *client_accept_base;
static struct tls_config *client_accept_conf;
int client_accept_sslmode;
static struct tls_config *server_connect_conf;
int server_connect_sslmode;

#define PG_ALPN_PROTOCOL_VECTOR { 10, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 'q', 'l' }
static const unsigned char alpn_protos[] = PG_ALPN_PROTOCOL_VECTOR;

/*
 * TLS setup
 */

static bool setup_tls(struct tls_config *conf, const char *pfx, int sslmode,
		      const char *protocols, const char *ciphers, const char *ciphers13,
		      const char *keyfile, const char *certfile, const char *cafile,
		      const char *dheparams, const char *ecdhecurve,
		      bool does_connect)
{
	int err;
	if (*protocols) {
		uint32_t protos = TLS_PROTOCOLS_ALL;
		err = tls_config_parse_protocols(&protos, protocols);
		if (err) {
			log_error("invalid %s_protocols: %s", pfx, protocols);
			return false;
		}
		tls_config_set_protocols(conf, protos);
	}
	if (*ciphers) {
		err = tls_config_set_ciphers(conf, ciphers);
		if (err) {
			log_error("invalid %s_ciphers: %s", pfx, ciphers);
			return false;
		}
	}
	if (ciphers13 != NULL) {
		err = tls_config_set_ciphers_v13(conf, ciphers13);
		if (err) {
			log_error("invalid %s_ciphers: %s", pfx, ciphers13);
			return false;
		}
	}
	if (*dheparams) {
		err = tls_config_set_dheparams(conf, dheparams);
		if (err) {
			log_error("invalid %s_dheparams: %s", pfx, dheparams);
			return false;
		}
	}
	if (*ecdhecurve) {
		err = tls_config_set_ecdhecurve(conf, ecdhecurve);
		if (err) {
			log_error("invalid %s_ecdhecurve: %s", pfx, ecdhecurve);
			return false;
		}
	}
	if (*cafile) {
		err = tls_config_set_ca_file(conf, cafile);
		if (err) {
			log_error("invalid %s_ca_file: %s", pfx, cafile);
			return false;
		}
	}
	if (*keyfile) {
		err = tls_config_set_key_file(conf, keyfile);
		if (err) {
			log_error("invalid %s_key_file: %s", pfx, keyfile);
			return false;
		}
	}
	if (*certfile) {
		err = tls_config_set_cert_file(conf, certfile);
		if (err) {
			log_error("invalid %s_cert_file: %s", pfx, certfile);
			return false;
		}
	}

	if (does_connect) {
		/* TLS client, check server? */
		if (sslmode == SSLMODE_VERIFY_FULL) {
			tls_config_verify(conf);
		} else if (sslmode == SSLMODE_VERIFY_CA) {
			tls_config_verify(conf);
			tls_config_insecure_noverifyname(conf);
		} else {
			tls_config_insecure_noverifycert(conf);
			tls_config_insecure_noverifyname(conf);
		}
	} else {
		/* TLS server, check client? */
		if (sslmode == SSLMODE_VERIFY_FULL) {
			tls_config_verify_client(conf);
		} else if (sslmode == SSLMODE_VERIFY_CA) {
			tls_config_verify_client(conf);
		} else {
			tls_config_verify_client_optional(conf);
		}
		tls_config_set_alpn_protocols(conf, alpn_protos, sizeof(alpn_protos));
	}

	return true;
}

static bool tls_change_requires_reconnect(struct tls_config *new_server_connect_conf)
{
	if (server_connect_sslmode != cf_server_tls_sslmode) {
		log_noise("new server_tls_sslmode detected");
		return true;
	} else if (server_connect_conf == NULL) {
		log_noise("no existing server tls config detected");
		return true;
	} else if (tls_config_equal(new_server_connect_conf, server_connect_conf)) {
		log_noise("no server tls config change detected");
		return false;
	} else {
		log_noise("server tls config change detected");
		return true;
	}
}

bool sbuf_tls_setup(void)
{
	int err;
	/*
	 * These variables store the new TLS configurations, based on the latest
	 * settings provided by the user. Once they have been configured completely
	 * without errors they are assigned to the globals at the end of this
	 * function. This way the globals never contain partially configured TLS
	 * configurations.
	 */
	struct tls_config *new_client_accept_conf = NULL;
	struct tls_config *new_server_connect_conf = NULL;
	struct tls *new_client_accept_base = NULL;

	if (cf_client_tls_sslmode != SSLMODE_DISABLED) {
		if (!*cf_client_tls_key_file || !*cf_client_tls_cert_file) {
			log_error("To allow TLS connections from clients, client_tls_key_file and client_tls_cert_file must be set.");
			return false;
		}
	}
	if (cf_auth_type == AUTH_TYPE_CERT) {
		if (cf_client_tls_sslmode != SSLMODE_VERIFY_FULL) {
			log_error("auth_type=cert requires client_tls_sslmode=SSLMODE_VERIFY_FULL");
			return false;
		}
		if (*cf_client_tls_ca_file == '\0') {
			log_error("auth_type=cert requires client_tls_ca_file");
			return false;
		}
	} else if (cf_client_tls_sslmode > SSLMODE_VERIFY_CA && *cf_client_tls_ca_file == '\0') {
		log_error("client_tls_sslmode requires client_tls_ca_file");
		return false;
	}

	err = tls_init();
	if (err)
		fatal("tls_init failed");

	if (cf_server_tls_sslmode != SSLMODE_DISABLED) {
		new_server_connect_conf = tls_config_new();
		if (!new_server_connect_conf) {
			log_error("tls_config_new failed 1");
			return false;
		}

		if (!setup_tls(new_server_connect_conf, "server_tls", cf_server_tls_sslmode,
			       cf_server_tls_protocols, cf_server_tls_ciphers, cf_server_tls13_ciphers,
			       cf_server_tls_key_file, cf_server_tls_cert_file,
			       cf_server_tls_ca_file, "", "", true))
			goto failed;
	}

	if (cf_client_tls_sslmode != SSLMODE_DISABLED) {
		new_client_accept_conf = tls_config_new();
		if (!new_client_accept_conf) {
			log_error("tls_config_new failed 2");
			goto failed;
		}

		if (!setup_tls(new_client_accept_conf, "client_tls", cf_client_tls_sslmode,
			       cf_client_tls_protocols, cf_client_tls_ciphers, cf_client_tls13_ciphers,
			       cf_client_tls_key_file, cf_client_tls_cert_file,
			       cf_client_tls_ca_file, cf_client_tls_dheparams,
			       cf_client_tls_ecdhecurve, false))
			goto failed;

		new_client_accept_base = tls_server();
		if (!new_client_accept_base) {
			log_error("server_base failed");
			goto failed;
		}
		err = tls_configure(new_client_accept_base, new_client_accept_conf);
		if (err) {
			log_error("TLS setup failed: %s", tls_error(new_client_accept_base));
			goto failed;
		}
	}

	/*
	 * To change server TLS settings all connections are marked as dirty. This
	 * way they are recycled and the new TLS settings will be used. Otherwise
	 * old TLS settings, possibly less secure, could be used for old
	 * connections indefinitely. If TLS is disabled, and it was disabled before
	 * as well then recycling connections is not necessary, since we know none
	 * of the settings have changed. */
	if ((server_connect_conf || new_server_connect_conf) && tls_change_requires_reconnect(new_server_connect_conf)) {
		struct List *item;
		PgPool *pool;
		statlist_for_each(item, &pool_list) {
			pool = container_of(item, PgPool, head);
			tag_pool_dirty(pool);
		}
	}

	usual_tls_free(client_accept_base);
	tls_config_free(client_accept_conf);
	tls_config_free(server_connect_conf);
	client_accept_base = new_client_accept_base;
	client_accept_conf = new_client_accept_conf;
	client_accept_sslmode = cf_client_tls_sslmode;
	server_connect_conf = new_server_connect_conf;
	server_connect_sslmode = cf_server_tls_sslmode;
	return true;
failed:
	usual_tls_free(new_client_accept_base);
	tls_config_free(new_client_accept_conf);
	tls_config_free(new_server_connect_conf);
	return false;
}

/*
 * TLS handshake
 */

static bool handle_tls_handshake(SBuf *sbuf)
{
	int err;

	err = tls_handshake(sbuf->tls);
	log_noise("tls_handshake: err=%d", err);
	if (err == TLS_WANT_POLLIN) {
		return sbuf_use_callback_once(sbuf, EV_READ, sbuf_tls_handshake_cb);
	} else if (err == TLS_WANT_POLLOUT) {
		return sbuf_use_callback_once(sbuf, EV_WRITE, sbuf_tls_handshake_cb);
	} else if (err == 0) {
		sbuf->tls_state = SBUF_TLS_OK;
		sbuf_call_proto(sbuf, SBUF_EV_TLS_READY);
		return true;
	} else {
		log_warning("TLS handshake error: %s", tls_error(sbuf->tls));
		return false;
	}
}

static void sbuf_tls_handshake_cb(evutil_socket_t fd, short flags, void *_sbuf)
{
	SBuf *sbuf = _sbuf;
	sbuf->wait_type = W_NONE;
	if (!handle_tls_handshake(sbuf))
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
}

/*
 * Accept TLS connection.
 */

bool sbuf_tls_accept(SBuf *sbuf)
{
	int err;

	if (!sbuf_pause(sbuf))
		return false;

	sbuf->ops = &tls_sbufio_ops;

	err = tls_accept_fds(client_accept_base, &sbuf->tls, sbuf->sock, sbuf->sock);
	log_noise("tls_accept_fds: err=%d", err);
	if (err < 0) {
		log_warning("TLS accept error: %s", tls_error(sbuf->tls));
		return false;
	}

	sbuf->tls_state = SBUF_TLS_DO_HANDSHAKE;
	return true;
}

/*
 * Connect to remote TLS host.
 */

bool sbuf_tls_connect(SBuf *sbuf, const char *hostname)
{
	struct tls *ctls;
	int err;

	if (!sbuf_pause(sbuf))
		return false;

	if (cf_server_tls_sslmode != SSLMODE_VERIFY_FULL)
		hostname = NULL;

	ctls = tls_client();
	if (!ctls)
		return false;
	err = tls_configure(ctls, server_connect_conf);
	if (err < 0) {
		log_error("tls client config failed: %s", tls_error(ctls));
		usual_tls_free(ctls);
		return false;
	}

	sbuf->tls = ctls;
	sbuf->tls_host = hostname;
	sbuf->ops = &tls_sbufio_ops;

	err = tls_connect_fds(sbuf->tls, sbuf->sock, sbuf->sock, sbuf->tls_host);
	if (err < 0) {
		log_warning("TLS connect error: %s", tls_error(sbuf->tls));
		return false;
	}

	sbuf->tls_state = SBUF_TLS_DO_HANDSHAKE;
	return true;
}

/*
 * TLS IO ops.
 */

static ssize_t tls_sbufio_peek(struct SBuf *sbuf, void *buf, size_t len)
{
	/* unused */
	return -1;
}

static ssize_t tls_sbufio_recv(struct SBuf *sbuf, void *dst, size_t len)
{
	ssize_t out = 0;

	if (sbuf->tls_state != SBUF_TLS_OK) {
		errno = EIO;
		return -1;
	}

	out = tls_read(sbuf->tls, dst, len);
	log_noise("tls_read: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == TLS_WANT_POLLIN) {
		errno = EAGAIN;
	} else if (out == TLS_WANT_POLLOUT) {
		log_warning("tls_sbufio_recv: got TLS_WANT_POLLOUT");
		errno = EIO;
	} else {
		log_warning("tls_sbufio_recv: %s", tls_error(sbuf->tls));
		errno = EIO;
	}
	return -1;
}

static ssize_t tls_sbufio_send(struct SBuf *sbuf, const void *data, size_t len)
{
	ssize_t out;

	if (sbuf->tls_state != SBUF_TLS_OK) {
		errno = EIO;
		return -1;
	}

	out = tls_write(sbuf->tls, data, len);
	log_noise("tls_write: req=%zu out=%zd", len, out);
	if (out >= 0) {
		return out;
	} else if (out == TLS_WANT_POLLOUT) {
		errno = EAGAIN;
	} else if (out == TLS_WANT_POLLIN) {
		log_warning("tls_sbufio_send: got TLS_WANT_POLLIN");
		errno = EIO;
	} else {
		log_warning("tls_sbufio_send: %s", tls_error(sbuf->tls));
		errno = EIO;
	}
	return -1;
}

static int tls_sbufio_close(struct SBuf *sbuf)
{
	log_noise("tls_close");
	if (sbuf->tls) {
		tls_close(sbuf->tls);
		usual_tls_free(sbuf->tls);
		sbuf->tls = NULL;
	}
	if (sbuf->sock > 0) {
		safe_close(sbuf->sock);
		sbuf->sock = 0;
	}
	return 0;
}

void sbuf_cleanup(void)
{
	usual_tls_free(client_accept_base);
	tls_config_free(client_accept_conf);
	tls_config_free(server_connect_conf);
	client_accept_conf = NULL;
	server_connect_conf = NULL;
	client_accept_base = NULL;
}

static bool handle_tls_startup(SBuf *sbuf, bool is_unix)
{
	if (client_accept_sslmode == SSLMODE_DISABLED || is_unix) {
		return true;
	}
	return sbuf_use_callback_once(sbuf, EV_READ, sbuf_tls_startup_cb);
}

static void sbuf_tls_startup_cb(evutil_socket_t fd, short flags, void *_sbuf)
{
	uint8_t peek_byte[1];
	ssize_t got;
	SBuf *sbuf = _sbuf;
	PgSocket *client = container_of(sbuf, PgSocket, sbuf);
	sbuf->wait_type = W_RECV;
	got = sbuf_op_peek(sbuf, peek_byte, 1);
	if (got <= 0) {
		/* eof from socket */
		log_warning("TLS startup peek received EOF.");
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
		return;
	}

	if (peek_byte[0] != 0x16) {
		/* Not a SSL handshake message, fallback to main loop */
		sbuf_continue(sbuf);
		return;
	}
	/*
	 * First byte indicates standard SSL handshake message
	 *
	 * (It can't be a Postgres startup length because in network byte order
	 * that would be a startup packet hundreds of megabytes long)
	 */
	log_noise("Starting TLS handshake");
	if (!sbuf_tls_accept(sbuf)) {
		disconnect_client(client, false, "failed to accept SSL");
		return;
	}
	sbuf->pkt_action = SBUF_TLS_IN_HANDSHAKE;
	if (!handle_tls_handshake(sbuf))
		sbuf_call_proto(sbuf, SBUF_EV_RECV_FAILED);
}

#else

int client_accept_sslmode = SSLMODE_DISABLED;
int server_connect_sslmode = SSLMODE_DISABLED;

bool sbuf_tls_setup(void)
{
	return true;
}
bool sbuf_tls_accept(SBuf *sbuf)
{
	return false;
}
bool sbuf_tls_connect(SBuf *sbuf, const char *hostname)
{
	return false;
}

void sbuf_cleanup(void)
{
}

static bool handle_tls_handshake(SBuf *sbuf)
{
	return false;
}

static bool handle_tls_startup(SBuf *sbuf, bool is_unix)
{
	return true;
}

#endif
