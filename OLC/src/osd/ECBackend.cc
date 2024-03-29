// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 Inktank Storage, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <iostream>
#include <sstream>
#include <fstream>

#include "ECBackend.h"
#include "messages/MOSDPGPush.h"
#include "messages/MOSDPGPushReply.h"
#include "messages/MOSDECSubOpWrite.h"
#include "messages/MOSDECSubOpWriteReply.h"
#include "messages/MOSDECSubOpRead.h"
#include "messages/MOSDECSubOpReadReply.h"
#include "ECMsgTypes.h"

#include "PrimaryLogPG.h"

#define dout_context cct
#define dout_subsys ceph_subsys_osd
#define DOUT_PREFIX_ARGS this
#undef dout_prefix
#define dout_prefix _prefix(_dout, this)
static ostream& _prefix(std::ostream *_dout, ECBackend *pgb) {
  return *_dout << pgb->get_parent()->gen_dbg_prefix();
}

struct ECRecoveryHandle : public PGBackend::RecoveryHandle {
  list<ECBackend::RecoveryOp> ops;
};

ostream &operator<<(ostream &lhs, const ECBackend::pipeline_state_t &rhs) {
  switch (rhs.pipeline_state) {
  case ECBackend::pipeline_state_t::CACHE_VALID:
    return lhs << "CACHE_VALID";
  case ECBackend::pipeline_state_t::CACHE_INVALID:
    return lhs << "CACHE_INVALID";
  default:
    assert(0 == "invalid pipeline state");
  }
  return lhs; // unreachable
}

static ostream &operator<<(ostream &lhs, const map<pg_shard_t, bufferlist> &rhs)
{
  lhs << "[";
  for (map<pg_shard_t, bufferlist>::const_iterator i = rhs.begin();
       i != rhs.end();
       ++i) {
    if (i != rhs.begin())
      lhs << ", ";
    lhs << make_pair(i->first, i->second.length());
  }
  return lhs << "]";
}

static ostream &operator<<(ostream &lhs, const map<int, bufferlist> &rhs)
{
  lhs << "[";
  for (map<int, bufferlist>::const_iterator i = rhs.begin();
       i != rhs.end();
       ++i) {
    if (i != rhs.begin())
      lhs << ", ";
    lhs << make_pair(i->first, i->second.length());
  }
  return lhs << "]";
}

static ostream &operator<<(
  ostream &lhs,
  const boost::tuple<uint64_t, uint64_t, map<pg_shard_t, bufferlist> > &rhs)
{
  return lhs << "(" << rhs.get<0>() << ", "
	     << rhs.get<1>() << ", " << rhs.get<2>() << ")";
}

ostream &operator<<(ostream &lhs, const ECBackend::read_request_t &rhs)
{
  return lhs << "read_request_t(to_read=[" << rhs.to_read << "]"
	     << ", need=" << rhs.need
	     << ", want_attrs=" << rhs.want_attrs
	     << ")";
}

ostream &operator<<(ostream &lhs, const ECBackend::read_result_t &rhs)
{
  lhs << "read_result_t(r=" << rhs.r
      << ", errors=" << rhs.errors;
  if (rhs.attrs) {
    lhs << ", attrs=" << rhs.attrs.get();
  } else {
    lhs << ", noattrs";
  }
  return lhs << ", returned=" << rhs.returned << ")";
}

ostream &operator<<(ostream &lhs, const ECBackend::ReadOp &rhs)
{
  lhs << "ReadOp(tid=" << rhs.tid;
  if (rhs.op && rhs.op->get_req()) {
    lhs << ", op=";
    rhs.op->get_req()->print(lhs);
  }
  return lhs << ", to_read=" << rhs.to_read
	     << ", complete=" << rhs.complete
	     << ", priority=" << rhs.priority
	     << ", obj_to_source=" << rhs.obj_to_source
	     << ", source_to_obj=" << rhs.source_to_obj
	     << ", in_progress=" << rhs.in_progress << ")";
}

void ECBackend::ReadOp::dump(Formatter *f) const
{
  f->dump_unsigned("tid", tid);
  if (op && op->get_req()) {
    f->dump_stream("op") << *(op->get_req());
  }
  f->dump_stream("to_read") << to_read;
  f->dump_stream("complete") << complete;
  f->dump_int("priority", priority);
  f->dump_stream("obj_to_source") << obj_to_source;
  f->dump_stream("source_to_obj") << source_to_obj;
  f->dump_stream("in_progress") << in_progress;
}

ostream &operator<<(ostream &lhs, const ECBackend::Op &rhs)
{
  lhs << "Op(" << rhs.hoid
      << " v=" << rhs.version
      << " tt=" << rhs.trim_to
      << " tid=" << rhs.tid
      << " reqid=" << rhs.reqid;
  if (rhs.client_op && rhs.client_op->get_req()) {
    lhs << " client_op=";
    rhs.client_op->get_req()->print(lhs);
  }
  lhs << " roll_forward_to=" << rhs.roll_forward_to
      << " temp_added=" << rhs.temp_added
      << " temp_cleared=" << rhs.temp_cleared
      << " pending_read=" << rhs.pending_read
      << " remote_read=" << rhs.remote_read
      << " remote_read_result=" << rhs.remote_read_result
      << " pending_apply=" << rhs.pending_apply
      << " pending_commit=" << rhs.pending_commit
      << " plan.to_read=" << rhs.plan.to_read
      << " plan.will_write=" << rhs.plan.will_write
      << ")";
  return lhs;
}

ostream &operator<<(ostream &lhs, const ECBackend::RecoveryOp &rhs)
{
  return lhs << "RecoveryOp("
	     << "hoid=" << rhs.hoid
	     << " v=" << rhs.v
	     << " missing_on=" << rhs.missing_on
	     << " missing_on_shards=" << rhs.missing_on_shards
	     << " recovery_info=" << rhs.recovery_info
	     << " recovery_progress=" << rhs.recovery_progress
	     << " obc refcount=" << rhs.obc.use_count()
	     << " state=" << ECBackend::RecoveryOp::tostr(rhs.state)
	     << " waiting_on_pushes=" << rhs.waiting_on_pushes
	     << " extent_requested=" << rhs.extent_requested
	     << ")";
}

void ECBackend::RecoveryOp::dump(Formatter *f) const
{
  f->dump_stream("hoid") << hoid;
  f->dump_stream("v") << v;
  f->dump_stream("missing_on") << missing_on;
  f->dump_stream("missing_on_shards") << missing_on_shards;
  f->dump_stream("recovery_info") << recovery_info;
  f->dump_stream("recovery_progress") << recovery_progress;
  f->dump_stream("state") << tostr(state);
  f->dump_stream("waiting_on_pushes") << waiting_on_pushes;
  f->dump_stream("extent_requested") << extent_requested;
}

ECBackend::ECBackend(
  PGBackend::Listener *pg,
  coll_t coll,
  ObjectStore::CollectionHandle &ch,
  ObjectStore *store,
  CephContext *cct,
  ErasureCodeInterfaceRef ec_impl,
  uint64_t stripe_width,
  OSDService *o)
  : PGBackend(cct, pg, store, coll, ch),
    ec_impl(ec_impl),
    sinfo(ec_impl->get_data_chunk_count(), stripe_width),
    osd(o) {
  assert((ec_impl->get_data_chunk_count() *
	  ec_impl->get_chunk_size(stripe_width)) == stripe_width);
}

PGBackend::RecoveryHandle *ECBackend::open_recovery_op()
{
  return new ECRecoveryHandle;
}

void ECBackend::_failed_push(const hobject_t &hoid,
  pair<RecoveryMessages *, ECBackend::read_result_t &> &in)
{
  ECBackend::read_result_t &res = in.second;
  dout(10) << __func__ << ": Read error " << hoid << " r="
	   << res.r << " errors=" << res.errors << dendl;
  dout(10) << __func__ << ": canceling recovery op for obj " << hoid
	   << dendl;
  assert(recovery_ops.count(hoid));
  eversion_t v = recovery_ops[hoid].v;
  recovery_ops.erase(hoid);

  list<pg_shard_t> fl;
  for (auto&& i : res.errors) {
    fl.push_back(i.first);
  }
  get_parent()->failed_push(fl, hoid);
  get_parent()->backfill_add_missing(hoid, v);
  get_parent()->finish_degraded_object(hoid);
}

struct OnRecoveryReadComplete :
  public GenContext<pair<RecoveryMessages*, ECBackend::read_result_t& > &> {
  ECBackend *pg;
  hobject_t hoid;
  set<int> want;
  OnRecoveryReadComplete(ECBackend *pg, const hobject_t &hoid)
    : pg(pg), hoid(hoid) {}
  void finish(pair<RecoveryMessages *, ECBackend::read_result_t &> &in) override {
    ECBackend::read_result_t &res = in.second;
    if (!(res.r == 0 && res.errors.empty())) {
        pg->_failed_push(hoid, in);
        return;
    }
    assert(res.returned.size() == 1);
    pg->handle_recovery_read_complete(
      hoid,
      res.returned.back(),
      res.attrs,
      in.first);
  }
};

struct RecoveryMessages {
  map<hobject_t,
      ECBackend::read_request_t> reads;
  map<hobject_t, set<int>> want_to_read;
  void read(
    ECBackend *ec,
    const hobject_t &hoid, uint64_t off, uint64_t len,
    set<int> &&_want_to_read,
    const set<pg_shard_t> &need,
    bool attrs) {
    list<boost::tuple<uint64_t, uint64_t, uint32_t> > to_read;
    to_read.push_back(boost::make_tuple(off, len, 0));
    assert(!reads.count(hoid));
    want_to_read.insert(make_pair(hoid, std::move(_want_to_read)));
    reads.insert(
      make_pair(
	hoid,
	ECBackend::read_request_t(
	  to_read,
	  need,
	  attrs,
	  new OnRecoveryReadComplete(
	    ec,
	    hoid))));
  }

  map<pg_shard_t, vector<PushOp> > pushes;
  map<pg_shard_t, vector<PushReplyOp> > push_replies;
  ObjectStore::Transaction t;
  RecoveryMessages() {}
  ~RecoveryMessages(){}
};

void ECBackend::handle_recovery_push(
  const PushOp &op,
  RecoveryMessages *m)
{
  ostringstream ss;
  if (get_parent()->check_failsafe_full(ss)) {
    dout(10) << __func__ << " Out of space (failsafe) processing push request: " << ss.str() << dendl;
    ceph_abort();
  }

  bool oneshot = op.before_progress.first && op.after_progress.data_complete;
  ghobject_t tobj;
  if (oneshot) {
    tobj = ghobject_t(op.soid, ghobject_t::NO_GEN,
		      get_parent()->whoami_shard().shard);
  } else {
    tobj = ghobject_t(get_parent()->get_temp_recovery_object(op.soid,
							     op.version),
		      ghobject_t::NO_GEN,
		      get_parent()->whoami_shard().shard);
    if (op.before_progress.first) {
      dout(10) << __func__ << ": Adding oid "
	       << tobj.hobj << " in the temp collection" << dendl;
      add_temp_obj(tobj.hobj);
    }
  }

  if (op.before_progress.first) {
    m->t.remove(coll, tobj);
    m->t.touch(coll, tobj);
  }

  if (!op.data_included.empty()) {
    uint64_t start = op.data_included.range_start();
    uint64_t end = op.data_included.range_end();
    assert(op.data.length() == (end - start));

    m->t.write(
      coll,
      tobj,
      start,
      op.data.length(),
      op.data);
  } else {
    assert(op.data.length() == 0);
  }

  if (op.before_progress.first) {
    assert(op.attrset.count(string("_")));
    m->t.setattrs(
      coll,
      tobj,
      op.attrset);
  }

  if (op.after_progress.data_complete && !oneshot) {
    dout(10) << __func__ << ": Removing oid "
	     << tobj.hobj << " from the temp collection" << dendl;
    clear_temp_obj(tobj.hobj);
    m->t.remove(coll, ghobject_t(
	op.soid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard));
    m->t.collection_move_rename(
      coll, tobj,
      coll, ghobject_t(
	op.soid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard));
  }
  if (op.after_progress.data_complete) {
    if ((get_parent()->pgb_is_primary())) {
      assert(recovery_ops.count(op.soid));
      assert(recovery_ops[op.soid].obc);
      get_parent()->on_local_recover(
	op.soid,
	op.recovery_info,
	recovery_ops[op.soid].obc,
	false,
	&m->t);
    } else {
      get_parent()->on_local_recover(
	op.soid,
	op.recovery_info,
	ObjectContextRef(),
	false,
	&m->t);
    }
  }
  m->push_replies[get_parent()->primary_shard()].push_back(PushReplyOp());
  m->push_replies[get_parent()->primary_shard()].back().soid = op.soid;
}

void ECBackend::handle_recovery_push_reply(
  const PushReplyOp &op,
  pg_shard_t from,
  RecoveryMessages *m)
{
  if (!recovery_ops.count(op.soid))
    return;
  RecoveryOp &rop = recovery_ops[op.soid];
  assert(rop.waiting_on_pushes.count(from));
  rop.waiting_on_pushes.erase(from);
  continue_recovery_op(rop, m);
}

void ECBackend::handle_recovery_read_complete(
  const hobject_t &hoid,
  boost::tuple<uint64_t, uint64_t, map<pg_shard_t, bufferlist> > &to_read,
  boost::optional<map<string, bufferlist> > attrs,
  RecoveryMessages *m)
{
  dout(10) << __func__ << ": returned " << hoid << " "
	   << "(" << to_read.get<0>()
	   << ", " << to_read.get<1>()
	   << ", " << to_read.get<2>()
	   << ")"
	   << dendl;
  assert(recovery_ops.count(hoid));
  RecoveryOp &op = recovery_ops[hoid];
  assert(op.returned_data.empty());
  map<int, bufferlist*> target;
  for (set<shard_id_t>::iterator i = op.missing_on_shards.begin();
       i != op.missing_on_shards.end();
       ++i) {
    target[*i] = &(op.returned_data[*i]);
  }
  map<int, bufferlist> from;
  for(map<pg_shard_t, bufferlist>::iterator i = to_read.get<2>().begin();
      i != to_read.get<2>().end();
      ++i) {
    from[i->first.shard].claim(i->second);
  }
  dout(10) << __func__ << ": " << from << dendl;
  int r = ECUtil::decode(sinfo, ec_impl, from, target);
  assert(r == 0);
  if (attrs) {
    op.xattrs.swap(*attrs);

    if (!op.obc) {
      // attrs only reference the origin bufferlist (decode from
      // ECSubReadReply message) whose size is much greater than attrs
      // in recovery. If obc cache it (get_obc maybe cache the attr),
      // this causes the whole origin bufferlist would not be free
      // until obc is evicted from obc cache. So rebuild the
      // bufferlist before cache it.
      for (map<string, bufferlist>::iterator it = op.xattrs.begin();
           it != op.xattrs.end();
           ++it) {
        it->second.rebuild();
      }
      // Need to remove ECUtil::get_hinfo_key() since it should not leak out
      // of the backend (see bug #12983)
      map<string, bufferlist> sanitized_attrs(op.xattrs);
      sanitized_attrs.erase(ECUtil::get_hinfo_key());
      op.obc = get_parent()->get_obc(hoid, sanitized_attrs);
      assert(op.obc);
      op.recovery_info.size = op.obc->obs.oi.size;
      op.recovery_info.oi = op.obc->obs.oi;
    }

    ECUtil::HashInfo hinfo(ec_impl->get_chunk_count());
    if (op.obc->obs.oi.size > 0) {
      assert(op.xattrs.count(ECUtil::get_hinfo_key()));
      bufferlist::iterator bp = op.xattrs[ECUtil::get_hinfo_key()].begin();
      ::decode(hinfo, bp);
    }
    op.hinfo = unstable_hashinfo_registry.lookup_or_create(hoid, hinfo);
  }
  assert(op.xattrs.size());
  assert(op.obc);
  continue_recovery_op(op, m);
}

struct SendPushReplies : public Context {
  PGBackend::Listener *l;
  epoch_t epoch;
  map<int, MOSDPGPushReply*> replies;
  SendPushReplies(
    PGBackend::Listener *l,
    epoch_t epoch,
    map<int, MOSDPGPushReply*> &in) : l(l), epoch(epoch) {
    replies.swap(in);
  }
  void finish(int) override {
    for (map<int, MOSDPGPushReply*>::iterator i = replies.begin();
	 i != replies.end();
	 ++i) {
      l->send_message_osd_cluster(i->first, i->second, epoch);
    }
    replies.clear();
  }
  ~SendPushReplies() override {
    for (map<int, MOSDPGPushReply*>::iterator i = replies.begin();
	 i != replies.end();
	 ++i) {
      i->second->put();
    }
    replies.clear();
  }
};

void ECBackend::dispatch_recovery_messages(RecoveryMessages &m, int priority)
{
  for (map<pg_shard_t, vector<PushOp> >::iterator i = m.pushes.begin();
       i != m.pushes.end();
       m.pushes.erase(i++)) {
    MOSDPGPush *msg = new MOSDPGPush();
    msg->set_priority(priority);
    msg->map_epoch = get_parent()->get_epoch();
    msg->min_epoch = get_parent()->get_last_peering_reset_epoch();
    msg->from = get_parent()->whoami_shard();
    msg->pgid = spg_t(get_parent()->get_info().pgid.pgid, i->first.shard);
    msg->pushes.swap(i->second);
    msg->compute_cost(cct);
    get_parent()->send_message(
      i->first.osd,
      msg);
  }
  map<int, MOSDPGPushReply*> replies;
  for (map<pg_shard_t, vector<PushReplyOp> >::iterator i =
	 m.push_replies.begin();
       i != m.push_replies.end();
       m.push_replies.erase(i++)) {
    MOSDPGPushReply *msg = new MOSDPGPushReply();
    msg->set_priority(priority);
    msg->map_epoch = get_parent()->get_epoch();
    msg->min_epoch = get_parent()->get_last_peering_reset_epoch();
    msg->from = get_parent()->whoami_shard();
    msg->pgid = spg_t(get_parent()->get_info().pgid.pgid, i->first.shard);
    msg->replies.swap(i->second);
    msg->compute_cost(cct);
    replies.insert(make_pair(i->first.osd, msg));
  }

  if (!replies.empty()) {
    (m.t).register_on_complete(
	get_parent()->bless_context(
	  new SendPushReplies(
	    get_parent(),
	    get_parent()->get_epoch(),
	    replies)));
    get_parent()->queue_transaction(std::move(m.t));
  } 

  if (m.reads.empty())
    return;
  start_read_op(
    priority,
    m.want_to_read,
    m.reads,
    OpRequestRef(),
    false, true);
}

void ECBackend::continue_recovery_op(
  RecoveryOp &op,
  RecoveryMessages *m)
{
  dout(10) << __func__ << ": continuing " << op << dendl;
  while (1) {
    switch (op.state) {
    case RecoveryOp::IDLE: {
      // start read
      op.state = RecoveryOp::READING;
      assert(!op.recovery_progress.data_complete);
      set<int> want(op.missing_on_shards.begin(), op.missing_on_shards.end());
      uint64_t from = op.recovery_progress.data_recovered_to;
      uint64_t amount = get_recovery_chunk_size();

      if (op.recovery_progress.first && op.obc) {
	/* We've got the attrs and the hinfo, might as well use them */
	op.hinfo = get_hash_info(op.hoid);
	assert(op.hinfo);
	op.xattrs = op.obc->attr_cache;
	::encode(*(op.hinfo), op.xattrs[ECUtil::get_hinfo_key()]);
      }

      set<pg_shard_t> to_read;
      int r = get_min_avail_to_read_shards(
	op.hoid, want, true, false, &to_read);
      if (r != 0) {
	// we must have lost a recovery source
	assert(!op.recovery_progress.first);
	dout(10) << __func__ << ": canceling recovery op for obj " << op.hoid
		 << dendl;
	get_parent()->cancel_pull(op.hoid);
	recovery_ops.erase(op.hoid);
	return;
      }
      m->read(
	this,
	op.hoid,
	op.recovery_progress.data_recovered_to,
	amount,
	std::move(want),
	to_read,
	op.recovery_progress.first && !op.obc);
      op.extent_requested = make_pair(
	from,
	amount);
      dout(10) << __func__ << ": IDLE return " << op << dendl;
      return;
    }
    case RecoveryOp::READING: {
      // read completed, start write
      assert(op.xattrs.size());
      assert(op.returned_data.size());
      op.state = RecoveryOp::WRITING;
      ObjectRecoveryProgress after_progress = op.recovery_progress;
      after_progress.data_recovered_to += op.extent_requested.second;
      after_progress.first = false;
      if (after_progress.data_recovered_to >= op.obc->obs.oi.size) {
	after_progress.data_recovered_to =
	  sinfo.logical_to_next_stripe_offset(
	    op.obc->obs.oi.size);
	after_progress.data_complete = true;
      }
      for (set<pg_shard_t>::iterator mi = op.missing_on.begin();
	   mi != op.missing_on.end();
	   ++mi) {
	assert(op.returned_data.count(mi->shard));
	m->pushes[*mi].push_back(PushOp());
	PushOp &pop = m->pushes[*mi].back();
	pop.soid = op.hoid;
	pop.version = op.v;
	pop.data = op.returned_data[mi->shard];
	dout(10) << __func__ << ": before_progress=" << op.recovery_progress
		 << ", after_progress=" << after_progress
		 << ", pop.data.length()=" << pop.data.length()
		 << ", size=" << op.obc->obs.oi.size << dendl;
	assert(
	  pop.data.length() ==
	  sinfo.aligned_logical_offset_to_chunk_offset(
	    after_progress.data_recovered_to -
	    op.recovery_progress.data_recovered_to)
	  );
	if (pop.data.length())
	  pop.data_included.insert(
	    sinfo.aligned_logical_offset_to_chunk_offset(
	      op.recovery_progress.data_recovered_to),
	    pop.data.length()
	    );
	if (op.recovery_progress.first) {
	  pop.attrset = op.xattrs;
	}
	pop.recovery_info = op.recovery_info;
	pop.before_progress = op.recovery_progress;
	pop.after_progress = after_progress;
	if (*mi != get_parent()->primary_shard())
	  get_parent()->begin_peer_recover(
	    *mi,
	    op.hoid);
      }
      op.returned_data.clear();
      op.waiting_on_pushes = op.missing_on;
      op.recovery_progress = after_progress;
      dout(10) << __func__ << ": READING return " << op << dendl;
      return;
    }
    case RecoveryOp::WRITING: {
      if (op.waiting_on_pushes.empty()) {
	if (op.recovery_progress.data_complete) {
	  op.state = RecoveryOp::COMPLETE;
	  for (set<pg_shard_t>::iterator i = op.missing_on.begin();
	       i != op.missing_on.end();
	       ++i) {
	    if (*i != get_parent()->primary_shard()) {
	      dout(10) << __func__ << ": on_peer_recover on " << *i
		       << ", obj " << op.hoid << dendl;
	      get_parent()->on_peer_recover(
		*i,
		op.hoid,
		op.recovery_info);
	    }
	  }
	  object_stat_sum_t stat;
	  stat.num_bytes_recovered = op.recovery_info.size;
	  stat.num_keys_recovered = 0; // ??? op ... omap_entries.size(); ?
	  stat.num_objects_recovered = 1;
	  get_parent()->on_global_recover(op.hoid, stat, false);
	  dout(10) << __func__ << ": WRITING return " << op << dendl;
	  recovery_ops.erase(op.hoid);
	  return;
	} else {
	  op.state = RecoveryOp::IDLE;
	  dout(10) << __func__ << ": WRITING continue " << op << dendl;
	  continue;
	}
      }
      return;
    }
    // should never be called once complete
    case RecoveryOp::COMPLETE:
    default: {
      ceph_abort();
    };
    }
  }
}

void ECBackend::run_recovery_op(
  RecoveryHandle *_h,
  int priority)
{
  ECRecoveryHandle *h = static_cast<ECRecoveryHandle*>(_h);
  RecoveryMessages m;
  for (list<RecoveryOp>::iterator i = h->ops.begin();
       i != h->ops.end();
       ++i) {
    dout(10) << __func__ << ": starting " << *i << dendl;
    assert(!recovery_ops.count(i->hoid));
    RecoveryOp &op = recovery_ops.insert(make_pair(i->hoid, *i)).first->second;
    continue_recovery_op(op, &m);
  }

  dispatch_recovery_messages(m, priority);
  send_recovery_deletes(priority, h->deletes);
  delete _h;
}

int ECBackend::recover_object(
  const hobject_t &hoid,
  eversion_t v,
  ObjectContextRef head,
  ObjectContextRef obc,
  RecoveryHandle *_h)
{
  ECRecoveryHandle *h = static_cast<ECRecoveryHandle*>(_h);
  h->ops.push_back(RecoveryOp());
  h->ops.back().v = v;
  h->ops.back().hoid = hoid;
  h->ops.back().obc = obc;
  h->ops.back().recovery_info.soid = hoid;
  h->ops.back().recovery_info.version = v;
  if (obc) {
    h->ops.back().recovery_info.size = obc->obs.oi.size;
    h->ops.back().recovery_info.oi = obc->obs.oi;
  }
  if (hoid.is_snap()) {
    if (obc) {
      assert(obc->ssc);
      h->ops.back().recovery_info.ss = obc->ssc->snapset;
    } else if (head) {
      assert(head->ssc);
      h->ops.back().recovery_info.ss = head->ssc->snapset;
    } else {
      assert(0 == "neither obc nor head set for a snap object");
    }
  }
  h->ops.back().recovery_progress.omap_complete = true;
  for (set<pg_shard_t>::const_iterator i =
	 get_parent()->get_actingbackfill_shards().begin();
       i != get_parent()->get_actingbackfill_shards().end();
       ++i) {
    dout(10) << "checking " << *i << dendl;
    if (get_parent()->get_shard_missing(*i).is_missing(hoid)) {
      h->ops.back().missing_on.insert(*i);
      h->ops.back().missing_on_shards.insert(i->shard);
    }
  }
  dout(10) << __func__ << ": built op " << h->ops.back() << dendl;
  return 0;
}

bool ECBackend::can_handle_while_inactive(
  OpRequestRef _op)
{
  return false;
}

bool ECBackend::_handle_message(
  OpRequestRef _op)
{
  dout(10) << __func__ << ": " << *_op->get_req() << dendl;
  int priority = _op->get_req()->get_priority();
  switch (_op->get_req()->get_type()) {
  case MSG_OSD_EC_WRITE: {
    // NOTE: this is non-const because handle_sub_write modifies the embedded
    // ObjectStore::Transaction in place (and then std::move's it).  It does
    // not conflict with ECSubWrite's operator<<.
    osd->osd->pending_sub_write_num--;
    osd->osd->get_logger()->set(l_osd_pending_sub_write_num,osd->osd->pending_sub_write_num);
    MOSDECSubOpWrite *op = static_cast<MOSDECSubOpWrite*>(
      _op->get_nonconst_req());
    parent->maybe_preempt_replica_scrub(op->op.soid);
    handle_sub_write(op->op.from, _op, op->op, _op->pg_trace);
    return true;
  }
  case MSG_OSD_EC_WRITE_REPLY: {
    const MOSDECSubOpWriteReply *op = static_cast<const MOSDECSubOpWriteReply*>(
      _op->get_req());
    handle_sub_write_reply(op->op.from, op->op, _op->pg_trace);
    return true;
  }
  case MSG_OSD_EC_READ: {

    osd->osd->pending_sub_read_num--;
    osd->osd->get_logger()->set(l_osd_pending_sub_read_num,osd->osd->pending_sub_read_num);
    dout(0)<<" mydebug:pending_info#"<<ceph_clock_now()<<","<<osd->osd->pending_sub_read_num<<"#"<<dendl;

    const MOSDECSubOpRead *op = static_cast<const MOSDECSubOpRead*>(_op->get_req());
    MOSDECSubOpReadReply *reply = new MOSDECSubOpReadReply;
    reply->pgid = get_parent()->primary_spg_t();
    reply->map_epoch = get_parent()->get_epoch();
    reply->min_epoch = get_parent()->get_interval_start_epoch();

    reply->op.wait_for_service_time = ceph_clock_now() - _op->get_req()->get_recv_stamp(); 
		//reply->op.queue_size = _op->get_queue_size_when_enqueued();
		reply->op.send_time = op->op.send_time;
    reply->op.queue_size = _op->read_queue_size;
    reply->op.queue_size_write = _op->write_queue_size;

    handle_sub_read(op->op.from, op->op, &(reply->op), _op->pg_trace);
    reply->trace = _op->pg_trace;
    get_parent()->send_message_osd_cluster(
      op->op.from.osd, reply, get_parent()->get_epoch());
    dout(0) << " mydebug:sub_read_op_finish" << "##" << dendl;
    return true;
  }
  case MSG_OSD_EC_READ_REPLY: {
    // NOTE: this is non-const because handle_sub_read_reply steals resulting
    // buffers.  It does not conflict with ECSubReadReply operator<<.
    MOSDECSubOpReadReply *op = static_cast<MOSDECSubOpReadReply*>(
      _op->get_nonconst_req());

    const Message* m = _op->get_req();
    utime_t p_time =  m->get_recv_stamp() - op->op.send_time;
    dout(0)<<":sub_info#"<< op->op.buffers_read.begin()->first.oid.name<<","<< op->op.from.osd<<","<<p_time<<","<<op->op.disk_read_time<<","<<op->op.queue_size<<","<<op->op.wait_for_service_time<<","<<op->op.queue_size_write<<"#"<<dendl;
    //对象名称，来自哪个osd，总的latency，磁盘时间，到达时读队列的大小，服务等待时间，到达时写队列的大小
    //<<","<<queue_size<<","<<wait_for_service_time<<","<<disk_read_time<<
    RecoveryMessages rm;
    handle_sub_read_reply(op->op.from, op->op, &rm, _op->pg_trace);
    dispatch_recovery_messages(rm, priority);
    return true;
  }
  case MSG_OSD_PG_PUSH: {
    const MOSDPGPush *op = static_cast<const MOSDPGPush *>(_op->get_req());
    RecoveryMessages rm;
    for (vector<PushOp>::const_iterator i = op->pushes.begin();
	 i != op->pushes.end();
	 ++i) {
      handle_recovery_push(*i, &rm);
    }
    dispatch_recovery_messages(rm, priority);
    return true;
  }
  case MSG_OSD_PG_PUSH_REPLY: {
    const MOSDPGPushReply *op = static_cast<const MOSDPGPushReply *>(
      _op->get_req());
    RecoveryMessages rm;
    for (vector<PushReplyOp>::const_iterator i = op->replies.begin();
	 i != op->replies.end();
	 ++i) {
      handle_recovery_push_reply(*i, op->from, &rm);
    }
    dispatch_recovery_messages(rm, priority);
    return true;
  }
  default:
    return false;
  }
  return false;
}

struct SubWriteCommitted : public Context {
  ECBackend *pg;
  OpRequestRef msg;
  ceph_tid_t tid;
  eversion_t version;
  eversion_t last_complete;
  const ZTracer::Trace trace;
  SubWriteCommitted(
    ECBackend *pg,
    OpRequestRef msg,
    ceph_tid_t tid,
    eversion_t version,
    eversion_t last_complete,
    const ZTracer::Trace &trace)
    : pg(pg), msg(msg), tid(tid),
      version(version), last_complete(last_complete), trace(trace) {}
  void finish(int) override {
    if (msg)
      msg->mark_event("sub_op_committed");
    pg->sub_write_committed(tid, version, last_complete, trace);
  }
};
void ECBackend::sub_write_committed(
  ceph_tid_t tid, eversion_t version, eversion_t last_complete,
  const ZTracer::Trace &trace) {
  if (get_parent()->pgb_is_primary()) {
    ECSubWriteReply reply;
    reply.tid = tid;
    reply.last_complete = last_complete;
    reply.committed = true;
    reply.from = get_parent()->whoami_shard();
    handle_sub_write_reply(
      get_parent()->whoami_shard(),
      reply, trace);
  } else {
    get_parent()->update_last_complete_ondisk(last_complete);
    MOSDECSubOpWriteReply *r = new MOSDECSubOpWriteReply;
    r->pgid = get_parent()->primary_spg_t();
    r->map_epoch = get_parent()->get_epoch();
    r->min_epoch = get_parent()->get_interval_start_epoch();
    r->op.tid = tid;
    r->op.last_complete = last_complete;
    r->op.committed = true;
    r->op.from = get_parent()->whoami_shard();
    r->set_priority(CEPH_MSG_PRIO_HIGH);
    r->trace = trace;
    r->trace.event("sending sub op commit");
    get_parent()->send_message_osd_cluster(
      get_parent()->primary_shard().osd, r, get_parent()->get_epoch());
  }
}

struct SubWriteApplied : public Context {
  ECBackend *pg;
  OpRequestRef msg;
  ceph_tid_t tid;
  eversion_t version;
  const ZTracer::Trace trace;
  SubWriteApplied(
    ECBackend *pg,
    OpRequestRef msg,
    ceph_tid_t tid,
    eversion_t version,
    const ZTracer::Trace &trace)
    : pg(pg), msg(msg), tid(tid), version(version), trace(trace) {}
  void finish(int) override {
    if (msg)
      msg->mark_event("sub_op_applied");
    pg->sub_write_applied(tid, version, trace);
  }
};
void ECBackend::sub_write_applied(
  ceph_tid_t tid, eversion_t version,
  const ZTracer::Trace &trace) {
  parent->op_applied(version);
  if (get_parent()->pgb_is_primary()) {
    ECSubWriteReply reply;
    reply.from = get_parent()->whoami_shard();
    reply.tid = tid;
    reply.applied = true;
    handle_sub_write_reply(
      get_parent()->whoami_shard(),
      reply, trace);
  } else {
    MOSDECSubOpWriteReply *r = new MOSDECSubOpWriteReply;
    r->pgid = get_parent()->primary_spg_t();
    r->map_epoch = get_parent()->get_epoch();
    r->min_epoch = get_parent()->get_interval_start_epoch();
    r->op.from = get_parent()->whoami_shard();
    r->op.tid = tid;
    r->op.applied = true;
    r->set_priority(CEPH_MSG_PRIO_HIGH);
    r->trace = trace;
    r->trace.event("sending sub op apply");
    get_parent()->send_message_osd_cluster(
      get_parent()->primary_shard().osd, r, get_parent()->get_epoch());
  }
}

void ECBackend::handle_sub_write(
  pg_shard_t from,
  OpRequestRef msg,
  ECSubWrite &op,
  const ZTracer::Trace &trace,
  Context *on_local_applied_sync)
{
  if (msg)
    msg->mark_started();
  trace.event("handle_sub_write");
  assert(!get_parent()->get_log().get_missing().is_missing(op.soid));
  if (!get_parent()->pgb_is_primary())
    get_parent()->update_stats(op.stats);
  ObjectStore::Transaction localt;
  if (!op.temp_added.empty()) {
    add_temp_objs(op.temp_added);
  }
  if (op.backfill) {
    for (set<hobject_t>::iterator i = op.temp_removed.begin();
	 i != op.temp_removed.end();
	 ++i) {
      dout(10) << __func__ << ": removing object " << *i
	       << " since we won't get the transaction" << dendl;
      localt.remove(
	coll,
	ghobject_t(
	  *i,
	  ghobject_t::NO_GEN,
	  get_parent()->whoami_shard().shard));
    }
  }
  clear_temp_objs(op.temp_removed);
  get_parent()->log_operation(
    op.log_entries,
    op.updated_hit_set_history,
    op.trim_to,
    op.roll_forward_to,
    !op.backfill,
    localt);

  PrimaryLogPG *_rPG = dynamic_cast<PrimaryLogPG *>(get_parent());
  if (_rPG && !_rPG->is_undersized() &&
      (unsigned)get_parent()->whoami_shard().shard >= ec_impl->get_data_chunk_count())
    op.t.set_fadvise_flag(CEPH_OSD_OP_FLAG_FADVISE_DONTNEED);

  if (on_local_applied_sync) {
    dout(10) << "Queueing onreadable_sync: " << on_local_applied_sync << dendl;
    localt.register_on_applied_sync(on_local_applied_sync);
  }
  localt.register_on_commit(
    get_parent()->bless_context(
      new SubWriteCommitted(
	this, msg, op.tid,
	op.at_version,
	get_parent()->get_info().last_complete, trace)));
  localt.register_on_applied(
    get_parent()->bless_context(
      new SubWriteApplied(this, msg, op.tid, op.at_version, trace)));
  vector<ObjectStore::Transaction> tls;
  tls.reserve(2);
  tls.push_back(std::move(op.t));
  tls.push_back(std::move(localt));

  //utime_t start_write_time = ceph_clock_now();
  get_parent()->queue_transactions(tls, msg);
  //dout(0) << "mydebug: write latency:" << ceph_clock_now()-start_write_time << dendl;
}

void ECBackend::handle_sub_read(
  pg_shard_t from,
  const ECSubRead &op,
  ECSubReadReply *reply,
  const ZTracer::Trace &trace)
{
  trace.event("handle sub read");
  shard_id_t shard = get_parent()->whoami_shard().shard;
  for(auto i = op.to_read.begin();  //to_read 是一个map，保存了每个object需要读取的偏移列表
      i != op.to_read.end();
      ++i) {
    int r = 0;
    for (auto j = i->second.begin(); j != i->second.end(); ++j) {
      bufferlist bl;
      utime_t start_read_time;
			utime_t end_read_time;
			start_read_time = ceph_clock_now();
      r = store->read(
	ch,
	ghobject_t(i->first, ghobject_t::NO_GEN, shard),
	j->get<0>(),
	j->get<1>(),
	bl, j->get<2>());
      //for balance generator
      utime_t delay_interval;
			delay_interval.tv.tv_sec = 0;
      //delay_interval.tv.tv_nsec = 40000000;
			delay_interval.tv.tv_nsec = osd->basic_delay_time * osd->delay_factor;
			utime_t delay_start_time = ceph_clock_now(); 
			while(ceph_clock_now() - delay_start_time < delay_interval); 
			utime_t delay_end_time = ceph_clock_now();
      osd->osd->disk_average_queue.add_value((delay_end_time - start_read_time).to_nsec());
      dout(0)<< ": mydebug: add_value:"<<(delay_end_time - start_read_time).to_nsec()<<dendl;
      osd->osd->get_logger()->set(l_osd_disk_read_latency,osd->osd->disk_average_queue.get_mean());
      dout(0)<< ": mydebug: set_value:"<<osd->osd->disk_average_queue.get_mean()<<dendl;
      //dout(0)<< ": mydebug: basic_delay_time="<<osd->basic_delay_time <<dendl;
      //dout(0)<< ": mydebug: delay_factor="<<osd->delay_factor <<dendl;
      //dout(0)<< ": mydebug: disk_read_time="<<delay_end_time - start_read_time <<dendl;

      if (r < 0) {
	get_parent()->clog_error() << "Error " << r
				   << " reading object "
				   << i->first;
	dout(5) << __func__ << ": Error " << r
		<< " reading " << i->first << dendl;
	goto error;
      } else {
        end_read_time = ceph_clock_now();
        reply->disk_read_time = end_read_time -start_read_time;
        dout(0)<< ": mydebug: read latency:"<<end_read_time - start_read_time <<dendl;

        dout(20) << __func__ << " read request=" << j->get<1>() << " r=" << r << " len=" << bl.length() << dendl;
	reply->buffers_read[i->first].push_back(
	  make_pair(
	    j->get<0>(),
	    bl)
	  );
      }

      if (!get_parent()->get_pool().allows_ecoverwrites()) {
	// This shows that we still need deep scrub because large enough files
	// are read in sections, so the digest check here won't be done here.
	// Do NOT check osd_read_eio_on_bad_digest here.  We need to report
	ECUtil::HashInfoRef hinfo;
	if (!get_parent()->get_pool().allows_ecoverwrites()) {
	  hinfo = get_hash_info(i->first);
	  if (!hinfo) {
	    r = -EIO;
	    get_parent()->clog_error() << "Corruption detected: object " << i->first
				       << " is missing hash_info";
	    dout(5) << __func__ << ": No hinfo for " << i->first << dendl;
	    goto error;
	  }
	}
	// the state of our chunk in case other chunks could substitute.
	assert(hinfo->has_chunk_hash());
	if ((bl.length() == hinfo->get_total_chunk_size()) &&
	    (j->get<0>() == 0)) {
	  dout(20) << __func__ << ": Checking hash of " << i->first << dendl;
	  bufferhash h(-1);
	  h << bl;
	  if (h.digest() != hinfo->get_chunk_hash(shard)) {
	    get_parent()->clog_error() << "Bad hash for " << i->first << " digest 0x"
				       << hex << h.digest() << " expected 0x" << hinfo->get_chunk_hash(shard) << dec;
	    dout(5) << __func__ << ": Bad hash for " << i->first << " digest 0x"
		    << hex << h.digest() << " expected 0x" << hinfo->get_chunk_hash(shard) << dec << dendl;
	    r = -EIO;
	    goto error;
	  }
	}
      }
    }
    continue;
error:
    // Do NOT check osd_read_eio_on_bad_digest here.  We need to report
    // the state of our chunk in case other chunks could substitute.
    reply->buffers_read.erase(i->first);
    reply->errors[i->first] = r;
  }
  for (set<hobject_t>::iterator i = op.attrs_to_read.begin();
       i != op.attrs_to_read.end();
       ++i) {
    dout(10) << __func__ << ": fulfilling attr request on "
	     << *i << dendl;
    if (reply->errors.count(*i))
      continue;
    int r = store->getattrs(
      ch,
      ghobject_t(
	*i, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
      reply->attrs_read[*i]);
    if (r < 0) {
      // If we read error, we should not return the attrs too.
      reply->attrs_read.erase(*i);
      reply->buffers_read.erase(*i);
      reply->errors[*i] = r;
    }
  }
  reply->from = get_parent()->whoami_shard();
  reply->tid = op.tid;
}

void ECBackend::handle_sub_write_reply(
  pg_shard_t from,
  const ECSubWriteReply &op,
  const ZTracer::Trace &trace)
{
  map<ceph_tid_t, Op>::iterator i = tid_to_op_map.find(op.tid);
  assert(i != tid_to_op_map.end());
  if (op.committed) {
    trace.event("sub write committed");
    assert(i->second.pending_commit.count(from));
    i->second.pending_commit.erase(from);
    if (from != get_parent()->whoami_shard()) {
      get_parent()->update_peer_last_complete_ondisk(from, op.last_complete);
    }
  }
  if (op.applied) {
    trace.event("sub write applied");
    assert(i->second.pending_apply.count(from));
    i->second.pending_apply.erase(from);
  }

  if (i->second.pending_apply.empty() && i->second.on_all_applied) {
    dout(10) << __func__ << " Calling on_all_applied on " << i->second << dendl;
    i->second.on_all_applied->complete(0);
    i->second.on_all_applied = 0;
    i->second.trace.event("ec write all applied");
  }
  if (i->second.pending_commit.empty() && i->second.on_all_commit) {
    dout(10) << __func__ << " Calling on_all_commit on " << i->second << dendl;
    i->second.on_all_commit->complete(0);
    i->second.on_all_commit = 0;
    i->second.trace.event("ec write all committed");
  }
  check_ops();
}

void ECBackend::handle_sub_read_reply(
  pg_shard_t from,
  ECSubReadReply &op,
  RecoveryMessages *m,
  const ZTracer::Trace &trace)
{
  trace.event("ec sub read reply");
  dout(10) << __func__ << ": reply " << op << dendl;
  map<ceph_tid_t, ReadOp>::iterator iter = tid_to_read_map.find(op.tid);
  if (iter == tid_to_read_map.end()) {
    //canceled
    dout(20) << __func__ << ": dropped " << op << dendl;
    return;
  }
  ReadOp &rop = iter->second;
  for (auto i = op.buffers_read.begin();
       i != op.buffers_read.end();
       ++i) {
    assert(!op.errors.count(i->first));	// If attribute error we better not have sent a buffer
    if (!rop.to_read.count(i->first)) {
      // We canceled this read! @see filter_read_op
      dout(20) << __func__ << " to_read skipping" << dendl;
      continue;
    }
    list<boost::tuple<uint64_t, uint64_t, uint32_t> >::const_iterator req_iter =
      rop.to_read.find(i->first)->second.to_read.begin();
    list<
      boost::tuple<
	uint64_t, uint64_t, map<pg_shard_t, bufferlist> > >::iterator riter =
      rop.complete[i->first].returned.begin();
    for (list<pair<uint64_t, bufferlist> >::iterator j = i->second.begin();
	 j != i->second.end();
	 ++j, ++req_iter, ++riter) {
      assert(req_iter != rop.to_read.find(i->first)->second.to_read.end());
      assert(riter != rop.complete[i->first].returned.end());
      pair<uint64_t, uint64_t> adjusted =
	sinfo.aligned_offset_len_to_chunk(
	  make_pair(req_iter->get<0>(), req_iter->get<1>()));
      assert(adjusted.first == j->first);
      riter->get<2>()[from].claim(j->second);
    }
  }
  for (auto i = op.attrs_read.begin();
       i != op.attrs_read.end();
       ++i) {
    assert(!op.errors.count(i->first));	// if read error better not have sent an attribute
    if (!rop.to_read.count(i->first)) {
      // We canceled this read! @see filter_read_op
      dout(20) << __func__ << " to_read skipping" << dendl;
      continue;
    }
    rop.complete[i->first].attrs = map<string, bufferlist>();
    (*(rop.complete[i->first].attrs)).swap(i->second);
  }
  for (auto i = op.errors.begin();
       i != op.errors.end();
       ++i) {
    rop.complete[i->first].errors.insert(
      make_pair(
	from,
	i->second));
    dout(20) << __func__ << " shard=" << from << " error=" << i->second << dendl;
  }

  map<pg_shard_t, set<ceph_tid_t> >::iterator siter =
					shard_to_read_map.find(from);
  assert(siter != shard_to_read_map.end());
  assert(siter->second.count(op.tid));
  siter->second.erase(op.tid);

  assert(rop.in_progress.count(from));
  rop.in_progress.erase(from);
  unsigned is_complete = 0;
  // For redundant reads check for completion as each shard comes in,
  // or in a non-recovery read check for completion once all the shards read.
  if (rop.do_redundant_reads || rop.in_progress.empty()) {
    for (map<hobject_t, read_result_t>::const_iterator iter =
        rop.complete.begin();
      iter != rop.complete.end();
      ++iter) {
      set<int> have;
      for (map<pg_shard_t, bufferlist>::const_iterator j =
          iter->second.returned.front().get<2>().begin();
        j != iter->second.returned.front().get<2>().end();
        ++j) {
        have.insert(j->first.shard);
        dout(20) << __func__ << " have shard=" << j->first.shard << dendl;
      }
      set<int> dummy_minimum;
      int err;
      if ((err = ec_impl->minimum_to_decode(rop.want_to_read[iter->first], have, &dummy_minimum)) < 0) {
	dout(20) << __func__ << " minimum_to_decode failed" << dendl;
        if (rop.in_progress.empty()) {
	  // If we don't have enough copies and we haven't sent reads for all shards
	  // we can send the rest of the reads, if any.
	  if (!rop.do_redundant_reads) {
	    int r = send_all_remaining_reads(iter->first, rop);
	    if (r == 0) {
	      // We added to in_progress and not incrementing is_complete
	      continue;
	    }
	    // Couldn't read any additional shards so handle as completed with errors
	  }
	  // We don't want to confuse clients / RBD with objectstore error
	  // values in particular ENOENT.  We may have different error returns
	  // from different shards, so we'll return minimum_to_decode() error
	  // (usually EIO) to reader.  It is likely an error here is due to a
	  // damaged pg.
	  rop.complete[iter->first].r = err;
	  ++is_complete;
	}
      } else {
        assert(rop.complete[iter->first].r == 0);
	if (!rop.complete[iter->first].errors.empty()) {
	  if (cct->_conf->osd_read_ec_check_for_errors) {
	    dout(10) << __func__ << ": Not ignoring errors, use one shard err=" << err << dendl;
	    err = rop.complete[iter->first].errors.begin()->second;
            rop.complete[iter->first].r = err;
	  } else {
	    get_parent()->clog_warn() << "Error(s) ignored for "
				       << iter->first << " enough copies available";
	    dout(10) << __func__ << " Error(s) ignored for " << iter->first
		     << " enough copies available" << dendl;
	    rop.complete[iter->first].errors.clear();
	  }
	}
	++is_complete;
      }
    }
  }
  if (rop.in_progress.empty() || is_complete == rop.complete.size()) {
    dout(20) << __func__ << " Complete: " << rop << dendl;
    rop.trace.event("ec read complete");
    //dout(0)<<" :obj_end#"<<op.buffers_read.begin()->first.oid.name<<","<<ceph_clock_now()<<","<<osd->whoami<<"#"<<dendl;
    complete_read_op(rop, m);
  } else {
    dout(10) << __func__ << " readop not complete: " << rop << dendl;
  }
}

void ECBackend::complete_read_op(ReadOp &rop, RecoveryMessages *m)
{
  map<hobject_t, read_request_t>::iterator reqiter =
    rop.to_read.begin();
  map<hobject_t, read_result_t>::iterator resiter =
    rop.complete.begin();
  assert(rop.to_read.size() == rop.complete.size());
  for (; reqiter != rop.to_read.end(); ++reqiter, ++resiter) {
    if (reqiter->second.cb) {
      pair<RecoveryMessages *, read_result_t &> arg(
	m, resiter->second);
      reqiter->second.cb->complete(arg);
      reqiter->second.cb = NULL;
    }
  }
  tid_to_read_map.erase(rop.tid);
}

struct FinishReadOp : public GenContext<ThreadPool::TPHandle&>  {
  ECBackend *ec;
  ceph_tid_t tid;
  FinishReadOp(ECBackend *ec, ceph_tid_t tid) : ec(ec), tid(tid) {}
  void finish(ThreadPool::TPHandle &handle) override {
    auto ropiter = ec->tid_to_read_map.find(tid);
    assert(ropiter != ec->tid_to_read_map.end());
    int priority = ropiter->second.priority;
    RecoveryMessages rm;
    ec->complete_read_op(ropiter->second, &rm);
    ec->dispatch_recovery_messages(rm, priority);
  }
};

void ECBackend::filter_read_op(
  const OSDMapRef& osdmap,
  ReadOp &op)
{
  set<hobject_t> to_cancel;
  for (map<pg_shard_t, set<hobject_t> >::iterator i = op.source_to_obj.begin();
       i != op.source_to_obj.end();
       ++i) {
    if (osdmap->is_down(i->first.osd)) {
      to_cancel.insert(i->second.begin(), i->second.end());
      op.in_progress.erase(i->first);
      continue;
    }
  }

  if (to_cancel.empty())
    return;

  for (map<pg_shard_t, set<hobject_t> >::iterator i = op.source_to_obj.begin();
       i != op.source_to_obj.end();
       ) {
    for (set<hobject_t>::iterator j = i->second.begin();
	 j != i->second.end();
	 ) {
      if (to_cancel.count(*j))
	i->second.erase(j++);
      else
	++j;
    }
    if (i->second.empty()) {
      op.source_to_obj.erase(i++);
    } else {
      assert(!osdmap->is_down(i->first.osd));
      ++i;
    }
  }

  for (set<hobject_t>::iterator i = to_cancel.begin();
       i != to_cancel.end();
       ++i) {
    get_parent()->cancel_pull(*i);

    assert(op.to_read.count(*i));
    read_request_t &req = op.to_read.find(*i)->second;
    dout(10) << __func__ << ": canceling " << req
	     << "  for obj " << *i << dendl;
    assert(req.cb);
    delete req.cb;
    req.cb = NULL;

    op.to_read.erase(*i);
    op.complete.erase(*i);
    recovery_ops.erase(*i);
  }

  if (op.in_progress.empty()) {
    get_parent()->schedule_recovery_work(
      get_parent()->bless_gencontext(
	new FinishReadOp(this, op.tid)));
  }
}

void ECBackend::check_recovery_sources(const OSDMapRef& osdmap)
{
  set<ceph_tid_t> tids_to_filter;
  for (map<pg_shard_t, set<ceph_tid_t> >::iterator 
       i = shard_to_read_map.begin();
       i != shard_to_read_map.end();
       ) {
    if (osdmap->is_down(i->first.osd)) {
      tids_to_filter.insert(i->second.begin(), i->second.end());
      shard_to_read_map.erase(i++);
    } else {
      ++i;
    }
  }
  for (set<ceph_tid_t>::iterator i = tids_to_filter.begin();
       i != tids_to_filter.end();
       ++i) {
    map<ceph_tid_t, ReadOp>::iterator j = tid_to_read_map.find(*i);
    assert(j != tid_to_read_map.end());
    filter_read_op(osdmap, j->second);
  }
}

void ECBackend::on_change()
{
  dout(10) << __func__ << dendl;

  completed_to = eversion_t();
  committed_to = eversion_t();
  pipeline_state.clear();
  waiting_reads.clear();
  waiting_state.clear();
  waiting_commit.clear();
  for (auto &&op: tid_to_op_map) {
    cache.release_write_pin(op.second.pin);
  }
  tid_to_op_map.clear();

  for (map<ceph_tid_t, ReadOp>::iterator i = tid_to_read_map.begin();
       i != tid_to_read_map.end();
       ++i) {
    dout(10) << __func__ << ": cancelling " << i->second << dendl;
    for (map<hobject_t, read_request_t>::iterator j =
	   i->second.to_read.begin();
	 j != i->second.to_read.end();
	 ++j) {
      delete j->second.cb;
      j->second.cb = 0;
    }
  }
  tid_to_read_map.clear();
  in_progress_client_reads.clear();
  shard_to_read_map.clear();
  clear_recovery_state();
}

void ECBackend::clear_recovery_state()
{
  recovery_ops.clear();
}

void ECBackend::on_flushed()
{
}

void ECBackend::dump_recovery_info(Formatter *f) const
{
  f->open_array_section("recovery_ops");
  for (map<hobject_t, RecoveryOp>::const_iterator i = recovery_ops.begin();
       i != recovery_ops.end();
       ++i) {
    f->open_object_section("op");
    i->second.dump(f);
    f->close_section();
  }
  f->close_section();
  f->open_array_section("read_ops");
  for (map<ceph_tid_t, ReadOp>::const_iterator i = tid_to_read_map.begin();
       i != tid_to_read_map.end();
       ++i) {
    f->open_object_section("read_op");
    i->second.dump(f);
    f->close_section();
  }
  f->close_section();
}

void ECBackend::submit_transaction(
  const hobject_t &hoid,
  const object_stat_sum_t &delta_stats,
  const eversion_t &at_version,
  PGTransactionUPtr &&t,
  const eversion_t &trim_to,
  const eversion_t &roll_forward_to,
  const vector<pg_log_entry_t> &log_entries,
  boost::optional<pg_hit_set_history_t> &hset_history,
  Context *on_local_applied_sync,
  Context *on_all_applied,
  Context *on_all_commit,
  ceph_tid_t tid,
  osd_reqid_t reqid,
  OpRequestRef client_op
  )
{
  assert(!tid_to_op_map.count(tid));
  Op *op = &(tid_to_op_map[tid]);
  op->hoid = hoid;
  op->delta_stats = delta_stats;
  op->version = at_version;
  op->trim_to = trim_to;
  op->roll_forward_to = MAX(roll_forward_to, committed_to);
  op->log_entries = log_entries;
  std::swap(op->updated_hit_set_history, hset_history);
  op->on_local_applied_sync = on_local_applied_sync;
  op->on_all_applied = on_all_applied;
  op->on_all_commit = on_all_commit;
  op->tid = tid;
  op->reqid = reqid;
  op->client_op = client_op;
  if (client_op)
    op->trace = client_op->pg_trace;
  
  dout(10) << __func__ << ": op " << *op << " starting" << dendl;
  start_rmw(op, std::move(t));
  dout(10) << "onreadable_sync: " << op->on_local_applied_sync << dendl;
}

void ECBackend::call_write_ordered(std::function<void(void)> &&cb) {
  if (!waiting_state.empty()) {
    waiting_state.back().on_write.emplace_back(std::move(cb));
  } else if (!waiting_reads.empty()) {
    waiting_reads.back().on_write.emplace_back(std::move(cb));
  } else {
    // Nothing earlier in the pipeline, just call it
    cb();
  }
}

void ECBackend::get_all_avail_shards(
  const hobject_t &hoid,
  const set<pg_shard_t> &error_shards,
  set<int> &have,
  map<shard_id_t, pg_shard_t> &shards,
  bool for_recovery)
{
  for (set<pg_shard_t>::const_iterator i =
	 get_parent()->get_acting_shards().begin();
       i != get_parent()->get_acting_shards().end();
       ++i) {
    dout(10) << __func__ << ": checking acting " << *i << dendl;
    const pg_missing_t &missing = get_parent()->get_shard_missing(*i);
    if (error_shards.find(*i) != error_shards.end())
      continue;
    if (!missing.is_missing(hoid)) {
      assert(!have.count(i->shard));
      have.insert(i->shard);
      assert(!shards.count(i->shard));
      shards.insert(make_pair(i->shard, *i));
    }
  }

  if (for_recovery) {
    for (set<pg_shard_t>::const_iterator i =
	   get_parent()->get_backfill_shards().begin();
	 i != get_parent()->get_backfill_shards().end();
	 ++i) {
      if (error_shards.find(*i) != error_shards.end())
	continue;
      if (have.count(i->shard)) {
	assert(shards.count(i->shard));
	continue;
      }
      dout(10) << __func__ << ": checking backfill " << *i << dendl;
      assert(!shards.count(i->shard));
      const pg_info_t &info = get_parent()->get_shard_info(*i);
      const pg_missing_t &missing = get_parent()->get_shard_missing(*i);
      if (hoid < info.last_backfill &&
	  !missing.is_missing(hoid)) {
	have.insert(i->shard);
	shards.insert(make_pair(i->shard, *i));
      }
    }

    map<hobject_t, set<pg_shard_t>>::const_iterator miter =
      get_parent()->get_missing_loc_shards().find(hoid);
    if (miter != get_parent()->get_missing_loc_shards().end()) {
      for (set<pg_shard_t>::iterator i = miter->second.begin();
	   i != miter->second.end();
	   ++i) {
	dout(10) << __func__ << ": checking missing_loc " << *i << dendl;
	auto m = get_parent()->maybe_get_shard_missing(*i);
	if (m) {
	  assert(!(*m).is_missing(hoid));
	}
	if (error_shards.find(*i) != error_shards.end())
	  continue;
	have.insert(i->shard);
	shards.insert(make_pair(i->shard, *i));
      }
    }
  }
}

bool mycmp(pair<shard_id_t,int> a, pair<shard_id_t,int> b) {
	return a.second > b.second; //降序排列，延迟大的osd放前面
}

bool mycmp3(pair<int,int> a, pair<int,int> b) {
	return a.second > b.second; //降序排列，延迟大的osd放前面
}

bool mycmp2(pair<int,float> a, pair<int,float> b) {
	return a.second < b.second; //升序排列，延迟小的osd放前面
}

void havetostr(string& res, int* have)
{
    for(int i=0;i<(EC_K+EC_M);i++){
        if(i!=(EC_K+EC_M-1)){
            string temp = to_string(have[i])+string(",");
            res += temp;
        }else{
            string temp = to_string(have[i]);
            res += temp;
        }
    }
    //cout<<"have to str:"<<res<<endl;
}

void strtohave(string& res, int* have)
{
    int pos = res.find(",");
    int pre_pos = 0;
    int i=0;
    while(i<(EC_K+EC_M)){
        have[i] = stoi(res.substr(pre_pos,(pos-pre_pos)));
        i++;
        pre_pos = pos+1;
        pos = res.find(",",pre_pos);
    }
}

int ECBackend::get_min_avail_to_read_shards(
  const hobject_t &hoid,
  const set<int> &want,
  bool for_recovery,
  bool do_redundant_reads,
  set<pg_shard_t> *to_read)
{
  // Make sure we don't do redundant reads for recovery
  assert(!for_recovery || !do_redundant_reads);

  set<int> have;
  map<shard_id_t, pg_shard_t> shards;
  set<pg_shard_t> error_shards;

  get_all_avail_shards(hoid, error_shards, have, shards, for_recovery);
  string before_str="";
  string after_str="";
  for(map<shard_id_t, pg_shard_t>::iterator i = shards.begin();i != shards.end();++i){
    before_str+=to_string(i->second.osd);
  }
  
  //dout(0) << ": mydebug: schedule_info#before,"<< hoid.oid.name << "," <<before_str<<"#"<< dendl;
  dout(0)<<" mydebug:schedule_info#"<<ceph_clock_now()<<","<<before_str<<"#"<<dendl;
  //straggler = 6 & 7
  // if(osd->cct->_conf->osd_imbalance_pattern != 0){
  //   for (map<shard_id_t, pg_shard_t>::iterator i = shards.begin();
  //     i != shards.end();
  //     ++i)
  //   {
  //     if((i->second).osd == 6 || (i->second).osd == 7){
  //       dout(0) << ": mydebug: shards "<< i->first <<" have straggler osd "<<(i->second).osd << dendl;
  //       have.erase(i->first);
  //       dout(0) << ": mydebug: erase " << i->first << " from have" << dendl;
  //     }	
  //   }
  // }else{
  //   int *load_map = [0,1,2,3,4,5,6,7];
  //   vector<pair<shard_id_t,int>> load_of_shard;
  //   for (map<shard_id_t, pg_shard_t>::iterator i = shards.begin();
  //     i != shards.end();
  //     ++i)
  //   {
  //     load_of_shard.push_back(make_pair(i->first, load_map[i->second.osd]));
  //   }
  //   sort(load_of_shard.begin(),load_of_shard.end(),mycmp);
  //   have.erase(load_of_shard[0].first);
  //   have.erase(load_of_shard[1].first);
  // }
  /****k-optimal***/
  vector<float> queue_map(NUM_OSD);

  if(osd->k_optimal){
    //vector<int> queue_map(NUM_OSD);
    int queue_map_size = 0;
    osd->osd->schedule_lock.lock();
    for(auto it : osd->osd->pending_list_size_map){ //for primitive k-optimal
      int cur_osd = it.first;
      int cur_size = it.second;
      queue_map[cur_osd] = cur_size;//+queue_map_size/8 fff
      queue_map_size++;
    }
    // if(osd->gio_reset==1){ //latest k-optimal
    //     for(int i=0;i<NUM_OSD;i++){
    //       osd->accumulate_queue_map[i] = 0;
    //     }
    //     osd->gio_reset=0;
    //     dout(0)<<" mydebug: reset gio complete"<<dendl;
    // }
    // for(int i=0;i<NUM_OSD;i++){
    //   //osd->accumulate_queue_map[i]=0;
    //   queue_map[i] = osd->accumulate_queue_map[i];
    //   queue_map_size++;
    // }
    osd->osd->schedule_lock.unlock();
    if(queue_map_size<NUM_OSD){
      dout(0)<<" mydebug: did not get complete queue_map"<<dendl;
    }
    //int load_map[] = {0,1,2,3,4,5,6,7};//primitive k-optimal
    vector<pair<shard_id_t,int>> load_of_shard;
    vector<pair<int,int>> load_of_shard2;
    for (map<shard_id_t, pg_shard_t>::iterator i = shards.begin();
      i != shards.end();
      ++i)
    {
      load_of_shard.push_back(make_pair(i->first, queue_map[i->second.osd]));
      load_of_shard2.push_back(make_pair(i->second.osd, queue_map[i->second.osd]));
    }
    sort(load_of_shard.begin(),load_of_shard.end(),mycmp);
    sort(load_of_shard2.begin(),load_of_shard2.end(),mycmp3);
    have.erase(load_of_shard[0].first);
    have.erase(load_of_shard[1].first);
    // for(int i=2;i<(EC_K+EC_M);i++){//latest k-optimal
    //   osd->accumulate_queue_map[load_of_shard2[i].first]++;
    // }
    // int queue_sum=0;
    // for(int i=0;i<NUM_OSD;i++){
    //   queue_sum+=osd->accumulate_queue_map[i];
    //   dout(0)<<"mydebug:queue_info#"<<queue_sum<<"#"<<dendl;
    // }

  }else if(osd->gio){//gio
    int my_id = get_parent()->whoami();
    string info_key = string("info")+to_string(my_id);
    string num_key = string("num")+to_string(my_id);
    string time_key = string("time")+to_string(my_id); //this is usec
    string sec_key = string("sec")+to_string(my_id);

    redisReply *reply;
    redisReply *reply2;

    //vector<int> &queue_map = osd->queue_map; //primitive gio
    //使用disk_latency_map以及pending_list_size_map来计算出新的queuemap
    /**先算(write*write/total+read)*disk***/
    /*****/
    //vector<float> queue_map(NUM_OSD);
    dout(0)<<" mydebug: in gio"<<dendl;
    int queue_map_size = 0;
    osd->osd->schedule_lock.lock();
    if(osd->cct->_conf->osd_gio_estimation==1){
      for(auto it : osd->osd->pending_list_size_map){
        int cur_osd = it.first;
        int cur_size = it.second;
        int write_size = osd->osd->pending_list_size_map_write[cur_osd];
        //dout(0)<<" mydebug: write_size="<<write_size<<dendl;
        int actual_disk_latency=0;//nsec
        if(osd->cct->_conf->osd_gio_estimation_disk==0){
          actual_disk_latency=osd->osd->disk_latency_map[cur_osd];
        }else{
          actual_disk_latency=osd->cct->_conf->osd_gio_estimation_disk;
        }
        float factor = ((float)((write_size*write_size/(write_size+cur_size+1)+cur_size)*actual_disk_latency))/1000000000;
        //dout(0)<<" mydebug: factor="<<factor<<dendl;
        //dout(0)<<" mydebug: disk latency="<<osd->osd->disk_latency_map[cur_osd]<<dendl;
        queue_map[cur_osd] = osd->cct->_conf->osd_gio_estimation_factor*factor+((float)(actual_disk_latency))/1000000000;
        queue_map_size++;
      }
    }else{
      // for(auto it : osd->osd->pending_list_size_map){ //for last gio
      //   int cur_osd = it.first;
      //   int cur_size = it.second;
      //   //int write_size = osd->osd->pending_list_size_map_write[cur_osd];
      //   //dout(0)<<" mydebug: write_size="<<write_size<<dendl;
      //   //dout(0)<<" mydebug: factor="<<factor<<dendl;
      //   //dout(0)<<" mydebug: disk latency="<<osd->osd->disk_latency_map[cur_osd]<<dendl;
      //   queue_map[cur_osd] = osd->osd->pending_list_size_map[cur_osd];
      //   queue_map_size++;
      // }
      if(osd->gio_reset==1){ //latest gio
        char ip[16];
        int port = 6379;
        redisContext *redis_context;
        redis_context = redisConnect("127.0.0.1", port);
        if (redis_context->err)    /* Error flags, 0 when there is no error */
		      dout(0)<<"mydebug: Connect local Redis server failed! Error: "<<redis_context->err<<", "<<redis_context->errstr<< dendl;
	      else{
          dout(0)<<"mydebug: Connect local Redis server successfully! I am Groot! "<< dendl;
          redisReply *reply;
          reply = (redisReply *)redisCommand(redis_context, "GET %s", "Redis Server IP");
          if(reply->len)
          strcpy(ip, reply->str);
          redisFree(redis_context);
        }
        dout(0)<<"mydebug: Redis server IP: "<< ip <<dendl;
        int osd_load_base[NUM_OSD] = {0};
        redis_context = redisConnect(ip, port);
        if (redis_context->err)
          dout(0)<<"mydebug: Connect remote Redis server failed! Error: "<<redis_context->err<<", "<<redis_context->errstr<< dendl;
        else{
          dout(0)<<"mydebug: Connect remote Redis server successfully! I am Groot! "<< dendl;
          redisReply *reply;
          string key_base = "OSD Load Base ";
          for(int i=0;i<NUM_OSD;i++){
            char id[8];
            sprintf(id, "%d", i);
            string key_id = id;
            string key_str = key_base + key_id;
            char* key = (char *)key_str.c_str();
            reply = (redisReply *)redisCommand(redis_context, "GET %s", key);
            if(reply->len)
              osd_load_base[i] = atoi(reply->str);
          }
          redisFree(redis_context);
        }

        for(int i=0;i<NUM_OSD;i++){
          osd->accumulate_queue_map[i] = osd_load_base[i];
        }
        dout(0)<<" mydebug: init osd->accumulate_queue_map complete"<<dendl;
        osd->gio_reset=0;
        dout(0)<<" mydebug: reset gio complete"<<dendl;
      }
      for(int i=0;i<NUM_OSD;i++){
        //osd->accumulate_queue_map[i]=0;
        queue_map[i] = osd->accumulate_queue_map[i];
        queue_map_size++;
      }
    }
    //根据pendinglist的情况决定time_interval的大小，
    utime_t time_out_interval;
		time_out_interval.tv.tv_sec = 0;
    time_out_interval.tv.tv_nsec = osd->cct->_conf->osd_gio_wait_interval;
    

    osd->osd->schedule_lock.unlock();
    if(queue_map_size<NUM_OSD){
      dout(0)<<" mydebug: did not get complete queue_map"<<dendl;
    }else{
      for(int i=0;i<NUM_OSD;i++){
        //dout(0)<<" queue_map["<<i<<"]="<<queue_map[i]<<dendl;
      }
    }

    redisContext *context = osd->redis_context;
    //translate to have2
    //test mac env
    int have2[EC_K+EC_M];
    int have2_pos=0;
    for (map<shard_id_t, pg_shard_t>::iterator i = shards.begin();
      i != shards.end();
      ++i)
    {
      have2[have2_pos]=i->second.osd;
      //dout(0)<<" mydebug: have2["<<have2_pos<<"]="<<have2[have2_pos]<<dendl;
      have2_pos++;
    }
    //start to handle
    int schedule_map[NUM_OSD][EC_K+EC_M];//初始化schedulemp
    for(int i=0;i<NUM_OSD;i++){
      for(int j=0;j<(EC_K+EC_M);j++){
        schedule_map[i][j]=-1;
      }   
    }
    //把自己的map给加上
    for(int i=0;i<(EC_K+EC_M);i++){
        schedule_map[my_id%osd->cct->_conf->osd_gio_coordination_granularity][i]=have2[i];
    }
    reply = (redisReply *)redisCommand(context, "exists %s", info_key.c_str());
    string info_str;
    havetostr(info_str,have2);
    //声明coor_times,先把自己的加上
    map<int,string> coor_times;
    //dout(0)<<" mydebug: infostr="<<info_str<<dendl;
    if(reply->integer == 0){//如果不存在就创建info_key和num_key
      //cout<<info_key<<" no exist!" <<endl;
      dout(0)<<" mydebug: info no exist!"<<dendl;
      // struct timeval tv;
      // struct timezone tz;
      // gettimeofday (&tv , &tz);
      utime_t pub_time = ceph_clock_now();
      //cout<<tv.tv_usec<<endl;
      reply = (redisReply *)redisCommand(context, "set %s %s", info_key.c_str(),info_str.c_str());
      //reply = (redisReply *)redisCommand(context, "set %s %d", num_key.c_str(),NUM_SCHEDULER-1);
      reply = (redisReply *)redisCommand(context, "set %s %d", num_key.c_str(),0);
      reply = (redisReply *)redisCommand(context, "set %s %d", time_key.c_str(),pub_time.usec());
      reply = (redisReply *)redisCommand(context, "set %s %d", sec_key.c_str(),pub_time.sec());
      //dout(0)<<"set sec_key ="<<pub_time.sec()<<dendl;
      //dout(0)<<"set res = "<<reply->str<<dendl;//hhaa
      //reply = (redisReply *)redisCommand(context, "get %s", sec_key.c_str());
      //dout(0)<<"get sec_key ="<<stoi(string(reply->str))<<dendl;
      coor_times[my_id] = to_string(pub_time.sec())+to_string(pub_time.usec());
      dout(0)<<"set coor_times of myid:"<<coor_times[my_id]<<dendl;
    }else{
      //dout(0)<<" mydebug: info exist!"<<dendl;
			utime_t start_time = ceph_clock_now();
      int first_check=1; 
      while(1){ //如果存在就等待拿的是不是差不多了
        reply = (redisReply *)redisCommand(context, "get %s", num_key.c_str());
        if(stoi(string(reply->str)) >= (osd->cct->_conf->osd_gio_coordination_granularity-1)){
          //当全部取完时，可以退出
          //cout<<info_key<<" has been consumed, start next!"<<endl;
          if(first_check){
            //dout(0)<<"consumed first_check"<<dendl;
          }else{
            //dout(0)<<"consumed other_check"<<dendl;
            //dout(0)<<info_key<<" pub wait for  "<<ceph_clock_now()-start_time<<dendl;
          }
          //dout(0)<<" mydebug:coor_info#"<<stoi(string(reply->str))<<"#"<<dendl;
          break;
        }
        first_check=0;       
        utime_t cur_time = ceph_clock_now();
        if((cur_time-start_time)>time_out_interval){
          //cout<<info_key<<" time_out, start next!"<<endl;
          //dout(0)<<info_key<<" time_out, start next!, consumed by "<<stoi(string(reply->str))<<dendl;
          //dout(0)<<" mydebug:coor_info#"<<stoi(string(reply->str))<<"#"<<dendl;
          break;
        }
      }
            
      // struct timeval tv;
      // struct timezone tz;
      // gettimeofday (&tv , &tz);
      utime_t pub_time = ceph_clock_now();
      //cout<<"new time_stamp"<<tv.tv_sec<<"."<<tv.tv_usec<<endl;
      utime_t start_set = ceph_clock_now();
      reply = (redisReply *)redisCommand(context, "set %s %s", info_key.c_str(),info_str.c_str());
      //reply = (redisReply *)redisCommand(context, "set %s %d", num_key.c_str(),NUM_SCHEDULER-1);
      reply = (redisReply *)redisCommand(context, "set %s %d", num_key.c_str(),0);
      reply = (redisReply *)redisCommand(context, "set %s %d", time_key.c_str(),pub_time.usec());
      reply = (redisReply *)redisCommand(context, "set %s %d", sec_key.c_str(),pub_time.sec());
      //dout(0)<<"redis_info#set_latency,"<<(ceph_clock_now()-start_set)/4*1000000<<"#"<<dendl;
      //dout(0)<<"set sec_key ="<<pub_time.sec()<<dendl;
      //dout(0)<<"set res = "<<reply->str<<dendl;//hhaa
      reply = (redisReply *)redisCommand(context, "get %s", sec_key.c_str());
      //dout(0)<<"get sec_key ="<<stoi(string(reply->str))<<dendl;
      coor_times[my_id] = to_string(pub_time.sec())+to_string(pub_time.usec());
      //dout(0)<<"set coor_times of myid:"<<coor_times[my_id]<<dendl;
    }
    
    utime_t start_rpush = ceph_clock_now();
    //reply = (redisReply *)redisCommand(context, "RPUSH testlist testtest");
    dout(0)<<"redis_info#rpush_latency,"<<(ceph_clock_now()-start_rpush)*1000000<<"#"<<dendl;
    utime_t start_lpop = ceph_clock_now();
    reply = (redisReply *)redisCommand(context, "LPOP testlist ");
    dout(0)<<"redis_info#lpop_latency,"<<(ceph_clock_now()-start_lpop)*1000000<<"#"<<dendl;
    //开始获取别的osd的obj
    int num_got = 0;
    //循环遍历其他osd
    int i=0;//i为当前遍历的osd编号在当前region的偏移
    vector<int> have_got(osd->cct->_conf->osd_gio_coordination_granularity,0);
    for(int j=0;j<osd->cct->_conf->osd_gio_coordination_granularity;j++){
      have_got[j]=0;
    }
    ////hahahaha
		utime_t start_time = ceph_clock_now();
    //cout<<"start_time="<<start_time<<endl;
    int region_id = my_id / osd->cct->_conf->osd_gio_coordination_granularity;
    

    while(1){
      if(i==(my_id%osd->cct->_conf->osd_gio_coordination_granularity) || have_got[i]){//跳过自己id的偏移以及已经获得的id
        //dout(0)<<"skip "<<i<<"!"<<dendl;
        i++;
        i%=osd->cct->_conf->osd_gio_coordination_granularity;
        continue;
      }
      int actual_id=i+region_id*osd->cct->_conf->osd_gio_coordination_granularity;
      //dout(0)<<"check "<<actual_id<<"..."<<dendl;
      string target_key = string("info")+to_string(actual_id);
      string target_num = string("num")+to_string(actual_id);
      string target_time = string("time")+to_string(actual_id);
      string target_sec = string("sec")+to_string(actual_id);
      //cout<<"target_key="<<target_key<<endl;
      utime_t start_exist = ceph_clock_now();
      reply = (redisReply *)redisCommand(context, "exists %s", target_time.c_str());
      reply2 = (redisReply *)redisCommand(context, "exists %s", target_sec.c_str());
      //dout(0)<<"redis_info#exist_latency,"<<(ceph_clock_now()-start_exist)/2*1000000<<"#"<<dendl;
      if(reply->integer == 0 || reply2->integer ==0){//如果target_time不存在就跳到后面判断是否结束
        dout(0)<<target_time<<" no exists!"<<dendl;
        goto end;
      }else{
        //cout<<target_time<<" exists!"<<endl;
        //time存在了就获得time
        reply = (redisReply *)redisCommand(context, "get %s", target_time.c_str());      
        string temp_time = reply->str;
        if(temp_time==osd->last_time[actual_id]){//如果还是之前的时间戳，就继续看下一个
          goto end;
        }
        reply = (redisReply *)redisCommand(context, "get %s", target_sec.c_str());      
        string sec_time = reply->str;
        if((start_time.sec()-stoi(sec_time))>3){//如果时间戳太旧了，就下一个
          //dout(0)<<"start_time.sec()="<<start_time.sec()<<", sec_time="<<stoi(sec_time)<<", deviation="<<start_time.sec()-stoi(sec_time)<<dendl;
          //dout(0)<<target_key<<" is too old"<<dendl;
          goto end;
        }
        //如果obj信息合适
        //cout<<"get proper "<<target_key<<endl;
        //dout(0)<<"get proper "<<target_key<<dendl;
        osd->last_time[actual_id] = temp_time;
        utime_t start_get = ceph_clock_now();
        reply = (redisReply *)redisCommand(context, "get %s", target_key.c_str());
        //dout(0)<<"redis_info#get_latency,"<<(ceph_clock_now()-start_get)*1000000<<"#"<<dendl;
        //cout<<reply->type<<endl;
        int temp_have[EC_K+EC_M];
        if(reply->str==NULL){
          //cout<<target_key<<" has beed deleted!"<<endl;
        }
        string temp_str = reply->str;

        //将目标obj的引用次数加一
        //reply = (redisReply *)redisCommand(context, "decr %s", target_num.c_str());
        utime_t start_incr = ceph_clock_now();
        reply = (redisReply *)redisCommand(context, "incr %s", target_num.c_str());
        //dout(0)<<"redis_info#incr_latency,"<<(ceph_clock_now()-start_incr)*1000000<<"#"<<dendl;
        strtohave(temp_str,temp_have);//读出的信息存放在temp_have中，
        // for(int i=0;i<(EC_K+EC_M);i++){
        //     cout<<"strtohave:"<<temp_have[i]<<endl;
        // }
        //将have插入到schedule_map中
        for(int j=0;j<(EC_K+EC_M);j++){
          schedule_map[i][j] = temp_have[j];
        }
        //将需要协调的对象的时间给保存下来
        coor_times[actual_id] = sec_time+temp_time;
        //获得的加1
        num_got++;
        have_got[i]=1;
      }
    end:            
      if(num_got>=(osd->cct->_conf->osd_gio_coordination_granularity-1)){//首先保证至少获得这么多 
        //dout(0)<<"have got all: "<<osd->cct->_conf->osd_gio_coordination_granularity-1<<dendl;
        //dout(0)<<"gather wait for"<<ceph_clock_now()-start_time<<dendl;
        //dout(0)<<" mydebug:coor_info#"<<num_got<<"#"<<dendl;
        break;
        //如果全部拿到了，就退出                   
      }
      utime_t cur_time = ceph_clock_now();
      if((cur_time-start_time)>time_out_interval){//如果实在等不到了，也推出
        //dout(0)<<"dont wait anymore, have got "<<num_got<<dendl;
        //dout(0)<<" mydebug:coor_info#"<<num_got<<"#"<<dendl;
        break;
      }
      i++;
      i%=osd->cct->_conf->osd_gio_coordination_granularity;
    }
    //已经获得到了schedule map，进行调度
    osd->osd->schedule_lock.lock();
    for(int i =0;i<osd->cct->_conf->osd_gio_coordination_granularity;i++){
      if(schedule_map[i][0]==-1){
        continue;//跳过没有收到信息的osd
      }
      //先查看是否已经存在这个结果了
      string coor_res = to_string(i)+coor_times[i];
      reply = (redisReply *)redisCommand(context, "exists %s", coor_res.c_str());
      int processed = 0;
      string res_string;
      if(reply->integer == 0){//如果不存在，就正常操作
        dout(0)<<i<<" not processed!"<<dendl;
      }else{ //如果存在，就把他取出来
        reply2 = (redisReply *)redisCommand(context, "get %s", coor_res.c_str());
        processed=1; //need change to 1
        res_string = reply2->str;
        dout(0)<<i<<" processed! res="<<res_string<<dendl;
      }
      
      if(processed==0){//如果还没被处理过
      //调度就是选最少的四个
        vector<pair<int,float>> load_of_shard;
        for(int j=0;j<(EC_K+EC_M);j++){
          load_of_shard.push_back(make_pair(schedule_map[i][j], queue_map[schedule_map[i][j]]));
        }
        sort(load_of_shard.begin(),load_of_shard.end(),mycmp2);
        res_string="";
        for(int j=0;j<EC_K;j++){//调度最小的k个
            //queue_map[load_of_shard[j].first]++;//for primitive gio
            //osd->osd->pending_list_size_map[load_of_shard[j].first]++;//for last gio
            osd->accumulate_queue_map[load_of_shard[j].first]++; //latest gio
            res_string+=to_string(load_of_shard[j].first);
        }
        for(int j=0;j<NUM_OSD;j++){
          dout(0)<<"mydebug: osd->accumulate_queue_map["<<j<<"]="<<osd->accumulate_queue_map[j]<<dendl;
        }
        //更新redis中的值，使用setnx保证唯一
        dout(0)<<"mydebug: after schedule, res="<<res_string<<dendl;
        utime_t start_setnx = ceph_clock_now();
        reply = (redisReply *)redisCommand(context, "setnx %s %s", coor_res.c_str(),res_string.c_str());
        //dout(0)<<"redis_info#setnx_latency,"<<(ceph_clock_now()-start_setnx)*1000000<<"#"<<dendl;
        //dout(0)<<i<<" replyres: "<<reply->type<<" "<<reply->integer<<dendl;
        if(reply->integer==0){
          dout(0)<<i<<" conflict!"<<dendl;
        }else{
          //dout(0)<<i<<" set res success!"<<dendl;
        }
        //更新queue_map
        if(osd->cct->_conf->osd_gio_estimation==1){
          for(auto it : osd->osd->pending_list_size_map){
            int cur_osd = it.first;
            int cur_size = it.second;
            int write_size = osd->osd->pending_list_size_map_write[cur_osd];
            //dout(0)<<" mydebug: write_size="<<write_size<<dendl;
            int actual_disk_latency=0;//nsec
            if(osd->cct->_conf->osd_gio_estimation_disk==0){
              actual_disk_latency=osd->osd->disk_latency_map[cur_osd];
            }else{
              actual_disk_latency=osd->cct->_conf->osd_gio_estimation_disk;
            }
            float factor = ((float)((write_size*write_size/(write_size+cur_size+1)+cur_size)*actual_disk_latency))/1000000000;
            //dout(0)<<" mydebug: factor="<<factor<<dendl;
            //dout(0)<<" mydebug: disk latency="<<osd->osd->disk_latency_map[cur_osd]<<dendl;
            queue_map[cur_osd] = osd->cct->_conf->osd_gio_estimation_factor*factor+((float)(actual_disk_latency))/1000000000;
            //queue_map_size++;
          }
        }else{
          // for(auto it : osd->osd->pending_list_size_map){ //for last gio
          //   int cur_osd = it.first;
          //   int cur_size = it.second;
          //   //int write_size = osd->osd->pending_list_size_map_write[cur_osd];
          //   //dout(0)<<" mydebug: write_size="<<write_size<<dendl;
          //   //dout(0)<<" mydebug: factor="<<factor<<dendl;
          //   //dout(0)<<" mydebug: disk latency="<<osd->osd->disk_latency_map[cur_osd]<<dendl;
          //   queue_map[cur_osd] = osd->osd->pending_list_size_map[cur_osd];
          //   //queue_map_size++;
          // }
          // for(int i=0;i<NUM_OSD;i++){ // for latest gio
          //   queue_map[i] = osd->accumulate_queue_map[i];
          //   dout(0)<<"mydebug:queue_info#"<<osd->accumulate_queue_map[i]<<"#"<<dendl;
          // }
        }
        if(i==(my_id%osd->cct->_conf->osd_gio_coordination_granularity)){//根据调度把自己的have给去了
          //需要定时删除掉自己之前的调度结果,如果是自己的话，就把当前的coor_res给放到队列里面去
          osd->trash_queue.push(coor_res);
          if(osd->trash_queue.size()>20){
            string to_delete = osd->trash_queue.front();
            osd->trash_queue.pop();
            utime_t start_del = ceph_clock_now();
            reply = (redisReply *)redisCommand(context, "del %s", to_delete.c_str());
            //dout(0)<<"redis_info#del_latency,"<<(ceph_clock_now()-start_del)*1000000<<"#"<<dendl;
          }
          //
          for(int j=EC_K;j<(EC_K+EC_M);j++){
            int temp_osd_id = load_of_shard[j].first;//不应该读这个osd
            int k;//相应osd所对应的shardid
            for(k=0;k<(EC_K+EC_M);k++){
              if(have2[k]==temp_osd_id){
                break;
              }
            }
            have.erase(k);
            //dout(0)<<"have.erase "<<k<<dendl;
          }
        }
      }else{//processed==1,如果之前有结果，就直接使用之前的结果，当节点数量上升时需要改变resstring的定义
        dout(0)<<i<<" mydebug: res_string= "<<res_string<<dendl;
        vector<int> temp_res_vec;
        for(int j=0;j<EC_K;j++){
          int temp_int = res_string[j]-'0'; //todo
          temp_res_vec.push_back(temp_int);
          //queue_map[temp_int]++; //for pritimitive gio
          //更新queuemap
          osd->accumulate_queue_map[temp_int]++; //for latest gio
          for(int i=0;i<NUM_OSD;i++){ //for latest gio
            queue_map[i] = osd->accumulate_queue_map[i];
            //dout(0)<<"mydebug:queue_info#"<<osd->accumulate_queue_map[i]<<"#"<<dendl;
          }
        }

        if(i==(my_id%osd->cct->_conf->osd_gio_coordination_granularity)){//根据调度把自己的have给去了
          //需要定时删除掉自己之前的调度结果,如果是自己的话，就把当前的coor_res给放到队列里面去
          osd->trash_queue.push(coor_res);
          if(osd->trash_queue.size()>20){
            string to_delete = osd->trash_queue.front();
            osd->trash_queue.pop();
            reply = (redisReply *)redisCommand(context, "del %s", to_delete.c_str());
          }
          //
          for(int j=0;j<(EC_K+EC_M);j++){
            int find=0;
            for(int k=0;k<EC_K;k++){
              if(temp_res_vec[k]==have2[j]){
                find=1;
                break;
              }
            }
            if(find==0){
               have.erase(j);
               dout(0)<<"have.erase "<<j<<dendl;
            }             
          }
        }
      }
    }
    int queue_sum=0;
    for(int i=0;i<NUM_OSD;i++){
      queue_sum+=osd->accumulate_queue_map[i];
      dout(0)<<"mydebug:queue_info#"<<queue_sum<<"#"<<dendl;
    }
    //dout(0)<<" mydebug:after_schedule:"<<queue_map<<dendl;
    osd->osd->schedule_lock.unlock();

  }else{
    ;
  }
  /****k-optimal***/




  set<int> need;
  int r = ec_impl->minimum_to_decode(want, have, &need);
  if (r < 0)
    return r;

  
  if (do_redundant_reads) {
      need.swap(have);
  } 

  if (!to_read)
    return 0;

  //dout(0) << ": mydebug: schedule_info#need,"<<need<<"#"<< dendl;
  //dout(0) << ": mydebug: schedule_info#do_redundant_reads,"<<do_redundant_reads<<"#"<< dendl;

  for (set<int>::iterator i = need.begin();
       i != need.end();
       ++i) {
    assert(shards.count(shard_id_t(*i)));
    to_read->insert(shards[shard_id_t(*i)]);
  }
  
  for(set<pg_shard_t>::iterator i = to_read->begin();i!=to_read->end();i++){
    after_str+=to_string(i->osd);
    //dout(0)<<":sub_info#estimated,"<< hoid.oid.name<<","<<i->osd<<","<<queue_map[i->osd]<<"#"<<dendl;
  }

  //dout(0) << ": mydebug: schedule_info#after,"<< hoid.oid.name << "," <<after_str<<","<<ceph_clock_now()<<"#"<< dendl;

  return 0;
}

int ECBackend::get_remaining_shards(
  const hobject_t &hoid,
  const set<int> &avail,
  const set<int> &want,
  const read_result_t &result,
  set<pg_shard_t> *to_read,
  bool for_recovery)
{
  assert(to_read);

  set<int> have;
  map<shard_id_t, pg_shard_t> shards;
  set<pg_shard_t> error_shards;
  for (auto &p : result.errors) {
    error_shards.insert(p.first);
  }

  get_all_avail_shards(hoid, error_shards, have, shards, for_recovery);

  set<int> need;
  int r = ec_impl->minimum_to_decode(want, have, &need);
  if (r < 0) {
    dout(0) << __func__ << " not enough shards left to try for " << hoid
	    << " read result was " << result << dendl;
    return -EIO;
  }

  set<int> shards_left;
  for (auto p : need) {
    if (avail.find(p) == avail.end()) {
      shards_left.insert(p);
    }
  }

  for (set<int>::iterator i = shards_left.begin();
       i != shards_left.end();
       ++i) {
    assert(shards.count(shard_id_t(*i)));
    assert(avail.find(*i) == avail.end());
    to_read->insert(shards[shard_id_t(*i)]);
  }
  return 0;
}

void ECBackend::start_read_op(
  int priority,
  map<hobject_t, set<int>> &want_to_read,
  map<hobject_t, read_request_t> &to_read,
  OpRequestRef _op,
  bool do_redundant_reads,
  bool for_recovery)
{
  ceph_tid_t tid = get_parent()->get_tid();
  assert(!tid_to_read_map.count(tid));
  auto &op = tid_to_read_map.emplace(
    tid,
    ReadOp(
      priority,
      tid,
      do_redundant_reads,
      for_recovery,
      _op,
      std::move(want_to_read),
      std::move(to_read))).first->second;
  dout(10) << __func__ << ": starting " << op << dendl;
  if (_op) {
    op.trace = _op->pg_trace;
    op.trace.event("start ec read");
  }
  do_read_op(op);
}

void ECBackend::do_read_op(ReadOp &op)
{
  int priority = op.priority;
  ceph_tid_t tid = op.tid;

  dout(10) << __func__ << ": starting read " << op << dendl;

  map<pg_shard_t, ECSubRead> messages;
  for (map<hobject_t, read_request_t>::iterator i = op.to_read.begin();
       i != op.to_read.end();
       ++i) {
    bool need_attrs = i->second.want_attrs;
    for (set<pg_shard_t>::const_iterator j = i->second.need.begin();
	 j != i->second.need.end();
	 ++j) {
      if (need_attrs) {
	messages[*j].attrs_to_read.insert(i->first);
	need_attrs = false;
      }
      op.obj_to_source[i->first].insert(*j);
      op.source_to_obj[*j].insert(i->first);
    }
    for (list<boost::tuple<uint64_t, uint64_t, uint32_t> >::const_iterator j =
	   i->second.to_read.begin();
	 j != i->second.to_read.end();
	 ++j) {
      pair<uint64_t, uint64_t> chunk_off_len =
	sinfo.aligned_offset_len_to_chunk(make_pair(j->get<0>(), j->get<1>()));
      for (set<pg_shard_t>::const_iterator k = i->second.need.begin();
	   k != i->second.need.end();
	   ++k) {
	messages[*k].to_read[i->first].push_back(
	  boost::make_tuple(
	    chunk_off_len.first,
	    chunk_off_len.second,
	    j->get<2>()));
      }
      assert(!need_attrs);
    }
  }

  for (map<pg_shard_t, ECSubRead>::iterator i = messages.begin();
       i != messages.end();
       ++i) {
    op.in_progress.insert(i->first);
    shard_to_read_map[i->first].insert(op.tid);
    i->second.tid = tid;
    MOSDECSubOpRead *msg = new MOSDECSubOpRead;
    msg->set_priority(priority);
    msg->pgid = spg_t(
      get_parent()->whoami_spg_t().pgid,
      i->first.shard);
    msg->map_epoch = get_parent()->get_epoch();
    msg->min_epoch = get_parent()->get_interval_start_epoch();
    msg->op = i->second;
    msg->op.from = get_parent()->whoami_shard();
    msg->op.tid = tid;
    if (op.trace) {
      // initialize a child span for this shard
      msg->trace.init("ec sub read", nullptr, &op.trace);
      msg->trace.keyval("shard", i->first.shard.id);
    }
    msg->op.send_time = ceph_clock_now();
    get_parent()->send_message_osd_cluster(
      i->first.osd,
      msg,
      get_parent()->get_epoch());
  }
  dout(10) << __func__ << ": started " << op << dendl;
}

ECUtil::HashInfoRef ECBackend::get_hash_info(
  const hobject_t &hoid, bool checks, const map<string,bufferptr> *attrs)
{
  dout(10) << __func__ << ": Getting attr on " << hoid << dendl;
  ECUtil::HashInfoRef ref = unstable_hashinfo_registry.lookup(hoid);
  if (!ref) {
    dout(10) << __func__ << ": not in cache " << hoid << dendl;
    struct stat st;
    int r = store->stat(
      ch,
      ghobject_t(hoid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
      &st);
    ECUtil::HashInfo hinfo(ec_impl->get_chunk_count());
    // XXX: What does it mean if there is no object on disk?
    if (r >= 0) {
      dout(10) << __func__ << ": found on disk, size " << st.st_size << dendl;
      bufferlist bl;
      if (attrs) {
	map<string, bufferptr>::const_iterator k = attrs->find(ECUtil::get_hinfo_key());
	if (k == attrs->end()) {
	  dout(5) << __func__ << " " << hoid << " missing hinfo attr" << dendl;
	} else {
	  bl.push_back(k->second);
	}
      } else {
	r = store->getattr(
	  ch,
	  ghobject_t(hoid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
	  ECUtil::get_hinfo_key(),
	  bl);
	if (r < 0) {
	  dout(5) << __func__ << ": getattr failed: " << cpp_strerror(r) << dendl;
	  bl.clear(); // just in case
	}
      }
      if (bl.length() > 0) {
	bufferlist::iterator bp = bl.begin();
        try {
	  ::decode(hinfo, bp);
        } catch(...) {
	  dout(0) << __func__ << ": Can't decode hinfo for " << hoid << dendl;
	  return ECUtil::HashInfoRef();
        }
	if (checks && hinfo.get_total_chunk_size() != (uint64_t)st.st_size) {
	  dout(0) << __func__ << ": Mismatch of total_chunk_size "
			       << hinfo.get_total_chunk_size() << dendl;
	  return ECUtil::HashInfoRef();
	}
      } else if (st.st_size > 0) { // If empty object and no hinfo, create it
	return ECUtil::HashInfoRef();
      }
    }
    ref = unstable_hashinfo_registry.lookup_or_create(hoid, hinfo);
  }
  return ref;
}

void ECBackend::start_rmw(Op *op, PGTransactionUPtr &&t)
{
  assert(op);

  op->plan = ECTransaction::get_write_plan(
    sinfo,
    std::move(t),
    [&](const hobject_t &i) {
      ECUtil::HashInfoRef ref = get_hash_info(i, false);
      if (!ref) {
	derr << __func__ << ": get_hash_info(" << i << ")"
	     << " returned a null pointer and there is no "
	     << " way to recover from such an error in this "
	     << " context" << dendl;
	ceph_abort();
      }
      return ref;
    },
    get_parent()->get_dpp());

  dout(10) << __func__ << ": " << *op << dendl;

  waiting_state.push_back(*op);
  check_ops();
}

bool ECBackend::try_state_to_reads()
{
  if (waiting_state.empty())
    return false;

  Op *op = &(waiting_state.front());
  if (op->requires_rmw() && pipeline_state.cache_invalid()) {
    assert(get_parent()->get_pool().allows_ecoverwrites());
    dout(20) << __func__ << ": blocking " << *op
	     << " because it requires an rmw and the cache is invalid "
	     << pipeline_state
	     << dendl;
    return false;
  }

  op->using_cache = pipeline_state.caching_enabled();

  if (op->invalidates_cache()) {
    dout(20) << __func__ << ": invalidating cache after this op"
	     << dendl;
    pipeline_state.invalidate();
  }

  waiting_state.pop_front();
  waiting_reads.push_back(*op);

  if (op->using_cache) {
    cache.open_write_pin(op->pin);

    extent_set empty;
    for (auto &&hpair: op->plan.will_write) {
      auto to_read_plan_iter = op->plan.to_read.find(hpair.first);
      const extent_set &to_read_plan =
	to_read_plan_iter == op->plan.to_read.end() ?
	empty :
	to_read_plan_iter->second;

      extent_set remote_read = cache.reserve_extents_for_rmw(
	hpair.first,
	op->pin,
	hpair.second,
	to_read_plan);

      extent_set pending_read = to_read_plan;
      pending_read.subtract(remote_read);

      if (!remote_read.empty()) {
	op->remote_read[hpair.first] = std::move(remote_read);
      }
      if (!pending_read.empty()) {
	op->pending_read[hpair.first] = std::move(pending_read);
      }
    }
  } else {
    op->remote_read = op->plan.to_read;
  }

  dout(10) << __func__ << ": " << *op << dendl;

  if (!op->remote_read.empty()) {
    assert(get_parent()->get_pool().allows_ecoverwrites());
    objects_read_async_no_cache(
      op->remote_read,
      [this, op](map<hobject_t,pair<int, extent_map> > &&results) {
	for (auto &&i: results) {
	  op->remote_read_result.emplace(i.first, i.second.second);
	}
	check_ops();
      });
  }

  return true;
}

bool ECBackend::try_reads_to_commit()
{
  if (waiting_reads.empty())
    return false;
  Op *op = &(waiting_reads.front());
  if (op->read_in_progress())
    return false;
  waiting_reads.pop_front();
  waiting_commit.push_back(*op);

  dout(10) << __func__ << ": starting commit on " << *op << dendl;
  dout(20) << __func__ << ": " << cache << dendl;

  get_parent()->apply_stats(
    op->hoid,
    op->delta_stats);

  if (op->using_cache) {
    for (auto &&hpair: op->pending_read) {
      op->remote_read_result[hpair.first].insert(
	cache.get_remaining_extents_for_rmw(
	  hpair.first,
	  op->pin,
	  hpair.second));
    }
    op->pending_read.clear();
  } else {
    assert(op->pending_read.empty());
  }

  map<shard_id_t, ObjectStore::Transaction> trans;
  for (set<pg_shard_t>::const_iterator i =
	 get_parent()->get_actingbackfill_shards().begin();
       i != get_parent()->get_actingbackfill_shards().end();
       ++i) {
    trans[i->shard];
  }

  op->trace.event("start ec write");

  map<hobject_t,extent_map> written;
  if (op->plan.t) {
    ECTransaction::generate_transactions(
      op->plan,
      ec_impl,
      get_parent()->get_info().pgid.pgid,
      (get_osdmap()->require_osd_release < CEPH_RELEASE_KRAKEN),
      sinfo,
      op->remote_read_result,
      op->log_entries,
      &written,
      &trans,
      &(op->temp_added),
      &(op->temp_cleared),
      get_parent()->get_dpp());
  }

  dout(20) << __func__ << ": " << cache << dendl;
  dout(20) << __func__ << ": written: " << written << dendl;
  dout(20) << __func__ << ": op: " << *op << dendl;

  if (!get_parent()->get_pool().allows_ecoverwrites()) {
    for (auto &&i: op->log_entries) {
      if (i.requires_kraken()) {
	derr << __func__ << ": log entry " << i << " requires kraken"
	     << " but overwrites are not enabled!" << dendl;
	ceph_abort();
      }
    }
  }

  map<hobject_t,extent_set> written_set;
  for (auto &&i: written) {
    written_set[i.first] = i.second.get_interval_set();
  }
  dout(20) << __func__ << ": written_set: " << written_set << dendl;
  assert(written_set == op->plan.will_write);

  if (op->using_cache) {
    for (auto &&hpair: written) {
      dout(20) << __func__ << ": " << hpair << dendl;
      cache.present_rmw_update(hpair.first, op->pin, hpair.second);
    }
  }
  op->remote_read.clear();
  op->remote_read_result.clear();

  dout(10) << "onreadable_sync: " << op->on_local_applied_sync << dendl;
  ObjectStore::Transaction empty;
  bool should_write_local = false;
  ECSubWrite local_write_op;
  for (set<pg_shard_t>::const_iterator i =
	 get_parent()->get_actingbackfill_shards().begin();
       i != get_parent()->get_actingbackfill_shards().end();
       ++i) {
    op->pending_apply.insert(*i);
    op->pending_commit.insert(*i);
    map<shard_id_t, ObjectStore::Transaction>::iterator iter =
      trans.find(i->shard);
    assert(iter != trans.end());
    bool should_send = get_parent()->should_send_op(*i, op->hoid);
    const pg_stat_t &stats =
      should_send ?
      get_info().stats :
      parent->get_shard_info().find(*i)->second.stats;

    ECSubWrite sop(
      get_parent()->whoami_shard(),
      op->tid,
      op->reqid,
      op->hoid,
      stats,
      should_send ? iter->second : empty,
      op->version,
      op->trim_to,
      op->roll_forward_to,
      op->log_entries,
      op->updated_hit_set_history,
      op->temp_added,
      op->temp_cleared,
      !should_send);

    ZTracer::Trace trace;
    if (op->trace) {
      // initialize a child span for this shard
      trace.init("ec sub write", nullptr, &op->trace);
      trace.keyval("shard", i->shard.id);
    }

    if (*i == get_parent()->whoami_shard()) {
      should_write_local = true;
      local_write_op.claim(sop);
    } else {
      MOSDECSubOpWrite *r = new MOSDECSubOpWrite(sop);
      r->pgid = spg_t(get_parent()->primary_spg_t().pgid, i->shard);
      r->map_epoch = get_parent()->get_epoch();
      r->min_epoch = get_parent()->get_interval_start_epoch();
      r->trace = trace;
      get_parent()->send_message_osd_cluster(
	i->osd, r, get_parent()->get_epoch());
    }
  }
  if (should_write_local) {
      handle_sub_write(
	get_parent()->whoami_shard(),
	op->client_op,
	local_write_op,
	op->trace,
	op->on_local_applied_sync);
      op->on_local_applied_sync = 0;
  }

  for (auto i = op->on_write.begin();
       i != op->on_write.end();
       op->on_write.erase(i++)) {
    (*i)();
  }

  return true;
}

bool ECBackend::try_finish_rmw()
{
  if (waiting_commit.empty())
    return false;
  Op *op = &(waiting_commit.front());
  if (op->write_in_progress())
    return false;
  waiting_commit.pop_front();

  dout(10) << __func__ << ": " << *op << dendl;
  dout(20) << __func__ << ": " << cache << dendl;

  if (op->roll_forward_to > completed_to)
    completed_to = op->roll_forward_to;
  if (op->version > committed_to)
    committed_to = op->version;

  if (get_osdmap()->require_osd_release >= CEPH_RELEASE_KRAKEN) {
    if (op->version > get_parent()->get_log().get_can_rollback_to() &&
	waiting_reads.empty() &&
	waiting_commit.empty()) {
      // submit a dummy transaction to kick the rollforward
      auto tid = get_parent()->get_tid();
      Op *nop = &(tid_to_op_map[tid]);
      nop->hoid = op->hoid;
      nop->trim_to = op->trim_to;
      nop->roll_forward_to = op->version;
      nop->tid = tid;
      nop->reqid = op->reqid;
      waiting_reads.push_back(*nop);
    }
  }

  if (op->using_cache) {
    cache.release_write_pin(op->pin);
  }
  tid_to_op_map.erase(op->tid);

  if (waiting_reads.empty() &&
      waiting_commit.empty()) {
    pipeline_state.clear();
    dout(20) << __func__ << ": clearing pipeline_state "
	     << pipeline_state
	     << dendl;
  }
  return true;
}

void ECBackend::check_ops()
{
  while (try_state_to_reads() ||
	 try_reads_to_commit() ||
	 try_finish_rmw());
}

int ECBackend::objects_read_sync(
  const hobject_t &hoid,
  uint64_t off,
  uint64_t len,
  uint32_t op_flags,
  bufferlist *bl)
{
  return -EOPNOTSUPP;
}

void ECBackend::objects_read_async(
  const hobject_t &hoid,
  const list<pair<boost::tuple<uint64_t, uint64_t, uint32_t>,
             pair<bufferlist*, Context*> > > &to_read,
  Context *on_complete,
  bool fast_read)
{
  dout(0) << " mydebug:: obj_read" << "#"<<hoid.oid.name<<","<<get_parent()->whoami()<<"#" << dendl;

  map<hobject_t,std::list<boost::tuple<uint64_t, uint64_t, uint32_t> > >
    reads;

  uint32_t flags = 0;
  extent_set es;
  for (list<pair<boost::tuple<uint64_t, uint64_t, uint32_t>,
	 pair<bufferlist*, Context*> > >::const_iterator i =
	 to_read.begin();
       i != to_read.end();
       ++i) {
    pair<uint64_t, uint64_t> tmp =
      sinfo.offset_len_to_stripe_bounds(
	make_pair(i->first.get<0>(), i->first.get<1>()));

    extent_set esnew;
    esnew.insert(tmp.first, tmp.second);
    es.union_of(esnew);
    flags |= i->first.get<2>();
  }

  if (!es.empty()) {
    auto &offsets = reads[hoid];
    for (auto j = es.begin();
	 j != es.end();
	 ++j) {
      offsets.push_back(
	boost::make_tuple(
	  j.get_start(),
	  j.get_len(),
	  flags));
    }
  }

  struct cb {
    ECBackend *ec;
    hobject_t hoid;
    list<pair<boost::tuple<uint64_t, uint64_t, uint32_t>,
	      pair<bufferlist*, Context*> > > to_read;
    unique_ptr<Context> on_complete;
    cb(const cb&) = delete;
    cb(cb &&) = default;
    cb(ECBackend *ec,
       const hobject_t &hoid,
       const list<pair<boost::tuple<uint64_t, uint64_t, uint32_t>,
                  pair<bufferlist*, Context*> > > &to_read,
       Context *on_complete)
      : ec(ec),
	hoid(hoid),
	to_read(to_read),
	on_complete(on_complete) {}
    void operator()(map<hobject_t,pair<int, extent_map> > &&results) {
      auto dpp = ec->get_parent()->get_dpp();
      ldpp_dout(dpp, 20) << "objects_read_async_cb: got: " << results
			 << dendl;
      ldpp_dout(dpp, 20) << "objects_read_async_cb: cache: " << ec->cache
			 << dendl;

      auto &got = results[hoid];

      int r = 0;
      for (auto &&read: to_read) {
	if (got.first < 0) {
	  if (read.second.second) {
	    read.second.second->complete(got.first);
	  }
	  if (r == 0)
	    r = got.first;
	} else {
	  assert(read.second.first);
	  uint64_t offset = read.first.get<0>();
	  uint64_t length = read.first.get<1>();
	  auto range = got.second.get_containing_range(offset, length);
	  assert(range.first != range.second);
	  assert(range.first.get_off() <= offset);
          ldpp_dout(dpp, 30) << "offset: " << offset << dendl;
          ldpp_dout(dpp, 30) << "range offset: " << range.first.get_off() << dendl;
          ldpp_dout(dpp, 30) << "length: " << length << dendl;
          ldpp_dout(dpp, 30) << "range length: " << range.first.get_len()  << dendl;
	  assert(
	    (offset + length) <=
	    (range.first.get_off() + range.first.get_len()));
	  read.second.first->substr_of(
	    range.first.get_val(),
	    offset - range.first.get_off(),
	    length);
	  if (read.second.second) {
	    read.second.second->complete(length);
	    read.second.second = nullptr;
	  }
	}
      }
      to_read.clear();
      if (on_complete) {
	on_complete.release()->complete(r);
      }
    }
    ~cb() {
      for (auto &&i: to_read) {
	delete i.second.second;
      }
      to_read.clear();
    }
  };
  objects_read_and_reconstruct(
    reads,
    fast_read,
    make_gen_lambda_context<
      map<hobject_t,pair<int, extent_map> > &&, cb>(
	cb(this,
	   hoid,
	   to_read,
	   on_complete)));
}

struct CallClientContexts :
  public GenContext<pair<RecoveryMessages*, ECBackend::read_result_t& > &> {
  hobject_t hoid;
  ECBackend *ec;
  ECBackend::ClientAsyncReadStatus *status;
  list<boost::tuple<uint64_t, uint64_t, uint32_t> > to_read;
  CallClientContexts(
    hobject_t hoid,
    ECBackend *ec,
    ECBackend::ClientAsyncReadStatus *status,
    const list<boost::tuple<uint64_t, uint64_t, uint32_t> > &to_read)
    : hoid(hoid), ec(ec), status(status), to_read(to_read) {}
  void finish(pair<RecoveryMessages *, ECBackend::read_result_t &> &in) override {
    ECBackend::read_result_t &res = in.second;
    extent_map result;
    if (res.r != 0)
      goto out;
    assert(res.returned.size() == to_read.size());
    assert(res.r == 0);
    assert(res.errors.empty());
    for (auto &&read: to_read) {
      pair<uint64_t, uint64_t> adjusted =
	ec->sinfo.offset_len_to_stripe_bounds(
	  make_pair(read.get<0>(), read.get<1>()));
      assert(res.returned.front().get<0>() == adjusted.first &&
	     res.returned.front().get<1>() == adjusted.second);
      map<int, bufferlist> to_decode;
      bufferlist bl;
      for (map<pg_shard_t, bufferlist>::iterator j =
	     res.returned.front().get<2>().begin();
	   j != res.returned.front().get<2>().end();
	   ++j) {
	to_decode[j->first.shard].claim(j->second);
      }
      int r = ECUtil::decode(
	ec->sinfo,
	ec->ec_impl,
	to_decode,
	&bl);
      if (r < 0) {
        res.r = r;
        goto out;
      }
      bufferlist trimmed;
      trimmed.substr_of(
	bl,
	read.get<0>() - adjusted.first,
	MIN(read.get<1>(),
	    bl.length() - (read.get<0>() - adjusted.first)));
      result.insert(
	read.get<0>(), trimmed.length(), std::move(trimmed));
      res.returned.pop_front();
    }
out:
    status->complete_object(hoid, res.r, std::move(result));
    ec->kick_reads();
  }
};

void ECBackend::objects_read_and_reconstruct(
  const map<hobject_t,
    std::list<boost::tuple<uint64_t, uint64_t, uint32_t> >
  > &reads,
  bool fast_read,
  GenContextURef<map<hobject_t,pair<int, extent_map> > &&> &&func)
{
  in_progress_client_reads.emplace_back(
    reads.size(), std::move(func));
  if (!reads.size()) {
    kick_reads();
    return;
  }

  map<hobject_t, set<int>> obj_want_to_read;
  set<int> want_to_read;
  get_want_to_read_shards(&want_to_read);
    
  map<hobject_t, read_request_t> for_read_op;
  for (auto &&to_read: reads) {
    set<pg_shard_t> shards;
    int r = get_min_avail_to_read_shards(
      to_read.first,
      want_to_read,
      false,
      fast_read,
      &shards);
    assert(r == 0);

    CallClientContexts *c = new CallClientContexts(
      to_read.first,
      this,
      &(in_progress_client_reads.back()),
      to_read.second);
    for_read_op.insert(
      make_pair(
	to_read.first,
	read_request_t(
	  to_read.second,
	  shards,
	  false,
	  c)));
    obj_want_to_read.insert(make_pair(to_read.first, want_to_read));
  }

  //dout(0)<<" :obj_start#"<<reads.begin()->first.oid.name<<","<<ceph_clock_now()<<","<<osd->whoami<<"#"<<dendl;
  start_read_op(
    CEPH_MSG_PRIO_DEFAULT,
    obj_want_to_read,
    for_read_op,
    OpRequestRef(),
    fast_read, false);
  return;
}


int ECBackend::send_all_remaining_reads(
  const hobject_t &hoid,
  ReadOp &rop)
{
  set<int> already_read;
  const set<pg_shard_t>& ots = rop.obj_to_source[hoid];
  for (set<pg_shard_t>::iterator i = ots.begin(); i != ots.end(); ++i)
    already_read.insert(i->shard);
  dout(10) << __func__ << " have/error shards=" << already_read << dendl;
  set<pg_shard_t> shards;
  int r = get_remaining_shards(hoid, already_read, rop.want_to_read[hoid],
			       rop.complete[hoid], &shards, rop.for_recovery);
  if (r)
    return r;

  list<boost::tuple<uint64_t, uint64_t, uint32_t> > offsets =
    rop.to_read.find(hoid)->second.to_read;
  GenContext<pair<RecoveryMessages *, read_result_t& > &> *c =
    rop.to_read.find(hoid)->second.cb;

  // (Note cuixf) If we need to read attrs and we read failed, try to read again.
  bool want_attrs =
    rop.to_read.find(hoid)->second.want_attrs &&
    (!rop.complete[hoid].attrs || rop.complete[hoid].attrs->empty());
  if (want_attrs) {
    dout(10) << __func__ << " want attrs again" << dendl;
  }

  rop.to_read.erase(hoid);
  rop.to_read.insert(make_pair(
      hoid,
      read_request_t(
	offsets,
	shards,
	want_attrs,
	c)));
  do_read_op(rop);
  return 0;
}

int ECBackend::objects_get_attrs(
  const hobject_t &hoid,
  map<string, bufferlist> *out)
{
  int r = store->getattrs(
    ch,
    ghobject_t(hoid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
    *out);
  if (r < 0)
    return r;

  for (map<string, bufferlist>::iterator i = out->begin();
       i != out->end();
       ) {
    if (ECUtil::is_hinfo_key_string(i->first))
      out->erase(i++);
    else
      ++i;
  }
  return r;
}

void ECBackend::rollback_append(
  const hobject_t &hoid,
  uint64_t old_size,
  ObjectStore::Transaction *t)
{
  assert(old_size % sinfo.get_stripe_width() == 0);
  t->truncate(
    coll,
    ghobject_t(hoid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
    sinfo.aligned_logical_offset_to_chunk_offset(
      old_size));
}

int ECBackend::be_deep_scrub(
  const hobject_t &poid,
  ScrubMap &map,
  ScrubMapBuilder &pos,
  ScrubMap::object &o)
{
  dout(10) << __func__ << " " << poid << " pos " << pos << dendl;
  int r;

  uint32_t fadvise_flags = CEPH_OSD_OP_FLAG_FADVISE_SEQUENTIAL |
                           CEPH_OSD_OP_FLAG_FADVISE_DONTNEED;

  utime_t sleeptime;
  sleeptime.set_from_double(cct->_conf->osd_debug_deep_scrub_sleep);
  if (sleeptime != utime_t()) {
    lgeneric_derr(cct) << __func__ << " sleeping for " << sleeptime << dendl;
    sleeptime.sleep();
  }

  if (pos.data_pos == 0) {
    pos.data_hash = bufferhash(-1);
  }

  uint64_t stride = cct->_conf->osd_deep_scrub_stride;
  if (stride % sinfo.get_chunk_size())
    stride += sinfo.get_chunk_size() - (stride % sinfo.get_chunk_size());

  bufferlist bl;
  r = store->read(
    ch,
    ghobject_t(
      poid, ghobject_t::NO_GEN, get_parent()->whoami_shard().shard),
    pos.data_pos,
    stride, bl,
    fadvise_flags);
  if (r < 0) {
    dout(20) << __func__ << "  " << poid << " got "
	     << r << " on read, read_error" << dendl;
    o.read_error = true;
    return 0;
  }
  if (bl.length() % sinfo.get_chunk_size()) {
    dout(20) << __func__ << "  " << poid << " got "
	     << r << " on read, not chunk size " << sinfo.get_chunk_size() << " aligned"
	     << dendl;
    o.read_error = true;
    return 0;
  }
  if (r > 0) {
    pos.data_hash << bl;
  }
  pos.data_pos += r;
  if (r == (int)stride) {
    return -EINPROGRESS;
  }

  ECUtil::HashInfoRef hinfo = get_hash_info(poid, false, &o.attrs);
  if (!hinfo) {
    dout(0) << "_scan_list  " << poid << " could not retrieve hash info" << dendl;
    o.read_error = true;
    o.digest_present = false;
    return 0;
  } else {
    if (!get_parent()->get_pool().allows_ecoverwrites()) {
      assert(hinfo->has_chunk_hash());
      if (hinfo->get_total_chunk_size() != (unsigned)pos.data_pos) {
	dout(0) << "_scan_list  " << poid << " got incorrect size on read 0x"
		<< std::hex << pos
		<< " expected 0x" << hinfo->get_total_chunk_size() << std::dec
		<< dendl;
	o.ec_size_mismatch = true;
	return 0;
      }

      if (hinfo->get_chunk_hash(get_parent()->whoami_shard().shard) !=
	  pos.data_hash.digest()) {
	dout(0) << "_scan_list  " << poid << " got incorrect hash on read 0x"
		<< std::hex << pos.data_hash.digest() << " !=  expected 0x"
		<< hinfo->get_chunk_hash(get_parent()->whoami_shard().shard)
		<< std::dec << dendl;
	o.ec_hash_mismatch = true;
	return 0;
      }

      /* We checked above that we match our own stored hash.  We cannot
       * send a hash of the actual object, so instead we simply send
       * our locally stored hash of shard 0 on the assumption that if
       * we match our chunk hash and our recollection of the hash for
       * chunk 0 matches that of our peers, there is likely no corruption.
       */
      o.digest = hinfo->get_chunk_hash(0);
      o.digest_present = true;
    } else {
      /* Hack! We must be using partial overwrites, and partial overwrites
       * don't support deep-scrub yet
       */
      o.digest = 0;
      o.digest_present = true;
    }
  }

  o.omap_digest = -1;
  o.omap_digest_present = true;
  return 0;
}
