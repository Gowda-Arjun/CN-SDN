#!/usr/bin/env python3
"""Dynamic host blocking controller app for Ryu/OpenFlow 1.3.

Features:
- Detect suspicious hosts based on packet/broadcast rate.
- Install drop flow rules dynamically for suspicious hosts.
- Verify block rules from flow stats replies.
- Log detection, blocking, verification, and unblock events.
"""

import json
import logging
import os
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3


class DynamicHostBlocker(app_manager.RyuApp):
    """Ryu app that blocks hosts dynamically based on traffic behavior."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    WINDOW_SECONDS = 5
    PACKET_RATE_THRESHOLD = 120
    BROADCAST_RATE_THRESHOLD = 40
    BLOCK_SECONDS = 60

    FORWARD_PRIORITY = 10
    BLOCK_PRIORITY = 200

    LEARNING_IDLE_TIMEOUT = 30
    LEARNING_HARD_TIMEOUT = 120

    VERIFY_INTERVAL_SECONDS = 5

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_to_port = defaultdict(dict)
        self.packet_times = defaultdict(deque)
        self.broadcast_times = defaultdict(deque)
        self.blocked_hosts = {}
        self.datapaths = {}

        self.event_logger = self._setup_event_logger()
        self.monitor_thread = hub.spawn(self._monitor)

        self._log_event(
            "controller_started",
            window_seconds=self.WINDOW_SECONDS,
            packet_threshold=self.PACKET_RATE_THRESHOLD,
            broadcast_threshold=self.BROADCAST_RATE_THRESHOLD,
            block_seconds=self.BLOCK_SECONDS,
        )

    def _setup_event_logger(self):
        """Create a rotating logger for event evidence/reporting."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        log_dir = os.getenv("DHB_LOG_DIR", os.path.join(project_root, "logs"))
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "block_events.log")

        logger = logging.getLogger("dynamic_host_blocking.events")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        if not logger.handlers:
            formatter = logging.Formatter("%(asctime)s %(message)s")

            file_handler = RotatingFileHandler(
                log_path, maxBytes=2_000_000, backupCount=3
            )
            file_handler.setFormatter(formatter)

            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)

            logger.addHandler(file_handler)
            logger.addHandler(stream_handler)

        return logger

    def _log_event(self, event_name, **fields):
        payload = {
            "event": event_name,
            "ts_epoch_ms": int(time.time() * 1000),
        }
        payload.update(fields)
        self.event_logger.info(json.dumps(payload, sort_keys=True))

    def _add_flow(
        self,
        datapath,
        priority,
        match,
        actions=None,
        idle_timeout=0,
        hard_timeout=0,
    ):
        parser = datapath.ofproto_parser

        if actions is None:
            instructions = []
        else:
            instructions = [
                parser.OFPInstructionActions(
                    datapath.ofproto.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def _delete_block_flow(self, datapath, src_mac, in_port):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(in_port=in_port, eth_src=src_mac)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=self.BLOCK_PRIORITY,
            match=match,
        )
        datapath.send_msg(mod)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _detect_suspicious(self, dpid, src, dst, now_ts):
        key = (dpid, src)

        pkt_window = self.packet_times[key]
        pkt_window.append(now_ts)
        while pkt_window and now_ts - pkt_window[0] > self.WINDOW_SECONDS:
            pkt_window.popleft()

        if len(pkt_window) > self.PACKET_RATE_THRESHOLD:
            return "packet_rate_exceeded"

        if dst == "ff:ff:ff:ff:ff:ff":
            bcast_window = self.broadcast_times[key]
            bcast_window.append(now_ts)
            while bcast_window and now_ts - bcast_window[0] > self.WINDOW_SECONDS:
                bcast_window.popleft()

            if len(bcast_window) > self.BROADCAST_RATE_THRESHOLD:
                return "broadcast_rate_exceeded"

        return None

    def _is_blocked(self, dpid, src, now_ts):
        key = (dpid, src)
        record = self.blocked_hosts.get(key)

        if record is None:
            return False

        if now_ts < record["unblock_at"]:
            return True

        self.blocked_hosts.pop(key, None)
        self._log_event(
            "host_unblocked",
            dpid=dpid,
            src=src,
            in_port=record["in_port"],
            reason="timer_expired",
        )
        return False

    def _block_host(self, datapath, src, in_port, reason, now_ts):
        dpid = datapath.id
        key = (dpid, src)

        existing = self.blocked_hosts.get(key)
        if existing and now_ts < existing["unblock_at"]:
            return

        parser = datapath.ofproto_parser
        drop_match = parser.OFPMatch(in_port=in_port, eth_src=src)

        self._add_flow(
            datapath=datapath,
            priority=self.BLOCK_PRIORITY,
            match=drop_match,
            actions=None,
            idle_timeout=0,
            hard_timeout=self.BLOCK_SECONDS,
        )

        self.blocked_hosts[key] = {
            "in_port": in_port,
            "blocked_at": now_ts,
            "unblock_at": now_ts + self.BLOCK_SECONDS,
            "reason": reason,
            "verified": False,
            "verify_checks": 0,
            "verify_retry_logged": False,
        }

        self._log_event(
            "host_blocked",
            dpid=dpid,
            src=src,
            in_port=in_port,
            reason=reason,
            block_seconds=self.BLOCK_SECONDS,
        )

        self._request_flow_stats(datapath)

    def _expire_blocks(self):
        now_ts = time.time()

        for (dpid, src), record in list(self.blocked_hosts.items()):
            if now_ts < record["unblock_at"]:
                continue

            self.blocked_hosts.pop((dpid, src), None)

            datapath = self.datapaths.get(dpid)
            if datapath is not None:
                self._delete_block_flow(datapath, src, record["in_port"])

            self._log_event(
                "host_unblocked",
                dpid=dpid,
                src=src,
                in_port=record["in_port"],
                reason="timer_expired",
            )

    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)
            self._expire_blocks()
            hub.sleep(self.VERIFY_INTERVAL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self._log_event("switch_connected", dpid=datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self._log_event("switch_disconnected", dpid=datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self._add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions,
        )

        self._log_event("table_miss_installed", dpid=datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src.lower()
        dst = eth.dst.lower()
        now_ts = time.time()

        self.mac_to_port[dpid][src] = in_port

        if self._is_blocked(dpid, src, now_ts):
            return

        reason = self._detect_suspicious(dpid, src, dst, now_ts)
        if reason is not None:
            self._block_host(datapath, src, in_port, reason, now_ts)
            return

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self._add_flow(
                datapath=datapath,
                priority=self.FORWARD_PRIORITY,
                match=match,
                actions=actions,
                idle_timeout=self.LEARNING_IDLE_TIMEOUT,
                hard_timeout=self.LEARNING_HARD_TIMEOUT,
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id

        found_block_entries = set()

        for stat in ev.msg.body:
            if stat.priority != self.BLOCK_PRIORITY:
                continue

            src = stat.match.get("eth_src")
            in_port = stat.match.get("in_port")
            if src is None or in_port is None:
                continue

            src = str(src).lower()
            key = (dpid, src)
            record = self.blocked_hosts.get(key)
            if not record:
                continue

            if int(in_port) != int(record["in_port"]):
                continue

            found_block_entries.add(key)

            if not record["verified"]:
                record["verified"] = True
                self._log_event(
                    "block_verified",
                    dpid=dpid,
                    src=src,
                    in_port=record["in_port"],
                    packet_count=stat.packet_count,
                    byte_count=stat.byte_count,
                )

        for key, record in list(self.blocked_hosts.items()):
            if key[0] != dpid:
                continue
            if key in found_block_entries:
                continue

            record["verify_checks"] += 1
            if record["verified"]:
                record["verified"] = False

            # Log only once if verification does not find the rule quickly.
            if record["verify_checks"] >= 2 and not record["verify_retry_logged"]:
                record["verify_retry_logged"] = True
                self._log_event(
                    "block_verification_retry",
                    dpid=dpid,
                    src=key[1],
                    in_port=record["in_port"],
                )
