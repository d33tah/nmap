
/***************************************************************************
 * scan_engine_connect.cc -- includes helper functions for scan_engine.cc  *
 * that are related to port scanning using connect() system call.          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nmap_error.h"
#include "Target.h"
#include "scan_engine_connect.h"
#include "libnetutil/netutil.h" /* for max_sd() */
#include "NmapOps.h"

#include <errno.h>

extern NmapOps o;

/* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
void UltraProbe::setConnect(u16 portno) {
  type = UP_CONNECT;
  probes.CP = new ConnectProbe();
  mypspec.type = PS_CONNECTTCP;
  mypspec.proto = IPPROTO_TCP;
  mypspec.pd.tcp.dport = portno;
  mypspec.pd.tcp.flags = TH_SYN;
}

ConnectScanInfo::ConnectScanInfo() {
  numSDs = 0;
  if (o.max_parallelism > 0) {
    maxSocketsAllowed = o.max_parallelism;
  } else {
    /* Subtracting 10 from max_sd accounts for
       stdin
       stdout
       stderr
       /dev/tty
       /var/run/utmpx, which is opened on Mac OS X at least
       -oG log file
       -oN log file
       -oS log file
       -oX log file
       perhaps another we've forgotten. */
    maxSocketsAllowed = max_sd() - 10;
    if (maxSocketsAllowed < 5)
      maxSocketsAllowed = 5;
  }
  maxSocketsAllowed = MIN(maxSocketsAllowed, FD_SETSIZE - 10);
  nsp = nsock_pool_new(NULL);
  nsock_set_log_function(nmap_nsock_stderr_logger);
  nsock_pool_set_device(nsp, o.device);

  if (o.proxy_chain) {
    nsock_pool_set_proxychain(nsp, o.proxy_chain);
  }
}

/* Nothing really to do here. */
ConnectScanInfo::~ConnectScanInfo() {
  nsock_pool_delete(nsp);
}

static void handleConnectResult(UltraScanInfo *USI, HostScanStats *hss,
                                std::list<UltraProbe *>::iterator probeI,
                                int connect_errno,
                                bool destroy_probe=false) {
  bool adjust_timing = true;
  int newportstate = PORT_UNKNOWN;
  int newhoststate = HOST_UNKNOWN;
  reason_t current_reason = ER_NORESPONSE;
  UltraProbe *probe = *probeI;
  struct sockaddr_storage remote;
  size_t remote_len;

  if (hss->target->TargetSockAddr(&remote, &remote_len) != 0) {
    fatal("Failed to get target socket address in %s", __func__);
  }
  if (remote.ss_family == AF_INET)
    ((struct sockaddr_in *) &remote)->sin_port = htons(probe->dport());
#if HAVE_IPV6
  else
    ((struct sockaddr_in6 *) &remote)->sin6_port = htons(probe->dport());
#endif
  PacketTrace::traceConnect(IPPROTO_TCP, (sockaddr *) &remote, remote_len,
      connect_errno, connect_errno, &USI->now);
  switch (connect_errno) {
    case 0:
      newhoststate = HOST_UP;
      newportstate = PORT_OPEN;
      current_reason = ER_CONACCEPT;
      break;
    case EACCES:
      /* Apparently this can be caused by dest unreachable admin
         prohibited messages sent back, at least from IPv6
         hosts */
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_ADMINPROHIBITED;
      break;
    /* This can happen on localhost, successful/failing connection immediately
       in non-blocking mode. */
    case ECONNREFUSED:
      newhoststate = HOST_UP;
      newportstate = PORT_CLOSED;
      current_reason = ER_CONREFUSED;
      break;
    case EAGAIN:
      log_write(LOG_STDOUT, "Machine %s MIGHT actually be listening on probe port %d\n", hss->target->targetipstr(), USI->ports->syn_ping_ports[probe->dport()]);
      /* Fall through. */
#ifdef WIN32
    case WSAENOTCONN:
#endif
      newhoststate = HOST_UP;
      current_reason = ER_CONACCEPT;
      break;
#ifdef ENOPROTOOPT
    case ENOPROTOOPT:
#endif
    case EHOSTUNREACH:
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_HOSTUNREACH;
      break;
#ifdef WIN32
    case WSAEADDRNOTAVAIL:
#endif
    case ETIMEDOUT:
    case EHOSTDOWN:
      newhoststate = HOST_DOWN;
      /* It could be the host is down, or it could be firewalled.  We
         will go on the safe side & assume port is closed ... on second
         thought, lets go firewalled! and see if it causes any trouble */
      newportstate = PORT_FILTERED;
      current_reason = ER_NORESPONSE;
      break;
    case ENETUNREACH:
      newhoststate = HOST_DOWN;
      newportstate = PORT_FILTERED;
      current_reason = ER_NETUNREACH;
      break;
    case ENETDOWN:
    case ENETRESET:
    case ECONNABORTED:
      fatal("Strange SO_ERROR from connection to %s (%d - '%s') -- bailing scan", hss->target->targetipstr(), connect_errno, strerror(connect_errno));
      break;
    default:
      error("Strange read error from %s (%d - '%s')", hss->target->targetipstr(), connect_errno, strerror(connect_errno));
      break;
  }
  if (probe->isPing() && newhoststate != HOST_UNKNOWN ) {
    ultrascan_ping_update(USI, hss, probeI, &USI->now, adjust_timing);
  } else if (USI->ping_scan && newhoststate != HOST_UNKNOWN) {
    ultrascan_host_probe_update(USI, hss, probeI, newhoststate, &USI->now, adjust_timing);
    hss->target->reason.reason_id = current_reason;
    /* If the host is up, we can forget our other probes. */
    if (newhoststate == HOST_UP)
      hss->destroyAllOutstandingProbes();
  } else if (!USI->ping_scan && newportstate != PORT_UNKNOWN) {
    /* Save these values so we can use them after
       ultrascan_port_probe_update deletes probe. */
    u8 protocol = probe->protocol();
    u16 dport = probe->dport();
    if (newportstate == PORT_OPEN && probe->CP()->self_connect)
      hss->markProbeTimedout(probeI);
    else {
      ultrascan_port_probe_update(USI, hss, probeI, newportstate, &USI->now, adjust_timing);
      hss->target->ports.setStateReason(dport, protocol, current_reason, 0, NULL);
    }
  } else if (destroy_probe) {
    hss->destroyOutstandingProbe(probeI);
  }
  return;
}

ConnectProbe::ConnectProbe() {
  connected = false;
  self_connect = false;
  connect_result = -2;
}

ConnectProbe::~ConnectProbe() {
  if (o.debugging > 8)
    log_write(LOG_PLAIN, "ConnectProbe::~ConnectProbe[%p]"
              ", connected=%d\n", this, connected);
  if (connected)
    nsock_iod_delete(sock_nsi, NSOCK_PENDING_SILENT);
}

static bool is_self_connect(int sd, int dport, Target *target) {
  struct sockaddr_storage local;
  socklen_t local_len = sizeof(struct sockaddr_storage);
  struct sockaddr_storage remote;
  size_t remote_len;

  if (getsockname(sd, (struct sockaddr*)&local, &local_len) == 0
    && target->TargetSockAddr(&remote, &remote_len) == 0) {
    if (sockaddr_storage_cmp(&local, &remote) == 0 && (
          (local.ss_family == AF_INET &&
            ((struct sockaddr_in*)&local)->sin_port == htons(dport))
#if HAVE_IPV6
          || (local.ss_family == AF_INET6 &&
            ((struct sockaddr_in6*)&local)->sin6_port == htons(dport))
#endif
          )) {
      return true;
    }
  }
  else {
    gh_perror("getsockname or TargetSockAddr failed");
  }
  return false;
}

struct probe_and_hss {
  UltraProbe *probe;
  HostScanStats *hss;
};

void connectHandler(nsock_pool nsp, nsock_event evt, void* data) {
  probe_and_hss *data_struct = (probe_and_hss*)data;
  UltraProbe *probe = data_struct->probe;
  HostScanStats *hss = data_struct->hss;
  delete data_struct;

  nsock_iod nsi = nse_iod(evt);
  enum nse_status status = nse_status(evt);
  enum nse_type type = nse_type(evt);

  assert(type == NSE_TYPE_CONNECT);
  int connect_errno = nse_errorcode(evt);
  assert(status != NSE_STATUS_SUCCESS || (status == NSE_STATUS_SUCCESS && connect_errno == 0));
  if (status == NSE_STATUS_TIMEOUT)
    connect_errno = ETIMEDOUT;

  if (status == NSE_STATUS_PROXYERROR) {
    nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
    return;
  }

  probe->CP()->connect_result = connect_errno;
  if (o.debugging > 5)
    log_write(LOG_PLAIN, "connectHandler: connect_errno=%d, status=%s, portno=%d.\n",
                connect_errno, nse_status2str(status), probe->dport());


  /* XXX: I'm getting the following error:
     nmap: scan_engine.cc:1673: void HostScanStats::markProbeTimedout(std::list<UltraProbe*>::iterator): Assertion `!probe->timedout' failed.
      Also, perhaps it's worth checking if we're behind proxy instead of doing
      this check all the time? */
  if (status != NSE_STATUS_KILL) {
    if (is_self_connect(nsock_iod_get_sd(nsi), probe->dport(), hss->target)) {
      probe->CP()->self_connect = true;
    }

    nsock_iod_delete(nsi, NSOCK_PENDING_SILENT);
  }
  probe->CP()->connected = false;
}

/* If this is NOT a ping probe, set pingseq to 0.  Otherwise it will be the
   ping sequence number (they start at 1).  The probe sent is returned. */
UltraProbe *sendConnectScanProbe(UltraScanInfo *USI, HostScanStats *hss,
                                 u16 destport, u8 tryno, u8 pingseq) {

  UltraProbe *probe = new UltraProbe();
  std::list<UltraProbe *>::iterator probeI;
  ConnectProbe *CP;

  probe->tryno = tryno;
  probe->pingseq = pingseq;
  /* First build the probe */
  probe->setConnect(destport);
  CP = probe->CP();

  CP->sock_nsi = nsock_iod_new(USI->gstats->CSI->nsp, NULL);
  if (CP->sock_nsi == NULL)
    fatal("Failed to create nsock_iod.");

  /* Set the socket lingering so we will RST connections instead of wasting
     bandwidth with the four-step close. */
  struct linger l;
  l.l_onoff = 1;
  l.l_linger = 0;
  nsock_iod_set_linger(CP->sock_nsi, l);

  /* Spoof the source IP address. The following is copied from l_connect from
     nse_nsock.cc. */
  if (o.spoofsource) {
    struct sockaddr_storage ss;
    size_t sslen;

    o.SourceSockAddr(&ss, &sslen);
    nsock_iod_set_localaddr(CP->sock_nsi, &ss, sslen);
  }

  /* Set the IP TTL value. */
  nsock_iod_set_ttl(CP->sock_nsi, o.ttl);

  /* Set any IP options user requested. */
  if (o.ipoptionslen)
    nsock_iod_set_ipoptions(CP->sock_nsi, o.ipoptions, o.ipoptionslen);

  /* Translate target's IP to struct sockaddr_storage. */
  struct sockaddr_storage targetss;
  size_t targetsslen;
  if (hss->target->TargetSockAddr(&targetss, &targetsslen) != 0)
    fatal("Failed to get target socket address in %s", __func__);

  probe->sent = USI->now;
  /* We don't record a byte count for connect probes. */
  hss->probeSent(0);
  probe_and_hss *userdata = new probe_and_hss();
  userdata->probe = probe;
  userdata->hss = hss;
  nsock_connect_tcp(USI->gstats->CSI->nsp, CP->sock_nsi, connectHandler,
                    1000, /* timeout */
                    userdata,
                    (struct sockaddr *)&targetss, targetsslen,
                    probe->pspec()->pd.tcp.dport);
  probe->CP()->connected = true;
  gettimeofday(&USI->now, NULL);
  /* This counts as probe being sent, so update structures */
  hss->probes_outstanding.push_back(probe);
  probeI = hss->probes_outstanding.end();
  probeI--;
  USI->gstats->num_probes_active++;
  hss->num_probes_active++;

  /* It would be convenient if the connect() call would never succeed
     or permanently fail here, so related code cood all be localized
     elsewhere.  But the reality is that connect() MAY be finished now. */

  /* XXX: static void PacketTrace::traceConnect(u8, const sockaddr*, int, int, int, const timeval*): Assertion `sin->sin_family == 10' failed. */
  //PacketTrace::traceConnect(IPPROTO_TCP, (sockaddr *) &sock, socklen, rc,
  //    connect_errno, &USI->now);
  gettimeofday(&USI->now, NULL);
  return probe;
}

/* Does a select() call and handles all of the results. This handles both host
   discovery (ping) scans and port scans.  Even if stime is now, it tries a very
   quick select() just in case.  Returns true if at least one good result
   (generally a port state change) is found, false if it times out instead */
bool do_one_select_round(UltraScanInfo *USI, struct timeval *stime) {
  int selectres = 1;
  ConnectScanInfo *CSI = USI->gstats->CSI;
  std::list<HostScanStats *>::iterator hostI;
  HostScanStats *host;
  UltraProbe *probe = NULL;
  int numGoodSD = 0;
  int err = 0;

  do {
    int timeleft_ms = TIMEVAL_MSEC_SUBTRACT(*stime, USI->now);
    if (timeleft_ms < 0)
      timeleft_ms = 0;

    nsock_loop(CSI->nsp, timeleft_ms);
  } while (selectres == -1 && err == EINTR);

  gettimeofday(&USI->now, NULL);

  if (selectres == -1)
    pfatal("select failed in %s()", __func__);

  if (!selectres)
    return false;

  /* Yay!  Got at least one response back -- loop through outstanding probes
     and find the relevant ones. Note the peculiar structure of the loop--we
     iterate through both incompleteHosts and completedHosts, because global
     timing pings are sent to hosts in completedHosts. */
  std::list<HostScanStats *>::iterator incompleteHostI, completedHostI;
  incompleteHostI = USI->incompleteHosts.begin();
  completedHostI = USI->completedHosts.begin();
  while ((incompleteHostI != USI->incompleteHosts.end()
          || completedHostI != USI->completedHosts.end())) {


    if (incompleteHostI != USI->incompleteHosts.end())
      hostI = incompleteHostI++;
    else
      hostI = completedHostI++;

    host = *hostI;
    if (host->num_probes_active == 0)
      continue;

    std::list<UltraProbe *>::iterator nextProbeI;
    for (std::list<UltraProbe *>::iterator probeI = host->probes_outstanding.begin(), end = host->probes_outstanding.end();
        probeI != end && host->num_probes_outstanding() > 0; probeI = nextProbeI) {
      /* handleConnectResult may remove the probe at probeI, which invalidates
       * the iterator. We copy and increment it here instead of in the for-loop
       * statement to avoid incrementing an invalid iterator */
      nextProbeI = probeI;
      nextProbeI++;
      probe = *probeI;
      assert(probe->type == UltraProbe::UP_CONNECT);

      int connect_errno = probe->CP()->connect_result;
      if (connect_errno == -2)
        connect_errno = ETIMEDOUT;
      if (connect_errno != ETIMEDOUT) {
        numGoodSD++;
        if (o.debugging > 5)
          log_write(LOG_PLAIN, "Calling handleConnectResult.\n");
        handleConnectResult(USI, host, probeI, connect_errno);
      }

    }
  }
  return numGoodSD;
}
