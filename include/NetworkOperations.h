/*
 Copyright 2022 Yury Bobylev <bobilev_yury@mail.ru>

 This file is part of libcommunist.
 libcommunist is free software: you can redistribute it and/or
 modify it under the terms of the GNU General Public License as 
 published by the Free Software Foundation, either version 3 of 
 the License, or (at your option) any later version.
 libcommunist is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with libcommunist. If not,
 see <https://www.gnu.org/licenses/>. 
 */

#ifndef NETWORKOPERATIONS_H_
#define NETWORKOPERATIONS_H_

#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cstring>
#include <thread>
#include <mutex>
#include <memory>
#include <tuple>
#include <iostream>
#include <functional>
#include <libtorrent/hex.hpp>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "AuxFuncNet.h"
#include "DHTOperations.h"
#include "LocalNetworkOp.h"
#include "FileReceiveOp.h"
#include "MsgProfileReceive.h"
#include "MsgSending.h"
#include "FileSending.h"
#include "RelayOperations.h"

#ifdef __linux
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#endif

#ifdef _WIN32
#include <Winsock2.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

class DHTOperations;
class LocalNetworkOp;
class MsgProfileReceive;
class FileSending;

class NetworkOperations
{
  friend class DHTOperations;
  friend class LocalNetworkOp;
  friend class FileReceiveOp;
  friend class MsgProfileReceive;
  friend class MsgSending;
  friend class FileSending;
public:
  NetworkOperations(std::string username, std::string password,
		    std::vector<std::tuple<int, std::string>> &Contacts,
		    std::array<char, 32> &Seed,
		    std::vector<std::string> &addfriends,
		    std::vector<std::tuple<std::string, std::string>> &Prefvect,
		    std::string sharepath, std::string homepath);
  virtual
  ~NetworkOperations();
  std::function<void
  ()> canceled;
  std::function<void
  (std::string, std::filesystem::path)> messageReceived;
  std::function<void
  (std::string, int)> profReceived;
  std::function<void
  (std::string, std::filesystem::path)> msgSent;
  std::function<void
  (std::string, uint64_t, uint64_t, std::string)> filerequest;
  std::function<void
  (std::string, std::filesystem::path)> fileRejected;
  std::function<void
  (std::string, std::filesystem::path)> filehasherr;
  std::function<void
  (std::string, std::filesystem::path)> filercvd;
  std::function<void
  (std::string, std::filesystem::path)> filesentsig;
  std::function<void
  (std::string, std::filesystem::path)> filesenterror;
  std::function<void
  (std::string)> ipv6signal;
  std::function<void
  (std::string)> ipv4signal;
  std::function<void
  ()> ipv6signalfinished;
  std::function<void
  ()> ipv4signalfinished;
  std::function<void
  (std::string, std::filesystem::path, uint64_t)> filepartrcvdsig; //key, path to file, file current size
  std::function<void
  (std::string, std::filesystem::path, uint64_t)> filepartsendsig; //key, path to file, sent byte quantity
  std::function<void
  (std::string, uint64_t)> smthrcvdsig;
  std::function<void
  (std::string)> friendDeleted;
  std::function<void
  ()> friendDelPulse;
  std::function<void
  ()> friendBlockedSig;
  void
  mainFunc();
  void
  getNewFriends(std::string key);
  void
  removeFriend(std::string key);
  bool
  checkIfMsgSent(std::filesystem::path p);
  std::filesystem::path
  createMsg(std::string key, std::filesystem::path p, int type);
  void
  renewProfile(std::string key);
  void
  fileReject(std::string key, uint64_t tm);
  void
  fileAccept(std::string key, uint64_t tm, std::filesystem::path sp, bool fa);
  void
  startFriend(std::string key, int ind);
  void
  blockFriend(std::string key);
  void
  setIPv6(std::string ip);
  void
  setIPv4(std::string ip);
  std::filesystem::path
  removeMsg(std::string key, std::filesystem::path msgpath);
  void
  cancelAll();
  void
  cancelSendF(std::string key, std::filesystem::path filepath);
  void
  cancelReceivF(std::string key, std::filesystem::path filepath);
  void
  editContByRelay(std::vector<std::string> &sendbyrel);
  std::filesystem::path
  formMsg(std::string key, std::string nick, std::string replstr,
	  std::filesystem::path msgpath, int type);
  std::filesystem::path
  formMsg(std::string key, std::string nick, std::string replstr,
	  std::string msgstring, int type);

private:
  std::function<void
  ()> dnsfinished;
  void
  dnsFunc();
  void
  putOwnIps(std::array<char, 32> otherkey, uint32_t ip, uint16_t port);
  std::pair<uint32_t, uint16_t>
  getOwnIps(int udpsock, std::pair<struct in_addr, int> stunsv);
  void
  holePunchThr(size_t i, time_t curtime, int sock, uint32_t ip,
	       std::mutex *thrmtx);
  void
  holePunch(int sock, uint32_t ip, std::array<char, 32> otherkey);
  int
  receiveMsg(int sockipv4, sockaddr_in *from, std::string relaykey,
	     std::vector<char> *relaymsg);
  void
  receivePoll();
  int
  sendMsg(int sockipv4, uint32_t ip, uint16_t port, std::vector<char> &msg);
  int
  sendMsg6(int sock, std::string ip6, uint16_t port, std::vector<char> &msg);
  int
  sendMsgGlob(int sock, std::array<char, 32> keytos, uint32_t ip,
	      uint16_t port);
  void
  commOps();
  void
  stunSrv();
  void
  stunSrvThread(std::mutex *thrmtx, int stnsrvsock);
  void
  stunCheckThread(std::mutex *thrmtx, int stnsock);
  void
  dnsFinishedThread(std::mutex *thrmtx);
  void
  getOwnIpsThread(
      std::mutex *thrmtx,
      std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, time_t>> *ownips,
      std::mutex *ownipsmtx);
  void
  getFriendIpsThread(
      std::vector<std::tuple<std::array<char, 32>, time_t>> *blockip,
      std::mutex *blockipmtx, std::mutex *thrmtx);
  void
  receiveMsgThread(int sock, std::mutex *thrmtx);
  void
  sendMsgThread(std::mutex *sendingthrmtx,
		std::vector<std::array<char, 32>> *sendingthr,
		std::array<char, 32> key, std::mutex *mtx, int sock,
		std::mutex *thrmtxsm);
#ifdef _WIN32
  int
  poll (struct pollfd *pfd, int nfds, int timeout);
#endif
  std::vector<std::tuple<int, std::array<char, 32>>> contacts;
  std::mutex contmtx;
  std::vector<std::tuple<int, std::array<char, 32>>> contactsfull;
  std::mutex contfullmtx;
  int contsizech = 0;
  std::vector<std::string> Addfriends;
  std::mutex addfrmtx;
  std::vector<std::tuple<std::array<char, 32>, time_t>> maintblock;
  std::mutex maintblockmtx;
  std::vector<
      std::tuple<std::array<char, 32>, int, std::mutex*, time_t, std::mutex*>> sockets4;
  std::mutex sockmtx;
  std::vector<std::array<char, 32>> getfr;
  std::mutex getfrmtx;
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int>> getfrres;
  std::mutex getfrresmtx;
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>> putipv;
  std::mutex putipmtx;
  std::vector<std::tuple<std::array<char, 32>, std::string, uint16_t, int>> ipv6cont; //key, ip, port, sequens
  std::mutex ipv6contmtx;
  std::vector<std::tuple<std::array<char, 32>, time_t>> ipv6lr;
  std::mutex ipv6lrmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>>> msghash; //0-key, 1-time, 2-msg size, 3-hash
  std::mutex msghashmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t, std::vector<char>>> msgparthash; //0-key, 1-time, 2-hash
  std::mutex msgparthashmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>>> msgpartrcv; //0-key, 1-time, 2-part numb, 3-part
  std::mutex msgpartrcvmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t, uint64_t>> msgrcvdpnum; //0-key, 1-time, 2-partnum
  std::mutex msgrcvdpnummtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, int, std::filesystem::path,
	  int, uint64_t, std::vector<char>>> msgpartbuf; //0-key, 1-time, 2-receive status, 3-path to msg, 4-byte sent, 5-partnum, 6-part
  std::mutex msgpartbufmtx;
  std::vector<
      std::tuple<std::array<char, 32>, std::filesystem::path, uint64_t, int,
	  std::filesystem::path>> filesendreq; //0-key, 1-file to send path, 2-time of first datagram, 3-accept status, 4-msg path
  std::mutex filesendreqmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, std::string, std::string,
	  std::string>> fqrcvd; //0-key, 1-time from FQ msg, 2-file name, 3-replay msg, 4-resend msg
  std::mutex fqrcvdmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t, std::string, uint64_t>> fqblockv; //0-key, 1-time from FQ msg, 2-file name, 3-time, element have been added to vector
  std::mutex fqblockvmtx;
  std::vector<std::pair<struct in_addr, uint16_t>> stunips;
  std::mutex stunipsmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, std::filesystem::path, int,
	  uint64_t, std::vector<char>, int>> filepartbuf; //0-key, 1-time from FQ message, 2-path to source file, 3-byte quantity sent, 4-part number, 5 - filepart, 6 - status
  std::mutex filepartbufmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, std::vector<char>,
	  std::filesystem::path, int>> filehashvect; //0-key, 1-time FB, 2-file hash, 3-path to file, 4-last rcvd part number
  std::mutex filehashvectmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>>> fileparthash; //0-key, 1-time FB, 2-file part number, 3-part hash
  std::mutex fileparthashmtx;
  std::vector<
      std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>>> filepartrcv; //0-key, 1-time, 2-part number, 3-part
  std::mutex filepartrcvmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t, int>> filepartrlog; //0-key, 1-time, 2-last part recieved
  std::mutex filepartrlogmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t, std::vector<char>>> currentpart; //0-key, 1-time, 2-part
  std::mutex currentpartmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t>> fbrvect; //"FB" received vector
  std::mutex fbrvectmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t>> filepartend; //0-key, 1-time
  std::mutex filepartendmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t>> fileend; //0-key, 1-time
  std::mutex fileendmtx;
  std::vector<std::tuple<std::array<char, 32>, uint64_t>> filecanceled; //0-key, 1-time from FQ msg
  std::mutex filecanceledmtx;
  std::vector<std::tuple<std::array<char, 32>, int>> holepunchstop; //0-key, 1-port to start with
  std::mutex holepunchstopmtx;
  std::string Username;
  std::string Password;
  int cancel = 0;
  std::mutex sendbufmtx;
  std::mutex rcvmtx;
  int cancelgetoips = 0;
  std::array<char, 32> seed;
  std::vector<std::tuple<std::string, std::string>> prefvect;

  std::string Home_Path = "";
  std::string rellistpath = "";
  uint16_t relayport = 0;
  std::string relaysrv = "";
  DHTOperations *DOp = nullptr;
  LocalNetworkOp *LNOp = nullptr;
  RelayOperations *ROp = nullptr;
  int sockipv6;
  std::mutex sockipv6mtx;
  int ownnattype = 0;
  time_t contreqtmr = 0;
  std::string ownipv6 = "";
  uint16_t ownipv6port = 0;
  std::mutex ownipv6mtx;
  std::mutex copsrun;
  std::mutex copsrunmtx;
  std::string Netmode = "0";
  int Maxmsgsz = 1024 * 1024;
  int Partsize = 457 * 3;
  std::string IPV4 = "";
  std::mutex IPV4mtx;
  std::string Sharepath;
  time_t Shuttmt = 600;
  time_t Tmttear = 20;
  time_t Maintpause = 5;
  uint16_t stunport = 3478;
  std::string Enablestun = "notactive";
  std::string Directinet = "notdirect";
  std::vector<std::tuple<std::mutex*, std::string>> threadvect;
  std::mutex threadvectmtx;

  std::vector<
      std::tuple<uint32_t, uint16_t, time_t, std::shared_ptr<std::mutex>>> relayaddr;
  std::mutex relayaddrmtx;

  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t>> frrelays;
  std::mutex frrelaysmtx;

  std::vector<std::array<char, 32>> sendbyrelay;
  std::mutex sendbyrelaymtx;

  bool Hole_Punch = false;
};

#endif /* NETWORKOPERATIONS_H_ */
