/*
 Copyright 2022-2023 Yury Bobylev <bobilev_yury@mail.ru>

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

#ifndef SRC_RELAYOPERATIONS_H_
#define SRC_RELAYOPERATIONS_H_

#include <vector>
#include <tuple>
#include <string>
#include <mutex>
#include <memory>
#include <functional>

#ifdef __linux
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <Winsock2.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

class RelayOperations
{
public:
  RelayOperations(
      std::string ipbstr,
      std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int>> *getfrres,
      std::mutex *getfrresmtx,
      std::vector<
	  std::tuple<uint32_t, uint16_t, time_t, std::shared_ptr<std::mutex>>> *relayaddr,
      std::mutex *relayaddrmtx,
      std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t>> *frrelays,
      std::mutex *frrelaysmtx, uint16_t relayport, std::string enable_relay_srv,
      std::vector<std::tuple<std::mutex*, std::string>> *threadvect,
      std::mutex *threadvectmtx, int *cancel, std::string relay_list_path,
      std::vector<std::array<char, 32>> *sendbyrelay,
      std::mutex *sendbyrelaymtx);
  virtual
  ~RelayOperations();
  std::function<void
  (int, sockaddr_in*, std::string, std::vector<char>*)> relaymsgrcvd_signal;
  int
  relaySend(std::array<char, 32> keyarr, std::array<char, 32> &seed,
	    std::vector<std::vector<char>> &msgsbuf);
  int
  relayCheck(
      std::array<char, 32> &seed, int *cancel,
      std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>> reltup);
private:
  void
  relayRequest();
  void
  relaySrv();
  void
  relaySrvThread(std::mutex *thrmtx, int relaysock);
  void
  relayRequestThread(std::mutex *thrmtx);
#ifdef _WIN32
  int
  poll (struct pollfd *pfd, int nfds, int timeout);
#endif
  void
  srvOperations(int sock);
  void
  msgProcOperations(int sock);
  bool
  establishConnect(
      int sock,
      std::tuple<int, std::array<char, 32>, std::array<char, 32>> *res);
  void
  receiveRP(int sock,
	    std::tuple<int, std::array<char, 32>, std::array<char, 32>> ttup,
	    std::vector<char> &buf, std::array<char, 32> &seed);
  void
  closeSockOp(int sock, std::string msg);
  std::vector<char>
  addMsgSize(std::vector<char> &msg);
  int
  sendMsg(int sock, std::vector<char> &msg);
  int
  receiveMsgs(std::vector<char> &buf, std::vector<std::vector<char>> *msgbuf);

  uint32_t ipbindto = INADDR_ANY;
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int>> *getfrres =
      nullptr;
  std::mutex *getfrresmtx = nullptr;
  std::vector<
      std::tuple<uint32_t, uint16_t, time_t, std::shared_ptr<std::mutex>>> *relayaddr =
      nullptr; //0-ip, 1-port, 2-time checked
  std::mutex *relayaddrmtx = nullptr;
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t>> *frrelays =
      nullptr;
  std::mutex *frrelaysmtx = nullptr;
  std::string enable_relay_srv = "disabled";
  std::vector<std::tuple<std::mutex*, std::string>> *threadvect = nullptr;
  std::mutex *threadvectmtx = nullptr;
  uint16_t relayport = htons(3029);
  int *cancel = nullptr;
  std::vector<std::tuple<uint32_t, uint16_t>> userrelaylist;

  std::vector<std::tuple<int, std::array<char, 32>, std::array<char, 32>>> keyvect; //0-socket, 1-own seed, 2-opponent key
  std::mutex keyvectmtx;

  std::vector<
      std::tuple<std::array<char, 32>, std::array<char, 32>, std::vector<char>,
	  std::array<char, 64>, time_t>> relayvect; //0-destination key, 1-key from, 2-msg, 3-signature, 4-time rcvd
  std::mutex relayvectmtx;

  std::vector<std::array<char, 32>> *sendbyrelay = nullptr;
  std::mutex *sendbyrelaymtx = nullptr;
};

#endif /* SRC_RELAYOPERATIONS_H_ */
