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

#ifndef SRC_FILERECEIVEOP_H_
#define SRC_FILERECEIVEOP_H_

#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include "NetworkOperations.h"
#include "AuxFuncNet.h"

class NetworkOperations;

class FileReceiveOp
{
public:
  FileReceiveOp(NetworkOperations *No);
  virtual
  ~FileReceiveOp();
  void
  fileProcessing(std::string msgtype, std::array<char, 32> keyarr, int ip6check,
		 int sockipv, sockaddr_in *from, sockaddr_in6 *from6,
		 bool relay);
  void
  fileFQ(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFJ(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFA(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFr(std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	 sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	 std::vector<char> &buf, bool relay);
  void
  fileFRFI(std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  fileFB(std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	 sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	 std::vector<char> &buf, bool relay);
  void
  fileFH(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFb(std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	 sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	 std::vector<char> &buf, bool relay);
  void
  fileFp(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFe(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFE(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
  void
  fileFF(std::string msgtype, std::array<char, 32> keyarr,
	 std::vector<char> &buf);
private:
  void
  filePrFp(std::array<char, 32> key, int rcvip6, bool relay, int sockipv,
	   sockaddr_in *from, sockaddr_in6 *from6);
  void
  filePrFe(std::array<char, 32> key, int rcvip6, bool relay, int sockipv,
	   sockaddr_in *from, sockaddr_in6 *from6);
  void
  filePrFE(std::array<char, 32> key, int rcvip6, bool relay, int sockipv,
	   sockaddr_in *from, sockaddr_in6 *from6, std::string index);
  void
  sendMsg(std::array<char, 32> key, std::string mtype, uint64_t tint,
	  uint64_t numb, int rcvip6, bool relay, int sockipv, sockaddr_in *from,
	  sockaddr_in6 *from6);

  NetworkOperations *no = nullptr;
};

#endif /* SRC_FILERECEIVEOP_H_ */
