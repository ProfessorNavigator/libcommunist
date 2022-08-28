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

#ifndef SRC_MSGPROFILERECEIVE_H_
#define SRC_MSGPROFILERECEIVE_H_

#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <mutex>
#include "NetworkOperations.h"
#include "AuxFuncNet.h"

class NetworkOperations;

class MsgProfileReceive
{
public:
  MsgProfileReceive (NetworkOperations *No);
  virtual
  ~MsgProfileReceive ();
  void
  msgMBPB (std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	   sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	   std::vector<char> &buf, bool relay);
  void
  msgMbPb (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  msgMpPp (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  msgMePe (std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	   sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	   std::vector<char> &buf, bool relay);
  void
  msgMEPE (std::string msgtype, std::array<char, 32> keyarr, int rcvip6,
	   sockaddr_in6 *from6, sockaddr_in *from, int sockipv4,
	   std::vector<char> &buf, bool relay);
  void
  msgMAPA (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  msgMrPr (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  msgMRPR (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
  void
  msgMIPI (std::string msgtype, std::array<char, 32> keyarr,
	   std::vector<char> &buf);
private:
  NetworkOperations *no = nullptr;
  int
  msgMe (std::array<char, 32> keyarr, uint64_t tm, uint64_t partnum);
  int
  msgPe (std::array<char, 32> keyarr, uint64_t tm, uint64_t partnum);
  int
  msgME (std::array<char, 32> keyarr, uint64_t tm);
  int
  msgPE (std::array<char, 32> keyarr, uint64_t tm);
};

#endif /* SRC_MSGPROFILERECEIVE_H_ */
