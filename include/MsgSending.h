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

#ifndef SRC_MSGSENDING_H_
#define SRC_MSGSENDING_H_

#include <iostream>
#include <vector>
#include <string>
#include <tuple>
#include <filesystem>
#include "NetworkOperations.h"
#include "AuxFuncNet.h"

class NetworkOperations;

class MsgSending
{
public:
  MsgSending(NetworkOperations *No);
  virtual
  ~MsgSending();
  int
  sendMsg(std::filesystem::path pvect, std::array<char, 32> keyarr, int variant,
	  int sock, uint32_t ip, uint16_t port, bool relay);
private:
  NetworkOperations *no = nullptr;
  std::vector<std::vector<char>> msgtorelay;
};

#endif /* SRC_MSGSENDING_H_ */
