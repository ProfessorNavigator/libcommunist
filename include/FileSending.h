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

#ifndef SRC_FILESENDING_H_
#define SRC_FILESENDING_H_

#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <mutex>
#include "NetworkOperations.h"
#include "AuxFuncNet.h"

class NetworkOpearations;

class FileSending
{
public:
  FileSending(NetworkOperations *No);
  virtual
  ~FileSending();
  int
  fileSending(std::filesystem::path pvect, std::array<char, 32> keyarr,
	      int variant, int sock, uint32_t ip, uint16_t port, int *totalsent,
	      bool relay);
private:
  NetworkOperations *no = nullptr;
  std::vector<std::vector<char>> filerelsending;
};

#endif /* SRC_FILESENDING_H_ */
