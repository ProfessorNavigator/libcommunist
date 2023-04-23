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

#ifndef SRC_LOCALNETWORKOP_H_
#define SRC_LOCALNETWORKOP_H_

#include <iostream>
#include <vector>
#include <tuple>
#include <string>
#include <mutex>
#include "NetworkOperations.h"

class NetworkOperations;

class LocalNetworkOp
{
public:
  LocalNetworkOp(NetworkOperations *No);
  virtual
  ~LocalNetworkOp();
private:
  void
  bootstrFunc();
  NetworkOperations *no = nullptr;
};

#endif /* SRC_LOCALNETWORKOP_H_ */
