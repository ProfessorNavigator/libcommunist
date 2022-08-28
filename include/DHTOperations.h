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

#ifndef DHTOPERATIONS_H_
#define DHTOPERATIONS_H_
#include <vector>
#include <mutex>
#include <thread>
#include <filesystem>
#include <string>
#include <sstream>
#include <libtorrent/session.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/alert.hpp>
#include <libtorrent/session_handle.hpp>
#include <libtorrent/session_params.hpp>
#include "AuxFuncNet.h"
#include "NetworkOperations.h"

class NetworkOperations;

class DHTOperations
{
public:
  DHTOperations (NetworkOperations *No);
  virtual
  ~DHTOperations ();
  void
  processDHT ();
private:
  std::vector<std::array<char, 32>>
  getFrVect ();

  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>>
  putVect ();

  std::array<char, 32>
  getSes (std::array<char, 32> key, lt::session *ses, bool relay);

  std::array<char, 32>
  getSes6 (std::array<char, 32> key, lt::session *ses);

  std::array<char, 32>
  putSes (std::array<char, 32> otherkey, uint32_t ip, uint16_t port,
	  lt::session *ses, bool relay);

  std::array<char, 32>
  putSes6 (std::array<char, 32> otherkey, lt::session *ses);

  void
  getvResult (std::array<char, 32> key, uint32_t ip, uint16_t port, int seq);

  void
  getvResult6 (std::array<char, 32> key, std::string ip, uint16_t port,
	       int seq);

  void
  dhtThread (std::mutex *thrmtx);

  void
  rcvRelay (
      std::array<char, 32> key,
      int64_t seq,
      std::string msg,
      std::vector<std::tuple<std::array<char, 32>, std::array<char, 32>>> &getvinner);

  void
  formRelayPut (
      std::vector<std::tuple<std::array<char, 32>, time_t, time_t>> *relayputinner);
  NetworkOperations *no = nullptr;
};

#endif /* DHTOPERATIONS_H_ */
