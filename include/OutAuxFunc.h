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

#ifndef INCLUDE_OUTAUXFUNC_H_
#define INCLUDE_OUTAUXFUNC_H_

#include <string>
#include <array>
#include <chrono>
#include <vector>
#include <tuple>
#include "AuxFuncNet.h"

class OutAuxFunc
{
public:
  OutAuxFunc();
  virtual
  ~OutAuxFunc();
  std::array<char, 32>
  seedGenerate();
  std::string
  getKeyFmSeed(std::array<char, 32> &seed);
  std::string
  getSecreteKeyFmSeed(std::array<char, 32> &seed);
  std::string
  genPasswd(std::string key, std::array<char, 32> &seed);
  std::string
  genFriendPasswd(std::string key, std::array<char, 32> &seed);
  int
  createProfile(std::string Username, std::string Password,
		std::string homepath,
		std::vector<std::tuple<std::string, std::string>> &profvect,
		std::array<char, 32> &seed);
  int
  openProfile(std::string homepath, std::string Username, std::string Password,
	      std::string outfoldername);
  int
  editProfile(std::string Username, std::string Password, std::string homepath,
	      std::vector<std::tuple<std::string, std::vector<char>>> &profvect,
	      std::array<char, 32> &seed,
	      std::vector<std::tuple<int, std::string>> &contacts,
	      std::vector<std::string> &Addfriends,
	      std::vector<std::string> &relaycontlist);
  std::vector<std::tuple<int, std::string>>
  readContacts(std::string homepath, std::string Username,
	       std::string Password);
  std::vector<std::string>
  readRequestList(std::string homepath, std::string Username,
		  std::string Password);
  std::string
  getContactMsgLog(std::string homepath, std::string Username,
		   std::string Password, int contind,
		   std::string outfolderpath);
  int
  openFriendProfile(std::string homepath, std::array<char, 32> &seed,
		    std::string friendkey, int ind, std::string outfoldername);
  void
  msgAutoRemove(std::string homepath, std::string Username,
		std::string Password, std::string mode);
  std::vector<std::tuple<std::string, std::vector<char>>>
  readProfile(std::string homepath, std::string Username, std::string Password);
  std::vector<std::tuple<std::string, std::vector<char>>>
  readFriendProfile(std::string homepath, std::array<char, 32> &seed,
		    std::string friendkey,
		    std::vector<std::tuple<int, std::string>> &contacts);
  int
  readSeed(std::string homepath, std::string Username, std::string Password,
	   std::array<char, 32> &seed);
  std::string
  openFriendMsg(std::filesystem::path msgpath, std::string friendkey,
		std::array<char, 32> &seed);
  std::string
  openOwnMsg(std::filesystem::path msgpath, std::string friendkey,
	     std::array<char, 32> &seed);
  std::vector<std::filesystem::path>
  listMessages(std::string homepath, std::string key,
	       std::vector<std::tuple<int, std::string>> &contacts);
  std::vector<std::string>
  readRelayContacts(std::string homepath, std::string Username,
		    std::string Password);
  std::string
  randomFileName();
};

#endif /* INCLUDE_OUTAUXFUNC_H_ */
