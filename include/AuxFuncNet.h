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

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <gcrypt.h>
#include <zip.h>
#include <libtorrent/kademlia/ed25519.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/bencode.hpp>
#include <libtorrent/kademlia/item.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/hex.hpp>
#include <iostream>
#include "OutAuxFunc.h"

#ifndef SRC_LIBCOMMUNIST_AUXFUNCNET_H_
#define SRC_LIBCOMMUNIST_AUXFUNCNET_H_

class AuxFuncNet
{
public:
  AuxFuncNet ();
  virtual
  ~AuxFuncNet ();
  void
  cryptFile (std::string Username, std::string Password, std::string infile,
	     std::string outfile);
  std::vector<char>
  cryptStrm (std::string Username, std::string Password,
	     std::vector<char> &input);
  void
  decryptFile (std::string Username, std::string Password, std::string infile,
	       std::string outfile);
  std::vector<char>
  decryptStrm (std::string Username, std::string Password,
	       std::vector<char> &input);
  int
  packing (std::string source, std::string out);
  int
  unpacking (std::string archadress, std::string outfolder);
  void
  put_string (lt::entry &e, std::array<char, 64> &sig, std::int64_t &seq,
	      std::string const &salt, std::array<char, 32> const &pk,
	      std::array<char, 64> const &sk, std::string str);
  std::vector<char>
  filehash (std::filesystem::path filepath);
  std::vector<char>
  strhash (std::vector<char> &th, int type);
  void
  updateMsgLog (std::string homepath, std::string Username,
		std::string Password, std::array<char, 32> keyarr, std::string msgname,
		std::vector<std::tuple<int, std::array<char, 32>>> &contacts);
private:
  int
  fileNames (std::string adress, std::vector<std::string> &filenames);
};

#endif /* SRC_LIBCOMMUNIST_AUXFUNCNET_H_ */
