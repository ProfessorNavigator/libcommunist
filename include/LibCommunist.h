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

#ifndef INCLUDE_LIBCOMMUNIST_H_
#define INCLUDE_LIBCOMMUNIST_H_

#include <string>
#include <vector>
#include <array>
#include <filesystem>
#include <tuple>
#include <NetOperationsComm.h>

class LibCommunist
{
public:
  LibCommunist ();
  virtual
  ~LibCommunist ();
  std::array<char, 32>
  seedGenerate ();
  std::string
  getKeyFmSeed (std::array<char, 32> &seed);
  std::string
  getSecreteKeyFmSeed (std::array<char, 32> &seed);
  std::string
  genPasswd (std::string key, std::array<char, 32> &seed);
  std::string
  genFriendPasswd (std::string key, std::array<char, 32> &seed);
  int
  createProfile (std::string Username, std::string Password,
		 std::string homepath,
		 std::vector<std::tuple<std::string, std::string>> &profvect,
		 std::array<char, 32> &seed);
  int
  openProfile (std::string homepath, std::string Username, std::string Password,
	       std::string outfoldername);
  int
  editProfile (
      std::string Username, std::string Password, std::string homepath,
      std::vector<std::tuple<std::string, std::vector<char>>> &profvect);
  std::vector<std::tuple<int, std::string>>
  readContacts (std::string homepath, std::string Username,
		std::string Password);
  std::vector<std::string>
  readRequestList (std::string homepath, std::string Username,
		   std::string Password);
  std::string
  getContactMsgLog (std::string homepath, std::string Username,
		    std::string Password, int contind,
		    std::string outfolderpath);
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
  int
  openFriendProfile (std::string homepath, std::string Username,
		     std::string Password, std::string friendkey,
		     std::string outfoldername);
  void
  msgAutoRemove (std::string homepath, std::string Username,
		 std::string Password, std::string mode);
  std::vector<std::tuple<std::string, std::vector<char>>>
  readProfile (std::string homepath, std::string Username,
	       std::string Password);
  std::vector<std::tuple<std::string, std::vector<char>>>
  readFriendProfile (std::string homepath, std::string friendkey,
		     std::string Username, std::string Password);
  int
  readSeed (std::string homepath, std::string Username, std::string Password,
	    std::array<char, 32> &seed);
  std::string
  openMessage (std::filesystem::path msgpath, std::string friendkey,
	       std::string Username, std::string Password);
  std::vector<std::filesystem::path>
  listMessages (std::string homepath, std::string key, std::string Username,
		std::string Password);
  std::vector<std::string>
  readRelayContacts (std::string homepath, std::string Username,
		     std::string Password);
  std::string
  randomFileName ();
private:
  std::string
  parseMsgVect (std::vector<std::string> &msgvect);
};

#endif /* INCLUDE_LIBCOMMUNIST_H_ */
