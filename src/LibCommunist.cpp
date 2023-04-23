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

#include <LibCommunist.h>
#include "AuxFuncNet.h"
#include "OutAuxFunc.h"

LibCommunist::LibCommunist()
{
  // TODO Auto-generated constructor stub

}

LibCommunist::~LibCommunist()
{
  // TODO Auto-generated destructor stub
}

std::array<char, 32>
LibCommunist::seedGenerate()
{
  OutAuxFunc oaf;
  return oaf.seedGenerate();
}

std::string
LibCommunist::getKeyFmSeed(std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.getKeyFmSeed(seed);
}

std::string
LibCommunist::getSecreteKeyFmSeed(std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.getSecreteKeyFmSeed(seed);
}

std::string
LibCommunist::genPasswd(std::string key, std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.genPasswd(key, seed);
}

std::string
LibCommunist::genFriendPasswd(std::string key, std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.genFriendPasswd(key, seed);
}

int
LibCommunist::createProfile(
    std::string Username, std::string Password, std::string homepath,
    std::vector<std::tuple<std::string, std::string>> &profvect,
    std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.createProfile(Username, Password, homepath, profvect, seed);
}

int
LibCommunist::openProfile(std::string homepath, std::string Username,
			  std::string Password, std::string outfoldername)
{
  OutAuxFunc oaf;
  return oaf.openProfile(homepath, Username, Password, outfoldername);
}

int
LibCommunist::editProfile(
    std::string Username, std::string Password, std::string homepath,
    std::vector<std::tuple<std::string, std::vector<char>>> &profvect)
{
  OutAuxFunc oaf;
  std::array<char, 32> seed;
  oaf.readSeed(homepath, Username, Password, seed);
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(homepath, Username, Password);
  std::vector<std::string> Addfriends;
  Addfriends = oaf.readRequestList(homepath, Username, Password);
  std::vector<std::string> relaycontlist;
  relaycontlist = oaf.readRelayContacts(homepath, Username, Password);
  return oaf.editProfile(Username, Password, homepath, profvect, seed, contacts,
			 Addfriends, relaycontlist);
}

std::vector<std::tuple<int, std::string>>
LibCommunist::readContacts(std::string homepath, std::string Username,
			   std::string Password)
{
  OutAuxFunc oaf;
  return oaf.readContacts(homepath, Username, Password);
}

std::vector<std::string>
LibCommunist::readRequestList(std::string homepath, std::string Username,
			      std::string Password)
{
  OutAuxFunc oaf;
  return oaf.readRequestList(homepath, Username, Password);
}

std::vector<std::string>
LibCommunist::readRelayContacts(std::string homepath, std::string Username,
				std::string Password)
{
  OutAuxFunc oaf;
  return oaf.readRelayContacts(homepath, Username, Password);
}

std::string
LibCommunist::getContactMsgLog(std::string homepath, std::string Username,
			       std::string Password, int contind,
			       std::string outfolderpath)
{
  OutAuxFunc oaf;
  return oaf.getContactMsgLog(homepath, Username, Password, contind,
			      outfolderpath);
}

void
LibCommunist::cryptFile(std::string Username, std::string Password,
			std::string infile, std::string outfile)
{
  AuxFuncNet afn;
  afn.cryptFile(Username, Password, infile, outfile);
}

std::vector<char>
LibCommunist::cryptStrm(std::string Username, std::string Password,
			std::vector<char> &input)
{
  AuxFuncNet afn;
  return afn.cryptStrm(Username, Password, input);
}

void
LibCommunist::decryptFile(std::string Username, std::string Password,
			  std::string infile, std::string outfile)
{
  AuxFuncNet afn;
  afn.decryptFile(Username, Password, infile, outfile);
}

std::vector<char>
LibCommunist::decryptStrm(std::string Username, std::string Password,
			  std::vector<char> &input)
{
  AuxFuncNet afn;
  return afn.decryptStrm(Username, Password, input);
}

int
LibCommunist::packing(std::string source, std::string out)
{
  AuxFuncNet afn;
  return afn.packing(source, out);
}

int
LibCommunist::unpacking(std::string archadress, std::string outfolder)
{
  AuxFuncNet afn;
  return afn.unpacking(archadress, outfolder);
}

int
LibCommunist::openFriendProfile(std::string homepath, std::string Username,
				std::string Password, std::string friendkey,
				std::string outfoldername)
{
  OutAuxFunc oaf;
  std::array<char, 32> seed;
  oaf.readSeed(homepath, Username, Password, seed);
  int ind = -1;
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(homepath, Username, Password);
  auto itcont = std::find_if(contacts.begin(), contacts.end(), [friendkey]
  (auto &el) 
    {
      return std::get<1>(el) == friendkey;
    });
  if(itcont != contacts.end())
    {
      ind = std::get<0>(*itcont);
    }
  return oaf.openFriendProfile(homepath, seed, friendkey, ind, outfoldername);
}

void
LibCommunist::msgAutoRemove(std::string homepath, std::string Username,
			    std::string Password, std::string mode)
{
  OutAuxFunc oaf;
  oaf.msgAutoRemove(homepath, Username, Password, mode);
}

std::vector<std::tuple<std::string, std::vector<char>>>
LibCommunist::readProfile(std::string homepath, std::string Username,
			  std::string Password)
{
  OutAuxFunc oaf;
  return oaf.readProfile(homepath, Username, Password);
}

int
LibCommunist::readSeed(std::string homepath, std::string Username,
		       std::string Password, std::array<char, 32> &seed)
{
  OutAuxFunc oaf;
  return oaf.readSeed(homepath, Username, Password, seed);
}

std::vector<std::tuple<std::string, std::vector<char>>>
LibCommunist::readFriendProfile(std::string homepath, std::string friendkey,
				std::string Username, std::string Password)
{
  OutAuxFunc oaf;
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(homepath, Username, Password);
  std::array<char, 32> seed;
  oaf.readSeed(homepath, Username, Password, seed);
  return oaf.readFriendProfile(homepath, seed, friendkey, contacts);
}

std::string
LibCommunist::openMessage(std::filesystem::path msgpath, std::string friendkey,
			  std::string Username, std::string Password)
{
  std::string result = "Error";
  OutAuxFunc oaf;
  std::array<char, 32> seed;
  std::string homepath =
      msgpath.parent_path().parent_path().parent_path().u8string();
  oaf.readSeed(homepath, Username, Password, seed);
  std::filesystem::path filepath = std::filesystem::u8path(
      oaf.openOwnMsg(msgpath, friendkey, seed));
  std::fstream f;
  std::vector<std::string> msgvect;
  std::string ownkey = oaf.getKeyFmSeed(seed);
  if(std::filesystem::exists(filepath))
    {
      f.open(filepath, std::ios_base::in);
      if(f.is_open())
	{
	  while(!f.eof())
	    {
	      std::string line;
	      getline(f, line);
	      if(!line.empty())
		{
		  msgvect.push_back(line);
		}
	    }
	  f.close();
	}
    }
  std::filesystem::remove_all(filepath);
  if(msgvect.size() > 0)
    {
      std::string line = msgvect[0];
      std::string::size_type n;
      n = line.find(ownkey);
      if(n != std::string::npos)
	{
	  result = parseMsgVect(msgvect);
	}
      else
	{
	  msgvect.clear();
	  filepath = std::filesystem::u8path(
	      oaf.openFriendMsg(msgpath, friendkey, seed));
	  f.open(filepath, std::ios_base::in);
	  if(f.is_open())
	    {
	      while(!f.eof())
		{
		  line.clear();
		  getline(f, line);
		  if(!line.empty())
		    {
		      msgvect.push_back(line);
		    }
		}
	      f.close();
	    }
	  std::filesystem::remove_all(filepath);
	  if(msgvect.size() > 0)
	    {
	      line = msgvect[0];
	      n = line.find(friendkey);
	      if(n != std::string::npos)
		{
		  result = parseMsgVect(msgvect);
		}
	    }
	}
    }
  return result;
}

std::string
LibCommunist::parseMsgVect(std::vector<std::string> &msgvect)
{
  std::string result = "Error";
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path().u8string();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  OutAuxFunc oaf;
  filename = filename + "/" + oaf.randomFileName() + "msg";
  std::filesystem::path filepath = std::filesystem::u8path(filename);
  if(std::filesystem::exists(filepath))
    {
      std::filesystem::remove_all(filepath);
    }
  std::fstream f;
  f.open(filepath, std::ios_base::out | std::ios_base::binary);
  for(size_t i = 0; i < msgvect.size(); i++)
    {
      std::string line = msgvect[i];
      std::string::size_type n;
      if(i == 0)
	{
	  n = line.find(" ");
	  if(n != std::string::npos)
	    {
	      std::string resnm = line.substr(0, n);
	      std::string key = line;
	      key.erase(0, key.find(" ") + std::string(" ").size());
	      key = "From: " + key + "\n";
	      f.write(key.c_str(), key.size());
	      resnm = "Resend from: " + resnm + "\n";
	      f.write(resnm.c_str(), resnm.size());
	    }
	  else
	    {
	      std::string resnm = "Resend from:\n";
	      std::string key = line;
	      key = "From: " + key + "\n";
	      f.write(key.c_str(), key.size());
	      f.write(resnm.c_str(), resnm.size());
	    }
	}
      if(i == 1)
	{
	  std::string to = line;
	  to = "To: " + to + "\n";
	  f.write(to.c_str(), to.size());
	}
      if(i == 2)
	{
	  std::string date = line;
	  date = "Creation time: " + date + "\n";
	  f.write(date.c_str(), date.size());
	}
      if(i == 3)
	{
	  std::string type = line;
	  if(type == "0")
	    {
	      type = "Type: text message\n";
	      f.write(type.c_str(), type.size());
	    }
	  if(type == "1")
	    {
	      type = "Type: file message\n";
	      f.write(type.c_str(), type.size());
	    }
	}
      if(i == 4)
	{
	  std::string repl = line;
	  n = repl.find(" ");
	  if(n != std::string::npos)
	    {
	      repl = repl.erase(0, n + std::string(" ").size());
	      repl = "Reply to: " + repl + "\n";
	    }
	  else
	    {
	      repl = "Reply to:\n";
	    }
	  f.write(repl.c_str(), repl.size());
	}
      if(i == 5)
	{
	  std::string msg = line;
	  msg = "Message:\n" + msg + "\n";
	  f.write(msg.c_str(), msg.size());
	}
    }
  f.close();
  result = filepath.u8string();
  return result;
}

std::vector<std::filesystem::path>
LibCommunist::listMessages(std::string homepath, std::string key,
			   std::string Username, std::string Password)
{
  OutAuxFunc oaf;
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(homepath, Username, Password);
  return oaf.listMessages(homepath, key, contacts);
}

std::string
LibCommunist::randomFileName()
{
  OutAuxFunc oaf;
  return oaf.randomFileName();
}
