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

#include <NetOperationsComm.h>
#include <NetworkOperations.h>
#include <OutAuxFunc.h>

NetworkOperations *nop = nullptr;

NetOperationsComm::NetOperationsComm()
{
  // TODO Auto-generated constructor stub

}

NetOperationsComm::~NetOperationsComm()
{
  delete nop;
  nop = nullptr;
}

NetOperationsComm*
NetOperationsComm::create_object()
{
  NetOperationsComm *noc = new NetOperationsComm;
  return noc;
}

void
NetOperationsComm::setPrefVector(
    std::vector<std::tuple<std::string, std::string>> &prefvect)
{
  this->prefvect = prefvect;
}

void
NetOperationsComm::setUsernamePasswd(std::string Username, std::string Password)
{
  this->Username = Username;
  this->Password = Password;
}

void
NetOperationsComm::setHomePath(std::string homepath)
{
  Home_Path = homepath;
}

void
NetOperationsComm::setStunListPath(std::string path)
{
  Stun_Path = path;
}

void
NetOperationsComm::startNetOperations()
{
  std::vector<std::tuple<int, std::string>> contacts;
  OutAuxFunc oaf;
  contacts = oaf.readContacts(Home_Path, Username, Password);
  std::vector<std::string> Addfriends;
  Addfriends = oaf.readRequestList(Home_Path, Username, Password);
  std::array<char, 32> seed;
  oaf.readSeed(Home_Path, Username, Password, seed);
  nop = new NetworkOperations(Username, Password, contacts, seed, Addfriends,
			      prefvect, Stun_Path, Home_Path);
  nop->canceled = net_op_canceled_signal;
  nop->messageReceived = messageReceived_signal;
  nop->profReceived = [this]
  (std::string key, int ind) 
    {
      this->profRcvd(key, ind);
      if (this->profReceived_signal)
	{
	  this->profReceived_signal(key, ind);
	}
    };
  nop->msgSent = msgSent_signal;
  nop->filerequest = filerequest_signal;
  nop->fileRejected = fileRejected_signal;
  nop->filehasherr = filehasherr_signal;
  nop->filercvd = filercvd_signal;
  nop->filesentsig = filesent_signal;
  nop->filesenterror = filesenterror_signal;
  nop->ipv6signal = ipv6_signal;
  nop->ipv4signal = ipv4_signal;
  nop->ipv6signalfinished = ipv6finished_signal;
  nop->ipv4signalfinished = ipv4finished_signal;
  nop->filepartrcvdsig = filepartrcvd_signal;
  nop->filepartsendsig = filepartsend_signal;
  nop->smthrcvdsig = smthrcvd_signal;
  nop->friendDeleted = friendDeleted_signal;
  nop->friendDelPulse = friendDelPulse_signal;
  nop->friendBlockedSig = friendBlocked_signal;
  std::vector<std::string> relvect;
  relvect = oaf.readRelayContacts(Home_Path, Username, Password);
  editContByRelay(relvect);

  nop->mainFunc();
}

void
NetOperationsComm::getNewFriends(std::string key)
{
  OutAuxFunc oaf;
  std::vector<std::tuple<std::string, std::vector<char>>> profvect;
  profvect = oaf.readProfile(Home_Path, Username, Password);
  std::array<char, 32> seed;
  oaf.readSeed(Home_Path, Username, Password, seed);
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(Home_Path, Username, Password);
  std::vector<std::string> relaycontlist;
  relaycontlist = oaf.readRelayContacts(Home_Path, Username, Password);
  std::vector<std::string> Addfriends;
  Addfriends = oaf.readRequestList(Home_Path, Username, Password);
  auto it = std::find(Addfriends.begin(), Addfriends.end(), key);
  if(it == Addfriends.end())
    {
      Addfriends.push_back(key);
    }
  oaf.editProfile(Username, Password, Home_Path, profvect, seed, contacts,
		  Addfriends, relaycontlist);
  if(nop)
    {
      nop->getNewFriends(key);
    }
  else
    {
      std::cerr << "Net object (getNewFriends) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::removeFriend(std::string key)
{
  if(nop)
    {
      nop->removeFriend(key);
    }
  else
    {
      std::cerr << "Net object (removeFriend) does not exist!" << std::endl;
      contDelFunc(key);
      if(friendDeleted_signal)
	{
	  friendDeleted_signal(key);
	}
    }
}

bool
NetOperationsComm::checkIfMsgSent(std::filesystem::path p)
{
  bool chk = true;
  if(nop)
    {
      chk = nop->checkIfMsgSent(p);
    }
  else
    {
      std::cerr << "Net object (checkIfMsgSent) does not exist!" << std::endl;
    }
  return chk;
}

std::filesystem::path
NetOperationsComm::sendMessage(std::string key, std::string nick,
			       std::string replstr,
			       std::filesystem::path msgpath)
{
  std::filesystem::path result = std::filesystem::u8path("Error");
  if(nop)
    {
      result = nop->formMsg(key, nick, replstr, msgpath, 0);
    }
  else
    {
      std::cerr << "Net object (sendMessage (file path)) does not exist"
	  << std::endl;
    }
  return result;
}

std::filesystem::path
NetOperationsComm::sendMessage(std::string key, std::string nick,
			       std::string replstr, std::string msgstring)
{
  std::filesystem::path result = std::filesystem::u8path("Error");
  if(nop)
    {
      result = nop->formMsg(key, nick, replstr, msgstring, 0);
    }
  else
    {
      std::cerr << "Net object (sendMessage (string)) does not exist"
	  << std::endl;
    }
  return result;
}

std::filesystem::path
NetOperationsComm::sendFile(std::string key, std::string nick,
			    std::string replstr, std::string pathtofile)
{
  std::filesystem::path result = std::filesystem::u8path("Error");
  if(nop)
    {
      result = nop->formMsg(key, nick, replstr, pathtofile, 1);
    }
  else
    {
      std::cerr << "Net object (sendMessage (string)) does not exist"
	  << std::endl;
    }
  return result;
}

void
NetOperationsComm::renewProfile(std::string key)
{
  if(nop)
    {
      nop->renewProfile(key);
    }
  else
    {
      std::cerr << "Net object (renewProfile) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::fileReject(std::string key, uint64_t tm)
{
  if(nop)
    {
      nop->fileReject(key, tm);
    }
  else
    {
      std::cerr << "Net object (fileReject) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::fileAccept(std::string key, uint64_t tm,
			      std::filesystem::path sp)
{
  if(nop)
    {
      nop->fileAccept(key, tm, sp, false);
    }
  else
    {
      std::cerr << "Net object (fileAccept) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::startFriend(std::string key, int ind)
{
  if(nop)
    {
      nop->startFriend(key, ind);
    }
  else
    {
      std::cerr << "Net object (startFriend) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::blockFriend(std::string key)
{
  if(nop)
    {
      nop->blockFriend(key);
    }
  else
    {
      std::cerr << "Net object (blockFriend) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::setIPv6(std::string ip)
{
  if(nop)
    {
      nop->setIPv6(ip);
    }
  else
    {
      std::cerr << "Net object (setIPv6) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::setIPv4(std::string ip)
{
  if(nop)
    {
      nop->setIPv4(ip);
    }
  else
    {
      std::cerr << "Net object (setIPv4) does not exist!" << std::endl;
    }
}

std::filesystem::path
NetOperationsComm::removeMsg(std::string key, std::filesystem::path msgpath)
{
  if(nop)
    {
      return nop->removeMsg(key, msgpath);
    }
  else
    {
      std::cerr << "Net object (removeMsg) does not exist!" << std::endl;
      return std::filesystem::u8path("Error!");
    }
}

void
NetOperationsComm::cancelSendFile(std::string key,
				  std::filesystem::path filepath)
{
  if(nop)
    {
      nop->cancelSendF(key, filepath);
    }
  else
    {
      std::cerr << "Net object (cancelSendFile) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::cancelReceivFile(std::string key,
				    std::filesystem::path filepath)
{
  if(nop)
    {
      nop->cancelReceivF(key, filepath);
    }
  else
    {
      std::cerr << "Net object (cancelReceivFile) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::cancelNetOperations()
{
  if(nop)
    {
      nop->cancelAll();
    }
  else
    {
      std::cerr << "Net object (cancelNetOperations) does not exist!"
	  << std::endl;
    }
}

void
NetOperationsComm::editContByRelay(std::vector<std::string> &sendbyrel)
{
  if(nop)
    {
      OutAuxFunc oaf;
      std::vector<std::tuple<std::string, std::vector<char>>> profvect;
      profvect = oaf.readProfile(Home_Path, Username, Password);
      std::array<char, 32> seed;
      oaf.readSeed(Home_Path, Username, Password, seed);
      std::vector<std::tuple<int, std::string>> contacts;
      contacts = oaf.readContacts(Home_Path, Username, Password);
      std::vector<std::string> Addfriends;
      Addfriends = oaf.readRequestList(Home_Path, Username, Password);
      oaf.editProfile(Username, Password, Home_Path, profvect, seed, contacts,
		      Addfriends, sendbyrel);
      nop->editContByRelay(sendbyrel);
    }
  else
    {
      std::cerr << "Net object (editContByRelay) does not exist!" << std::endl;
    }
}

void
NetOperationsComm::cleanMemory(NetOperationsComm *noc)
{
  if(noc)
    {
      delete noc;
      noc = nullptr;
    }
}

void
NetOperationsComm::profRcvd(std::string key, int ind)
{
  OutAuxFunc oaf;
  std::vector<std::tuple<std::string, std::vector<char>>> profvect;
  profvect = oaf.readProfile(Home_Path, Username, Password);
  std::array<char, 32> seed;
  oaf.readSeed(Home_Path, Username, Password, seed);
  std::vector<std::tuple<int, std::string>> contacts;
  contacts = oaf.readContacts(Home_Path, Username, Password);
  auto itcont = std::find_if(contacts.begin(), contacts.end(), [key]
  (auto &el) 
    {
      return std::get<1>(el) == key;
    });
  if(itcont == contacts.end())
    {
      std::tuple<int, std::string> ttup;
      std::get<0>(ttup) = ind;
      std::get<1>(ttup) = key;
      contacts.push_back(ttup);
    }
  std::vector<std::string> relvect;
  relvect = oaf.readRelayContacts(Home_Path, Username, Password);
  std::vector<std::string> Addfriends;
  Addfriends = oaf.readRequestList(Home_Path, Username, Password);
  Addfriends.erase(std::remove(Addfriends.begin(), Addfriends.end(), key),
		   Addfriends.end());
  oaf.editProfile(Username, Password, Home_Path, profvect, seed, contacts,
		  Addfriends, relvect);
}

void
NetOperationsComm::contDelFunc(std::string key)
{
  std::string keyloc = key;
  OutAuxFunc oaf;
  std::vector<std::tuple<int, std::string>> contactsfull;
  contactsfull = oaf.readContacts(Home_Path, Username, Password);
  auto contit = std::find_if(contactsfull.begin(), contactsfull.end(), [&keyloc]
  (auto &el) 
    {
      return std::get<1>(el) == keyloc;
    });
  if(contit != contactsfull.end())
    {
      std::stringstream strm;
      std::locale loc("C");
      strm.imbue(loc);
      std::string index;
      strm << std::get<0>(*contit);
      index = strm.str();
      std::string filename = Home_Path;
      filename = filename + "/.Communist/SendBufer/" + index;
      std::filesystem::path filepath = std::filesystem::u8path(filename);
      if(std::filesystem::exists(filepath))
	{
	  std::filesystem::remove_all(filepath);
	}

      std::string line;
      int indep = std::get<0>(*contit);
      filename = Home_Path;
      filename = filename + "/.Communist/SendBufer";
      std::filesystem::path folderpath = std::filesystem::u8path(filename);
      std::vector<std::filesystem::path> pathvect;
      if(std::filesystem::exists(folderpath))
	{
	  for(auto &dir : std::filesystem::directory_iterator(folderpath))
	    {
	      std::filesystem::path old = dir.path();
	      pathvect.push_back(old);
	    }
	  std::sort(pathvect.begin(), pathvect.end(), []
	  (auto &el1, auto el2) 
	    {
	      std::string line1 = el1.filename().u8string();
	      std::string line2 = el2.filename().u8string();
	      return std::stoi(line1) < std::stoi(line2);
	    });
	  for(size_t i = 0; i < pathvect.size(); i++)
	    {
	      line = pathvect[i].filename().u8string();
	      strm.str("");
	      strm.clear();
	      strm.imbue(loc);
	      strm << line;
	      int tint;
	      strm >> tint;
	      if(tint > indep)
		{
		  tint = tint - 1;
		  strm.str("");
		  strm.clear();
		  strm.imbue(loc);
		  strm << tint;
		  line = pathvect[i].parent_path().u8string();
		  line = line + "/" + strm.str();
		  std::filesystem::path newpath(std::filesystem::u8path(line));
		  std::filesystem::rename(pathvect[i], newpath);
		}
	    }
	}

      filename = Home_Path;
      filename = filename + "/.Communist/Bufer/" + index;
      filepath = std::filesystem::u8path(filename);
      if(std::filesystem::exists(filepath))
	{
	  std::filesystem::remove_all(filepath);
	}

      filename = Home_Path;
      filename = filename + "/.Communist/Bufer";
      folderpath = std::filesystem::u8path(filename);
      pathvect.clear();
      if(std::filesystem::exists(folderpath))
	{
	  for(auto &dir : std::filesystem::directory_iterator(folderpath))
	    {
	      std::filesystem::path old = dir.path();
	      pathvect.push_back(old);
	    }
	  std::sort(pathvect.begin(), pathvect.end(), []
	  (auto &el1, auto el2) 
	    {
	      std::string line1 = el1.filename().u8string();
	      std::string line2 = el2.filename().u8string();
	      return std::stoi(line1) < std::stoi(line2);
	    });
	  for(size_t i = 0; i < pathvect.size(); i++)
	    {
	      line = pathvect[i].filename().u8string();
	      strm.str("");
	      strm.clear();
	      strm.imbue(loc);
	      strm << line;
	      int tint;
	      strm >> tint;
	      if(tint > indep)
		{
		  tint = tint - 1;
		  strm.str("");
		  strm.clear();
		  strm.imbue(loc);
		  strm << tint;
		  line = pathvect[i].parent_path().u8string();
		  line = line + "/" + strm.str();
		  std::filesystem::path newpath(std::filesystem::u8path(line));
		  std::filesystem::rename(pathvect[i], newpath);
		}
	    }
	}

      filename = Home_Path;
      filename = filename + "/.Communist/" + index;
      filepath = std::filesystem::u8path(filename);
      if(std::filesystem::exists(filepath))
	{
	  std::filesystem::remove_all(filepath);
	}

      contactsfull.erase(contit);
      filename = Home_Path;
      filename = filename + "/.Communist";
      folderpath = std::filesystem::u8path(filename);
      pathvect.clear();
      for(auto &dir : std::filesystem::directory_iterator(folderpath))
	{
	  std::filesystem::path old = dir.path();
	  if(std::filesystem::is_directory(old)
	      && old.filename().u8string() != "Bufer"
	      && old.filename().u8string() != "SendBufer")
	    {
	      pathvect.push_back(old);
	    }
	}
      std::sort(pathvect.begin(), pathvect.end(), []
      (auto &el1, auto el2) 
	{
	  std::string line1 = el1.filename().u8string();
	  std::string line2 = el2.filename().u8string();
	  return std::stoi(line1) < std::stoi(line2);
	});
      for(size_t i = 0; i < pathvect.size(); i++)
	{
	  line = pathvect[i].filename().u8string();
	  strm.str("");
	  strm.clear();
	  strm.imbue(loc);
	  strm << line;
	  int tint;
	  strm >> tint;
	  if(tint > indep)
	    {
	      tint = tint - 1;
	      strm.str("");
	      strm.clear();
	      strm.imbue(loc);
	      strm << tint;
	      line = pathvect[i].parent_path().u8string();
	      line = line + "/" + strm.str();
	      std::filesystem::path newpath(std::filesystem::u8path(line));
	      std::filesystem::rename(pathvect[i], newpath);
	    }
	}
      for(size_t i = 0; i < contactsfull.size(); i++)
	{
	  if(std::get<0>(contactsfull[i]) > indep)
	    {
	      std::get<0>(contactsfull[i]) = std::get<0>(contactsfull[i]) - 1;
	    }
	}
      std::vector<std::tuple<std::string, std::vector<char>>> profvect;
      profvect = oaf.readProfile(Home_Path, Username, Password);
      std::array<char, 32> seed;
      oaf.readSeed(Home_Path, Username, Password, seed);
      std::vector<std::string> relaylist;
      relaylist = oaf.readRelayContacts(Home_Path, Username, Password);
      std::vector<std::string> Addfriends;
      Addfriends = oaf.readRequestList(Home_Path, Username, Password);
      Addfriends.erase(
	  std::remove(Addfriends.begin(), Addfriends.end(), keyloc),
	  Addfriends.end());
      oaf.editProfile(Username, Password, Home_Path, profvect, seed,
		      contactsfull, Addfriends, relaylist);
    }
}
