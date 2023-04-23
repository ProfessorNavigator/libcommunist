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

#ifndef INCLUDE_NETOPERATIONSCOMM_H_
#define INCLUDE_NETOPERATIONSCOMM_H_

#include <functional>
#include <string>
#include <filesystem>

class NetOperationsComm
{
public:
  NetOperationsComm();
  virtual
  ~NetOperationsComm();

  std::function<void
  ()> net_op_canceled_signal;
  std::function<void
  (std::string, std::filesystem::path)> messageReceived_signal;
  std::function<void
  (std::string, int)> profReceived_signal;
  std::function<void
  (std::string, std::filesystem::path)> msgSent_signal;
  std::function<void
  (std::string, uint64_t, uint64_t, std::string)> filerequest_signal;
  std::function<void
  (std::string, std::filesystem::path)> fileRejected_signal;
  std::function<void
  (std::string, std::filesystem::path)> filehasherr_signal;
  std::function<void
  (std::string, std::filesystem::path)> filercvd_signal;
  std::function<void
  (std::string, std::filesystem::path)> filesent_signal;
  std::function<void
  (std::string, std::filesystem::path)> filesenterror_signal;
  std::function<void
  (std::string)> ipv6_signal;
  std::function<void
  (std::string)> ipv4_signal;
  std::function<void
  ()> ipv6finished_signal;
  std::function<void
  ()> ipv4finished_signal;
  std::function<void
  (std::string, std::filesystem::path, uint64_t)> filepartrcvd_signal;
  std::function<void
  (std::string, std::filesystem::path, uint64_t)> filepartsend_signal;
  std::function<void
  (std::string, uint64_t)> smthrcvd_signal;
  std::function<void
  (std::string)> friendDeleted_signal;
  std::function<void
  ()> friendDelPulse_signal;
  std::function<void
  ()> friendBlocked_signal;

  static NetOperationsComm*
  create_object();

  void
  setPrefVector(std::vector<std::tuple<std::string, std::string>> &prefvect);
  void
  setUsernamePasswd(std::string Username, std::string Password);
  void
  setHomePath(std::string homepath);
  void
  setStunListPath(std::string path);
  void
  startNetOperations();

  void
  getNewFriends(std::string key);
  void
  removeFriend(std::string key);
  bool
  checkIfMsgSent(std::filesystem::path p);
  std::filesystem::path
  sendMessage(std::string key, std::string nick, std::string replstr,
	      std::filesystem::path msgpath);
  std::filesystem::path
  sendMessage(std::string key, std::string nick, std::string replstr,
	      std::string msgstring);
  std::filesystem::path
  sendFile(std::string key, std::string nick, std::string replstr,
	   std::string pathtofile);
  void
  renewProfile(std::string key);
  void
  fileReject(std::string key, uint64_t tm);
  void
  fileAccept(std::string key, uint64_t tm, std::filesystem::path sp);
  void
  startFriend(std::string key, int ind);
  void
  blockFriend(std::string key);
  void
  setIPv6(std::string ip);
  void
  setIPv4(std::string ip);
  std::filesystem::path
  removeMsg(std::string key, std::filesystem::path msgpath);
  void
  cancelSendFile(std::string key, std::filesystem::path filepath);
  void
  cancelReceivFile(std::string key, std::filesystem::path filepath);
  void
  editContByRelay(std::vector<std::string> &sendbyrel);
  void
  cancelNetOperations();
  static void
  cleanMemory(NetOperationsComm *noc);

private:
  void
  profRcvd(std::string key, int ind);
  void
  contDelFunc(std::string key);
  std::vector<std::tuple<std::string, std::string>> prefvect;
  std::string Username = "";
  std::string Password = "";
  std::string Home_Path = "";
  std::string Stun_Path = "";
};

#endif /* INCLUDE_NETOPERATIONSCOMM_H_ */
