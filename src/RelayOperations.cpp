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

#include <RelayOperations.h>
#include <thread>
#include <time.h>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <libtorrent/hex.hpp>
#include "AuxFuncNet.h"
#include "OutAuxFunc.h"

RelayOperations::RelayOperations(
    std::string ipbstr,
    std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int>> *getfrres,
    std::mutex *getfrresmtx,
    std::vector<
	std::tuple<uint32_t, uint16_t, time_t, std::shared_ptr<std::mutex>>> *relayaddr,
    std::mutex *relayaddrmtx,
    std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t>> *frrelays,
    std::mutex *frrelaysmtx, uint16_t relayport, std::string enable_relay_srv,
    std::vector<std::tuple<std::mutex*, std::string>> *threadvect,
    std::mutex *threadvectmtx, int *cancel, std::string relay_list_path,
    std::vector<std::array<char, 32>> *sendbyrelay, std::mutex *sendbyrelaymtx)
{
  int check = 0;
  check = inet_pton(AF_INET, ipbstr.c_str(), &ipbindto);
  if(check <= 0)
    {
      ipbindto = INADDR_ANY;
#ifdef __linux
      std::cerr << "Addres convert error: " << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
      check = WSAGetLastError ();
      std::cerr << "Addres convert error: " << check << std::endl;
#endif
    }
  this->getfrres = getfrres;
  this->getfrresmtx = getfrresmtx;
  this->relayaddr = relayaddr;
  this->relayaddrmtx = relayaddrmtx;
  this->frrelays = frrelays;
  this->frrelaysmtx = frrelaysmtx;
  if(relayport != 0)
    {
      this->relayport = htons(relayport);
    }
  this->enable_relay_srv = enable_relay_srv;
  if(this->enable_relay_srv != "disabled"
      && this->enable_relay_srv != "enabled")
    {
      this->enable_relay_srv = "disabled";
    }
  this->threadvect = threadvect;
  this->threadvectmtx = threadvectmtx;
  this->cancel = cancel;

  if(relay_list_path != "")
    {
      std::filesystem::path filepath = std::filesystem::u8path(relay_list_path);
      if(std::filesystem::exists(filepath))
	{
	  std::fstream f;
	  f.open(filepath, std::ios_base::in);
	  if(f.is_open())
	    {
	      while(!f.eof())
		{
		  std::string line;
		  getline(f, line);
		  if(!line.empty())
		    {
		      std::string ipstr = line;
		      ipstr = ipstr.substr(0, ipstr.find(":"));
		      uint32_t ip;
		      int ch = inet_pton(AF_INET, ipstr.c_str(), &ip);
		      if(ch > 0)
			{
			  std::string portstr = line;
			  portstr.erase(
			      0, portstr.find(":") + std::string(":").size());
			  std::stringstream strm;
			  std::locale loc("C");
			  strm.imbue(loc);
			  strm << portstr;
			  uint16_t port;
			  strm >> port;
			  if(port != 0)
			    {
			      port = htons(port);
			      userrelaylist.push_back(
				  std::make_tuple(ip, port));
			    }
			}
		    }
		}
	      f.close();
	    }
	}
    }

  this->sendbyrelay = sendbyrelay;
  this->sendbyrelaymtx = sendbyrelaymtx;

  relayRequest();

  if(this->enable_relay_srv == "enabled")
    {
      relaySrv();
    }
}

RelayOperations::~RelayOperations()
{
  // TODO Auto-generated destructor stub
}

void
RelayOperations::relayRequest()
{
  std::mutex *thrmtx = new std::mutex;
  thrmtx->lock();
  threadvectmtx->lock();
  threadvect->push_back(std::make_tuple(thrmtx, "Relay request"));
  threadvectmtx->unlock();
  std::thread *relreqthr = new std::thread(
      std::bind(&RelayOperations::relayRequestThread, this, thrmtx));
  relreqthr->detach();
  delete relreqthr;
}

void
RelayOperations::relayRequestThread(std::mutex *thrmtx)
{
  int ch = 0;
  std::vector<std::tuple<uint32_t, uint16_t>> fraddrs;
  OutAuxFunc oaf;
  time_t endc = time(NULL);
  time_t beginc = endc - 3;
  for(;;)
    {
      if(*cancel > 0)
	{
	  break;
	}
      if(endc - beginc < 3)
	{
	  sleep(3 - (endc - beginc));
	}
      beginc = time(NULL);
      fraddrs.clear();

      int relsz = 0;
      sendbyrelaymtx->lock();
      relsz = sendbyrelay->size();
      sendbyrelaymtx->unlock();

      if(relsz > 0)
	{
	  for(size_t i = 0; i < userrelaylist.size(); i++)
	    {
	      fraddrs.push_back(userrelaylist[i]);
	    }

	  getfrresmtx->lock();
	  for(size_t i = 0; i < getfrres->size(); i++)
	    {
	      uint32_t ip = std::get<1>(getfrres->at(i));
	      uint16_t port = std::get<2>(getfrres->at(i));
	      if(ip > 0 && port > 0)
		{
		  std::tuple<uint32_t, uint16_t> tmptup;
		  std::get<0>(tmptup) = ip;
		  std::get<1>(tmptup) = relayport;
		  fraddrs.push_back(tmptup);
		}
	    }
	  getfrresmtx->unlock();
	  frrelaysmtx->lock();
	  for(size_t i = 0; i < frrelays->size(); i++)
	    {
	      uint32_t ip = std::get<1>(frrelays->at(i));
	      uint16_t port = std::get<2>(frrelays->at(i));

	      auto itfradd = std::find_if(
		  fraddrs.begin(), fraddrs.end(), [&ip, &port]
		  (auto &el) 
		    {
		      if (ip == std::get<0>(el) && port == std::get<1>(el))
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    });
	      if(itfradd == fraddrs.end())
		{
		  std::tuple<uint32_t, uint16_t> tmptup;
		  std::get<0>(tmptup) = ip;
		  std::get<1>(tmptup) = port;
		  fraddrs.push_back(tmptup);
		}
	    }
	  frrelaysmtx->unlock();

	  relayaddrmtx->lock();
	  time_t curtime = time(NULL);
	  for(size_t i = 0; i < relayaddr->size(); i++)
	    {
	      time_t chtm = std::get<2>(relayaddr->at(i));
	      if(curtime - chtm > 1200)
		{
		  uint32_t ip = std::get<0>(relayaddr->at(i));
		  uint16_t port = std::get<1>(relayaddr->at(i));
		  std::tuple<uint32_t, uint16_t> tmptup;
		  std::get<0>(tmptup) = ip;
		  std::get<1>(tmptup) = port;
		  auto itfr = std::find(fraddrs.begin(), fraddrs.end(), tmptup);
		  if(itfr == fraddrs.end())
		    {
		      fraddrs.push_back(tmptup);
		    }
		}
	    }

	  relayaddr->erase(
	      std::remove_if(relayaddr->begin(), relayaddr->end(), [&curtime]
	      (auto &el) 
		{
		  if (curtime - std::get<2>(el) > 1200)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	      relayaddr->end());

	  for(size_t i = 0; i < relayaddr->size(); i++)
	    {
	      uint32_t ip = std::get<0>(relayaddr->at(i));
	      uint16_t port = std::get<1>(relayaddr->at(i));
	      fraddrs.erase(
		  std::remove_if(fraddrs.begin(), fraddrs.end(), [ &ip, &port]
		  (auto &el) 
		    {
		      if (std::get<0>(el) == ip && std::get<1>(el) == port)
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    }),
		  fraddrs.end());
	    }

	  relayaddrmtx->unlock();

	  for(size_t i = 0; i < fraddrs.size(); i++)
	    {
	      if(*cancel > 0)
		{
		  break;
		}
	      int relayreqsock = socket(AF_INET, SOCK_STREAM, 0);
	      sockaddr_in relaysrv =
		{ };
	      relaysrv.sin_family = AF_INET;
	      relaysrv.sin_addr.s_addr = std::get<0>(fraddrs[i]);
	      relaysrv.sin_port = std::get<1>(fraddrs[i]);
	      std::vector<char> tmpb;
	      tmpb.resize(INET_ADDRSTRLEN);
	      std::string addr = inet_ntop(AF_INET, &relaysrv.sin_addr.s_addr,
					   &tmpb[0], tmpb.size());
	      std::cout << "Test server " << addr << ":"
		  << ntohs(relaysrv.sin_port) << std::endl;

	      std::vector<char> msg;
	      std::string msgstr = "tst";
	      std::copy(msgstr.begin(), msgstr.end(), std::back_inserter(msg));
	      ch = -1;
	      ch = connect(relayreqsock, (sockaddr*) &relaysrv,
			   socklen_t(sizeof(relaysrv)));
	      if(ch < 0)
		{
#ifdef __linux
		  int errn = errno;
#endif
#ifdef _WIN32
	      int errn = WSAGetLastError ();
#endif
		  tmpb.clear();
		  tmpb.resize(INET_ADDRSTRLEN);
		  std::string addr = inet_ntop(AF_INET,
					       &relaysrv.sin_addr.s_addr,
					       &tmpb[0], tmpb.size());

#ifdef __linux
		  std::cerr << "Relay server (" << addr << ":"
		      << ntohs(relaysrv.sin_port) << ") test error: "
		      << strerror(errn) << std::endl;
#endif
#ifdef _WIN32
	      std::cerr << "Relay server test error: " << errn << std::endl;
#endif
		}
	      else
		{
		  int chsend = sendMsg(relayreqsock, msg);
		  std::vector<char> buf;
		  if(chsend > 0)
		    {
		      for(;;)
			{
			  if(*cancel > 0)
			    {
			      break;
			    }
			  if(buf.size() >= std::string("reptst").size() + 2)
			    {
			      break;
			    }
			  pollfd fdsl[1];
			  fdsl[0].fd = relayreqsock;
			  fdsl[0].events = POLLRDNORM;
			  int respol = poll(fdsl, 1, 3000);
			  if(respol < 0)
			    {
#ifdef __linux
			      std::cerr << "Relay test polling error: "
				  << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
			  respol = WSAGetLastError ();
			  std::cerr << "Relay test polling error: " << respol << std::endl;
#endif
			      break;
			    }
			  else
			    {
			      if(respol == 0)
				{
				  break;
				}
			      else
				{
				  if(fdsl[0].revents == POLLRDNORM)
				    {
				      std::vector<char> lbuf;
				      lbuf.resize(1500);
				      int n = 0;
				      n = recv(fdsl[0].fd, &lbuf[0],
					       lbuf.size(),
					       MSG_PEEK);
				      if(n > 0)
					{
					  lbuf.clear();
					  lbuf.resize(n);
					  recv(fdsl[0].fd, &lbuf[0],
					       lbuf.size(), 0);
					  std::copy(lbuf.begin(), lbuf.end(),
						    std::back_inserter(buf));
					}
				      else
					{
					  break;
					}
				    }
				}
			    }
			}

		    }
		  else
		    {
		      std::cerr
			  << "Connection to server is broken (relayRequestThread)"
			  << std::endl;
		    }
		  std::vector<std::vector<char>> msgbuf;
		  receiveMsgs(buf, &msgbuf);
		  if(msgbuf.size() > 0)
		    {
		      buf = msgbuf[0];
		      std::string chstr;
		      std::copy(buf.begin(), buf.end(),
				std::back_inserter(chstr));
		      if(chstr == "reptst")
			{
			  tmpb.clear();
			  tmpb.resize(INET_ADDRSTRLEN);
			  std::string addr = inet_ntop(
			      AF_INET, &relaysrv.sin_addr.s_addr, &tmpb[0],
			      tmpb.size());
			  std::cout << "Server " << addr << ":"
			      << ntohs(relaysrv.sin_port)
			      << " successfully tested" << std::endl;
			  std::shared_ptr<std::mutex> mtx(new std::mutex);
			  std::tuple<uint32_t, uint16_t, time_t,
			      std::shared_ptr<std::mutex>> ttup;
			  std::get<0>(ttup) = std::get<0>(fraddrs[i]);
			  std::get<1>(ttup) = std::get<1>(fraddrs[i]);
			  std::get<2>(ttup) = time(NULL);
			  std::get<3>(ttup) = mtx;
			  relayaddrmtx->lock();
			  relayaddr->push_back(ttup);
			  relayaddrmtx->unlock();
			}
		    }
		}
	      closeSockOp(relayreqsock, "Relay test close socket error: ");
	      if(*cancel > 0)
		{
		  break;
		}
	    }
	}
      endc = time(NULL);
    }
  thrmtx->unlock();
}

#ifdef _WIN32
int
RelayOperations::poll (struct pollfd *pfd, int nfds, int timeout)
{
  return WSAPoll (pfd, nfds, timeout);
}
#endif

void
RelayOperations::relaySrv()
{
  int relaysock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in relaysrvaddr =
    { };
  relaysrvaddr.sin_family = AF_INET;
  relaysrvaddr.sin_addr.s_addr = ipbindto;
  relaysrvaddr.sin_port = relayport;
  size_t addrlen = sizeof(relaysrvaddr);
  if(bind(relaysock, (const sockaddr*) &relaysrvaddr, addrlen) == 0)
    {
      listen(relaysock, 5);
      std::mutex *thrmtx = new std::mutex;
      thrmtx->lock();
      threadvectmtx->lock();
      threadvect->push_back(std::make_tuple(thrmtx, "Relay server"));
      threadvectmtx->unlock();
      std::thread *relsrvthr = new std::thread([this, thrmtx, relaysock]
      {
	this->relaySrvThread(thrmtx, relaysock);
      });
      relsrvthr->detach();
      delete relsrvthr;
    }
  else
    {
#ifdef __linux
      std::cerr << "Relay server socket bind error: " << strerror(errno)
	  << std::endl;
#endif
#ifdef _WIN32
      int ch = WSAGetLastError ();
      std::cerr << "Relay server socket bind error: " << ch << std::endl;
#endif
    }
}

void
RelayOperations::relaySrvThread(std::mutex *thrmtx, int relaysock)
{
  for(;;)
    {
      if(*(this->cancel) > 0)
	{
	  break;
	}
      relayvectmtx.lock();
      relayvect.erase(std::remove_if(relayvect.begin(), relayvect.end(), []
      (auto &el) 
	{
	  time_t curtm = time (NULL);
	  if (curtm - std::get<4>(el) > 10)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
		      relayvect.end());
      relayvectmtx.unlock();
      pollfd fdsl[1];
      fdsl[0].fd = relaysock;
      fdsl[0].events = POLLRDNORM;
      int respol = poll(fdsl, 1, 3000);
      if(respol < 0)
	{
#ifdef __linux
	  std::cerr << "Relay server polling error: " << strerror(errno)
	      << std::endl;
#endif
#ifdef _WIN32
	  respol = WSAGetLastError ();
	  std::cerr << "Relay server polling error: " << respol << std::endl;
#endif
	}
      else
	{
	  if(fdsl[0].revents == POLLRDNORM)
	    {
	      sockaddr_in rcvdaddr =
		{ };
	      socklen_t sz = sizeof(rcvdaddr);
	      int srvsock = accept(relaysock, (sockaddr*) &rcvdaddr, &sz);
	      std::vector<char> tmpv;
	      tmpv.resize(INET_ADDRSTRLEN);
	      std::cout << "Relay srv rcvd request fm: "
		  << inet_ntop(AF_INET, &rcvdaddr.sin_addr.s_addr, &tmpv[0],
			       tmpv.size()) << ":" << ntohs(rcvdaddr.sin_port)
		  << std::endl;
	      std::mutex *thrmtxl = new std::mutex;
	      thrmtxl->lock();
	      threadvectmtx->lock();
	      threadvect->push_back(std::make_tuple(thrmtxl, "relaySrvThread"));
	      threadvectmtx->unlock();
	      std::thread *thrsrv = new std::thread([thrmtxl, srvsock, this]
	      {
		this->srvOperations(srvsock);
		thrmtxl->unlock();
	      });
	      thrsrv->detach();
	      delete thrsrv;
	    }
	}
    }
  thrmtx->unlock();
}

void
RelayOperations::srvOperations(int sock)
{
  std::vector<char> buf;
  for(;;)
    {
      if(buf.size() > 10000)
	{
	  break;
	}
      pollfd fd[1];
      fd[0].fd = sock;
      fd[0].events = POLLRDNORM;
      int respol = poll(fd, 1, 3000);
      if(respol < 0)
	{
#ifdef __linux
	  std::cerr << "Relay server polling error: " << strerror(errno)
	      << std::endl;
#endif
#ifdef _WIN32
	  respol = WSAGetLastError ();
	  std::cerr << "Relay server polling error: " << respol << std::endl;
#endif
	}
      else
	{
	  if(respol == 0)
	    {
	      break;
	    }
	  else
	    {
	      if(fd[0].revents == POLLRDNORM)
		{
		  std::vector<char> lbuf;
		  lbuf.resize(1500);
		  int n = 0;
		  n = recv(fd[0].fd, &lbuf[0], lbuf.size(), MSG_PEEK);
		  if(n > 0)
		    {
		      lbuf.clear();
		      lbuf.resize(n);
		      recv(fd[0].fd, &lbuf[0], lbuf.size(), 0);
		      std::copy(lbuf.begin(), lbuf.end(),
				std::back_inserter(buf));
		    }
		  else
		    {
		      break;
		    }
		}
	      else
		{
		  break;
		}
	    }
	}
    }
  std::vector<std::vector<char>> msgbuf;
  receiveMsgs(buf, &msgbuf);

  for(size_t i = 0; i < msgbuf.size(); i++)
    {
      buf = msgbuf[i];
      std::string type;
      std::copy(buf.begin(), buf.begin() + 3, std::back_inserter(type));
      if(type == "tst")
	{
	  std::vector<char> msg;
	  type = "reptst";
	  std::copy(type.begin(), type.end(), std::back_inserter(msg));
	  sendMsg(sock, msg);
	  closeSockOp(sock, "Relay test srv close socket error: ");
	  break;
	}
      else
	{
	  if(type == "req")
	    {
	      OutAuxFunc oaf;
	      std::array<char, 32> seed;
	      seed = oaf.seedGenerate();
	      std::array<char, 32> othkey;
	      std::copy(buf.begin() + 3, buf.end(), othkey.data());
	      std::string ownk = oaf.getKeyFmSeed(seed);
	      std::array<char, 32> ownkey;
	      lt::aux::from_hex(ownk, ownkey.data());
	      std::vector<char> msg;
	      std::string msgstr = "rep";
	      std::copy(msgstr.begin(), msgstr.end(), std::back_inserter(msg));
	      std::copy(ownkey.begin(), ownkey.end(), std::back_inserter(msg));
	      int szs = sendMsg(sock, msg);
	      if(szs > 0)
		{
		  keyvectmtx.lock();
		  keyvect.push_back(std::make_tuple(sock, seed, othkey));
		  keyvectmtx.unlock();
		  msgProcOperations(sock);
		}
	      else
		{
		  closeSockOp(sock, "Relay srv close socket error: ");
		  break;
		}
	    }
	  else
	    {
	      closeSockOp(sock, "Relay test srv close socket error: ");
	      break;
	    }
	}
    }
}

void
RelayOperations::msgProcOperations(int sock)
{
  std::vector<char> buf;
  int breakvar = 0;
  int count = 0;
  for(;;)
    {
      buf.clear();
      if(*cancel > 0)
	{
	  break;
	}
      breakvar = 0;
      pollfd fd[1];
      fd[0].fd = sock;
      fd[0].events = POLLRDNORM;

      int respol = poll(fd, 1, 3000);
      if(respol < 0)
	{
#ifdef __linux
	  std::cerr << "Relay server msgProcOperations polling error: "
	      << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
	  respol = WSAGetLastError ();
	  std::cerr << "Relay server msgProcOperations polling error: " << respol << std::endl;
#endif
	  break;
	}
      else
	{
	  if(respol == 0)
	    {
	      if(count > 3)
		{
		  breakvar = 1;
		}
	      count++;
	    }
	  else
	    {
	      if(fd[0].revents == POLLRDNORM)
		{
		  std::vector<char> lbuf;
		  lbuf.resize(1500);
		  int n = 0;
		  n = recv(fd[0].fd, &lbuf[0], lbuf.size(), MSG_PEEK);
		  if(n > 0)
		    {
		      count = 0;
		      lbuf.clear();
		      lbuf.resize(n);
		      recv(fd[0].fd, &lbuf[0], lbuf.size(), 0);
		      std::copy(lbuf.begin(), lbuf.end(),
				std::back_inserter(buf));
		    }
		  else
		    {
		      breakvar = 1;
		    }
		}
	      else
		{
		  std::cout << "Break poll error" << std::endl;
		  breakvar = 1;
		}
	    }
	}
      std::vector<std::vector<char>> msgbuf;
      receiveMsgs(buf, &msgbuf);
      for(size_t i = 0; i < msgbuf.size(); i++)
	{
	  buf = msgbuf[i];
	  keyvectmtx.lock();
	  auto itkv = std::find_if(keyvect.begin(), keyvect.end(), [sock]
	  (auto &el) 
	    {
	      return std::get<0>(el) == sock;
	    });
	  if(itkv != keyvect.end())
	    {
	      std::array<char, 32> seed = std::get<1>(*itkv);
	      std::array<char, 32> othkarr = std::get<2>(*itkv);
	      std::string othkey = lt::aux::to_hex(othkarr);
	      OutAuxFunc oaf;
	      std::string passwd = oaf.genPasswd(othkey, seed);
	      AuxFuncNet afn;
	      std::vector<char> lbuf;
	      std::string owkstr = oaf.getKeyFmSeed(seed);
	      lbuf = afn.decryptStrm(owkstr, passwd, buf);
	      std::string msgtype;
	      std::copy(lbuf.begin(), lbuf.begin() + 2,
			std::back_inserter(msgtype));
	      if(msgtype == "RQ" && lbuf.size() > 34)
		{
		  std::array<char, 32> rcvdkey;
		  std::copy(lbuf.begin() + 2, lbuf.begin() + 34,
			    rcvdkey.data());
		  std::array<char, 64> sign;
		  std::copy(lbuf.begin() + 34, lbuf.end(), sign.data());
		  lt::dht::public_key pk;
		  pk.bytes = rcvdkey;
		  lt::dht::signature sig;
		  sig.bytes = sign;
		  std::vector<char> msgtoch;
		  std::copy(lbuf.begin(), lbuf.begin() + 34,
			    std::back_inserter(msgtoch));
		  if(lt::dht::ed25519_verify(sig, msgtoch, pk))
		    {
		      relayvectmtx.lock();
		      for(;;)
			{
			  auto itrv = std::find_if(
			      relayvect.begin(), relayvect.end(), [rcvdkey]
			      (auto &el) 
				{
				  return std::get<0>(el) == rcvdkey;
				});
			  if(itrv != relayvect.end())
			    {
			      std::array<char, 32> keyfm = std::get<1>(*itrv);
			      std::vector<char> msgtmp = std::get<2>(*itrv);
			      std::string reptype = "RP";
			      std::vector<char> msg(reptype.begin(),
						    reptype.end());
			      std::copy(keyfm.begin(), keyfm.end(),
					std::back_inserter(msg));
			      std::array<char, 64> signtos = std::get<3>(*itrv);
			      std::copy(signtos.begin(), signtos.end(),
					std::back_inserter(msg));
			      std::copy(msgtmp.begin(), msgtmp.end(),
					std::back_inserter(msg));
			      std::string othpasswd = oaf.genFriendPasswd(
				  othkey, seed);
			      msg = afn.cryptStrm(othkey, othpasswd, msg);
			      int sz = sendMsg(sock, msg);
			      if(sz < 0)
				{
#ifdef __linux
				  std::cerr << "Relay srv RP error: "
				      << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
				  int check = WSAGetLastError ();
				  std::cerr << "Relay srv RP error: " << check << std::endl;
#endif
				  breakvar = 1;
				  break;
				}
			      else
				{
				  relayvect.erase(itrv);
				}
			    }
			  else
			    {
			      std::string replmsg = "RE";
			      std::vector<char> msg(replmsg.begin(),
						    replmsg.end());
			      sendMsg(sock, msg);
			      breakvar = 1;
			      break;
			    }
			}
		      relayvectmtx.unlock();
		    }
		  else
		    {
		      std::cerr << "RQ request did not passed verification"
			  << std::endl;
		      std::string replmsg = "RF";
		      std::vector<char> msg(replmsg.begin(), replmsg.end());
		      sendMsg(sock, msg);
		      breakvar = 1;
		    }
		}
	      if(msgtype == "RM" && lbuf.size() > 130)
		{
		  std::vector<char> msgtoch;
		  std::copy(lbuf.begin() + 34, lbuf.begin() + 66,
			    std::back_inserter(msgtoch));
		  std::copy(lbuf.begin() + 130, lbuf.end(),
			    std::back_inserter(msgtoch));

		  std::array<char, 32> keyto;
		  std::copy(lbuf.begin() + 2, lbuf.begin() + 34, keyto.data());
		  std::array<char, 32> keyfm;
		  std::copy(lbuf.begin() + 34, lbuf.begin() + 66, keyfm.data());
		  std::array<char, 64> sign;
		  std::copy(lbuf.begin() + 66, lbuf.begin() + 130, sign.data());
		  lt::dht::public_key pk;
		  pk.bytes = keyfm;
		  lt::dht::signature sig;
		  sig.bytes = sign;
		  if(lt::dht::ed25519_verify(sig, msgtoch, pk))
		    {
		      std::vector<char> msgtorl;
		      std::copy(lbuf.begin() + 130, lbuf.end(),
				std::back_inserter(msgtorl));
		      std::tuple<std::array<char, 32>, std::array<char, 32>,
			  std::vector<char>, std::array<char, 64>, time_t> ttup;
		      std::get<0>(ttup) = keyto;
		      std::get<1>(ttup) = keyfm;
		      std::get<2>(ttup) = msgtorl;
		      std::get<3>(ttup) = sign;
		      std::get<4>(ttup) = time(NULL);
		      relayvectmtx.lock();
		      if(relayvect.size() < 100)
			{
			  relayvect.push_back(ttup);
			  std::string replmsg = "RS";
			  std::vector<char> msg(replmsg.begin(), replmsg.end());
			  sendMsg(sock, msg);
			}
		      else
			{
			  std::cerr << "Relay bufer overflow" << std::endl;
			  std::string replmsg = "RB";
			  std::vector<char> msg(replmsg.begin(), replmsg.end());
			  sendMsg(sock, msg);
			  breakvar = 1;
			}
		      relayvectmtx.unlock();
		    }
		  else
		    {
		      std::cerr << "RM request did not passed verification"
			  << std::endl;
		      std::string replmsg = "RF";
		      std::vector<char> msg(replmsg.begin(), replmsg.end());
		      sendMsg(sock, msg);
		      breakvar = 1;
		    }
		}
	    }
	  else
	    {
	      breakvar = 1;
	    }
	  keyvectmtx.unlock();
	}
      if(breakvar > 0)
	{
	  break;
	}
    }

  keyvectmtx.lock();
  keyvect.erase(std::remove_if(keyvect.begin(), keyvect.end(), [sock]
  (auto &el) 
    {
      return std::get<0>(el) == sock;
    }),
		keyvect.end());
  keyvectmtx.unlock();
  closeSockOp(sock, "msgProcOperations close socket error: ");
}

int
RelayOperations::relaySend(std::array<char, 32> keyarr,
			   std::array<char, 32> &seed,
			   std::vector<std::vector<char>> &msgsbuf)
{
  std::vector<std::vector<char>> lmsgsbuf = msgsbuf;
  int result = -1;
  int sock = -1;
  uint32_t ip = 0;
  uint16_t port = 0;
  frrelaysmtx->lock();
  auto itfrr = std::find_if(frrelays->begin(), frrelays->end(), [keyarr]
  (auto &el) 
    {
      return std::get<0>(el) == keyarr;
    });
  if(itfrr != frrelays->end())
    {
      ip = std::get<1>(*itfrr);
      port = std::get<2>(*itfrr);
    }
  frrelaysmtx->unlock();
  std::shared_ptr<std::mutex> relsmtx;
  relayaddrmtx->lock();
  auto itra = std::find_if(relayaddr->begin(), relayaddr->end(), [&ip, &port]
  (auto &el) 
    {
      if (std::get<0>(el) == ip && std::get<1>(el) == port)
	{
	  return true;
	}
      else
	{
	  return false;
	}
    });
  if(itra == relayaddr->end())
    {
      ip = 0;
      port = 0;
      if(relayaddr->size() > 0)
	{
	  ip = std::get<0>(relayaddr->at(0));
	  port = std::get<1>(relayaddr->at(0));
	  relsmtx = std::get<3>(relayaddr->at(0));
	}
    }
  else
    {
      relsmtx = std::get<3>(*itra);
    }
  relayaddrmtx->unlock();

  if(ip != 0 && port != 0)
    {
      sock = socket(AF_INET, SOCK_STREAM, 0);
      sockaddr_in reladdr =
	{ };
      reladdr.sin_family = AF_INET;
      reladdr.sin_addr.s_addr = ip;
      reladdr.sin_port = port;
      int ch = -1;
      ch = connect(sock, (sockaddr*) &reladdr, socklen_t(sizeof(reladdr)));
      if(ch < 0)
	{
#ifdef __linux
	  std::cerr << "Relay send connect error: " << strerror(errno)
	      << std::endl;
#endif
#ifdef _WIN32
	  ch = WSAGetLastError ();
	  std::cerr << "Relay send connect error: " << ch << std::endl;
#endif
	}
      else
	{
	  std::tuple<int, std::array<char, 32>, std::array<char, 32>> restup;
	  if(establishConnect(sock, &restup))
	    {
	      for(size_t j = 0; j < lmsgsbuf.size(); j++)
		{
		  std::vector<char> msg = lmsgsbuf[j];
		  std::string msgstr = "RM";
		  std::vector<char> lmsg(msgstr.begin(), msgstr.end());
		  std::array<char, 32> keytoarr = keyarr;
		  std::copy(keytoarr.begin(), keytoarr.end(),
			    std::back_inserter(lmsg));
		  OutAuxFunc oaf;
		  std::string keyfm = oaf.getKeyFmSeed(seed);
		  std::array<char, 32> keyfmarr;
		  lt::aux::from_hex(keyfm, keyfmarr.data());
		  std::copy(keyfmarr.begin(), keyfmarr.end(),
			    std::back_inserter(lmsg));

		  lt::dht::signature sig;
		  std::tuple<lt::dht::public_key, lt::dht::secret_key> kp;
		  kp = lt::dht::ed25519_create_keypair(seed);
		  std::vector<char> msgtosign;
		  std::copy(keyfmarr.begin(), keyfmarr.end(),
			    std::back_inserter(msgtosign));
		  std::copy(msg.begin(), msg.end(),
			    std::back_inserter(msgtosign));
		  sig = lt::dht::ed25519_sign(msgtosign, std::get<0>(kp),
					      std::get<1>(kp));
		  std::array<char, 64> sigarr = sig.bytes;

		  std::copy(sigarr.begin(), sigarr.end(),
			    std::back_inserter(lmsg));
		  std::copy(msg.begin(), msg.end(), std::back_inserter(lmsg));

		  std::string othkey = lt::aux::to_hex(std::get<2>(restup));
		  std::string uname = othkey;
		  std::string passwd = oaf.genFriendPasswd(othkey,
							   std::get<1>(restup));
		  AuxFuncNet afn;
		  lmsg = afn.cryptStrm(uname, passwd, lmsg);
		  int ssz = sendMsg(sock, lmsg);
		  if(ssz > 0)
		    {
		      std::vector<char> buf;
		      int count = 0;
		      for(;;)
			{
			  if(buf.size() >= 4)
			    {
			      break;
			    }
			  pollfd fd[1];
			  fd[0].fd = sock;
			  fd[0].events = POLLRDNORM;

			  int respol = poll(fd, 1, 3000);
			  if(respol < 0)
			    {
#ifdef __linux
			      std::cerr << "Relay RM poll error: "
				  << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
			      respol = WSAGetLastError ();
			      std::cerr << "Relay RM poll error: " << respol << std::endl;
#endif
			      break;
			    }
			  else
			    {
			      if(respol == 0)
				{
				  if(count > 3)
				    {
				      break;
				    }
				  count++;
				}
			      else
				{
				  count = 0;
				  if(fd[0].revents == POLLRDNORM)
				    {
				      std::vector<char> lbuf;
				      lbuf.resize(1500);
				      int n = 0;
				      n = recv(fd[0].fd, &lbuf[0], lbuf.size(),
				      MSG_PEEK);
				      if(n > 0)
					{
					  lbuf.clear();
					  lbuf.resize(n);
					  recv(fd[0].fd, &lbuf[0], lbuf.size(),
					       0);
					  std::copy(lbuf.begin(), lbuf.end(),
						    std::back_inserter(buf));
					}
				      else
					{
					  break;
					}
				    }
				  else
				    {
				      break;
				    }
				}
			    }
			}
		      std::vector<std::vector<char>> msgbuf;
		      receiveMsgs(buf, &msgbuf);
		      if(msgbuf.size() > 0)
			{
			  buf = msgbuf[0];
			  std::string msgtype;
			  std::copy(buf.begin(), buf.end(),
				    std::back_inserter(msgtype));
			  if(msgtype == "RS")
			    {
			      std::cout << "Msg sent to relay" << std::endl;
			      result = 1;
			    }
			}
		    }
		  else
		    {
		      std::cerr << "relaySend send error: " << strerror(errno)
			  << std::endl;
		    }
		}
	    }
	  else
	    {
	      std::cerr << "Secured connection not established" << std::endl;
	    }
	}
      closeSockOp(sock, "relaySend close socket error: ");
      std::mutex *relthrmtx = new std::mutex;
      relthrmtx->lock();
      threadvectmtx->lock();
      threadvect->push_back(std::make_tuple(relthrmtx, "Relay check"));
      threadvectmtx->unlock();
      std::array<char, 32> *lockseed = new std::array<char, 32>;
      *lockseed = seed;
      std::thread *relchthr = new std::thread(
	  [this, relthrmtx, ip, port, lockseed, relsmtx]
	  {
	    std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>> ttup;
	    std::get<0>(ttup) = ip;
	    std::get<1>(ttup) = port;
	    std::get<2>(ttup) = relsmtx;
	    if(relsmtx)
	      {
		this->relayCheck(*lockseed, this->cancel, ttup);
	      }
	    delete lockseed;
	    relthrmtx->unlock();
	  });
      relchthr->detach();
      delete relchthr;
    }

  return result;
}

bool
RelayOperations::establishConnect(
    int sock, std::tuple<int, std::array<char, 32>, std::array<char, 32>> *res)
{
  bool result = false;
  std::vector<char> msg;
  std::array<char, 32> seed;
  OutAuxFunc oaf;
  seed = oaf.seedGenerate();
  std::string keystr = oaf.getKeyFmSeed(seed);
  std::array<char, 32> keyarr;
  lt::aux::from_hex(keystr, keyarr.data());

  std::string msgstr = "req";
  std::copy(msgstr.begin(), msgstr.end(), std::back_inserter(msg));
  std::copy(keyarr.begin(), keyarr.end(), std::back_inserter(msg));
  int ssz = sendMsg(sock, msg);
  int count = 0;
  if(ssz > 0)
    {
      std::vector<char> buf;
      for(;;)
	{
	  if(buf.size() >= 37)
	    {
	      break;
	    }
	  pollfd fd[1];
	  fd[0].fd = sock;
	  fd[0].events = POLLRDNORM;

	  int respol = poll(fd, 1, 3000);

	  if(respol < 0)
	    {
#ifdef __linux
	      std::cerr << "Relay connetion establish error: "
		  << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
	      respol = WSAGetLastError ();
	      std::cerr << "Relay connetion establish error: " << respol << std::endl;
#endif
	      break;
	    }
	  else
	    {
	      if(respol == 0)
		{
		  if(count > 3)
		    {
		      break;
		    }
		  count++;
		}
	      else
		{
		  count = 0;
		  if(fd[0].revents == POLLRDNORM)
		    {
		      std::vector<char> lbuf;
		      lbuf.resize(1500);
		      int n = 0;
		      n = recv(fd[0].fd, &lbuf[0], lbuf.size(), MSG_PEEK);
		      if(n > 0)
			{
			  lbuf.clear();
			  lbuf.resize(n);
			  recv(fd[0].fd, &lbuf[0], lbuf.size(), 0);
			  std::copy(lbuf.begin(), lbuf.end(),
				    std::back_inserter(buf));
			}
		      else
			{
			  break;
			}
		    }
		  else
		    {
		      break;
		    }
		}
	    }
	}
      std::vector<std::vector<char>> msgbuf;
      receiveMsgs(buf, &msgbuf);
      if(msgbuf.size() > 0)
	{
	  buf = msgbuf[0];
	  std::string msgtype;
	  std::copy(buf.begin(), buf.begin() + 3, std::back_inserter(msgtype));
	  if(msgtype == "rep")
	    {
	      sockaddr_in addr =
		{ };
	      socklen_t sz = sizeof(addr);
	      getpeername(sock, (sockaddr*) &addr, &sz);
	      std::vector<char> tmpb;
	      tmpb.resize(INET_ADDRSTRLEN);
	      std::string stradd = inet_ntop(AF_INET, &addr.sin_addr.s_addr,
					     &tmpb[0], tmpb.size());
	      std::cout << "Secured connection established with " << stradd
		  << ":" << ntohs(addr.sin_port) << std::endl;
	      std::array<char, 32> othkey;
	      std::copy(buf.begin() + 3, buf.end(), othkey.data());
	      *res = std::make_tuple(sock, seed, othkey);
	      result = true;
	    }
	  else
	    {
	      sockaddr_in addr =
		{ };
	      socklen_t sz = sizeof(addr);
	      getpeername(sock, (sockaddr*) &addr, &sz);
	      std::vector<char> tmpb;
	      tmpb.resize(INET_ADDRSTRLEN);
	      std::string stradd = inet_ntop(AF_INET, &addr.sin_addr.s_addr,
					     &tmpb[0], tmpb.size());
	      std::cerr << "establishConnect wrong msg: " << msgtype << " from "
		  << stradd << ":" << ntohs(addr.sin_port) << std::endl;
	    }
	}
      else
	{
	  sockaddr_in addr =
	    { };
	  socklen_t sz = sizeof(addr);
	  getpeername(sock, (sockaddr*) &addr, &sz);
	  std::vector<char> tmpb;
	  tmpb.resize(INET_ADDRSTRLEN);
	  std::string stradd = inet_ntop(AF_INET, &addr.sin_addr.s_addr,
					 &tmpb[0], tmpb.size());
	  std::cerr << "establishConnect nothing received from server "
	      << stradd << ":" << ntohs(addr.sin_port) << std::endl;
	}
    }
  else
    {
      std::cerr << "establishConnect send error: " << strerror(errno)
	  << std::endl;
    }
  return result;
}

int
RelayOperations::relayCheck(
    std::array<char, 32> &seed, int *cancel,
    std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>> reltup)
{
  int result = -1;
  int sock = -10;
  time_t curtm = time(NULL);
  std::vector<std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>>> innerrel;
  if(std::get<0>(reltup) != 0 && std::get<1>(reltup) != 0)
    {
      innerrel.push_back(reltup);
    }
  else
    {
      relayaddrmtx->lock();
      for(size_t i = 0; i < relayaddr->size(); i++)
	{
	  time_t chtm = std::get<2>(relayaddr->at(i));
	  if(curtm - chtm <= 1200)
	    {
	      std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>> ttup;
	      std::get<0>(ttup) = std::get<0>(relayaddr->at(i));
	      std::get<1>(ttup) = std::get<1>(relayaddr->at(i));
	      std::get<2>(ttup) = std::get<3>(relayaddr->at(i));
	      innerrel.push_back(ttup);
	    }
	}
      relayaddrmtx->unlock();
    }
  for(size_t i = 0; i < innerrel.size(); i++)
    {
      if(*cancel > 0)
	{
	  break;
	}
      std::shared_ptr<std::mutex> mtx = std::get<2>(innerrel[i]);
      if(mtx->try_lock())
	{
	  uint32_t ip = std::get<0>(innerrel[i]);
	  uint16_t port = std::get<1>(innerrel[i]);
	  sock = socket(AF_INET, SOCK_STREAM, 0);
	  sockaddr_in reladdr =
	    { };
	  reladdr.sin_family = AF_INET;
	  reladdr.sin_addr.s_addr = ip;
	  reladdr.sin_port = port;
	  int check = connect(sock, (sockaddr*) &reladdr,
			      socklen_t(sizeof(reladdr)));
	  if(check != 0)
	    {
#ifdef __linux
	      std::cerr << "relayCheck connection error: " << strerror(errno)
		  << std::endl;
#endif
#ifdef _WIN32
	      check = WSAGetLastError ();
	      std::cerr << "relayCheck connection error: " << check << std::endl;
#endif
	    }
	  else
	    {
	      std::tuple<int, std::array<char, 32>, std::array<char, 32>> ttup;
	      if(establishConnect(sock, &ttup))
		{
		  std::string msgstr = "RQ";
		  std::vector<char> msg(msgstr.begin(), msgstr.end());
		  OutAuxFunc oaf;
		  std::string ownkeystr = oaf.getKeyFmSeed(seed);
		  std::array<char, 32> ownkarr;
		  lt::aux::from_hex(ownkeystr, ownkarr.data());
		  std::copy(ownkarr.begin(), ownkarr.end(),
			    std::back_inserter(msg));
		  std::tuple<lt::dht::public_key, lt::dht::secret_key> kp;
		  kp = lt::dht::ed25519_create_keypair(seed);
		  lt::dht::signature sig = lt::dht::ed25519_sign(
		      msg, std::get<0>(kp), std::get<1>(kp));
		  std::array<char, 64> sigarr = sig.bytes;
		  std::copy(sigarr.begin(), sigarr.end(),
			    std::back_inserter(msg));
		  std::string uname = lt::aux::to_hex(std::get<2>(ttup));
		  std::string passwd = oaf.genFriendPasswd(uname,
							   std::get<1>(ttup));
		  AuxFuncNet afn;
		  msg = afn.cryptStrm(uname, passwd, msg);
		  int ssz = sendMsg(sock, msg);
		  if(ssz > 0)
		    {
		      std::vector<char> buf;
		      int count = 0;
		      for(;;)
			{
			  if(*cancel > 0 || buf.size() > 10000)
			    {
			      break;
			    }
			  pollfd fd[1];
			  fd[0].fd = sock;
			  fd[0].events = POLLRDNORM;

			  int respol = poll(fd, 1, 3000);

			  if(respol < 0)
			    {
#ifdef __linux
			      std::cerr << "Relay RQ request poll error: "
				  << strerror(errno) << std::endl;
#endif
#ifdef _WIN32
			      respol = WSAGetLastError ();
			      std::cerr << "Relay RQ request poll error: " << respol << std::endl;
#endif
			      break;
			    }
			  else
			    {
			      if(respol == 0)
				{
				  if(count > 3)
				    {
				      break;
				    }
				  count++;
				}
			      else
				{
				  count = 0;
				  if(fd[0].revents == POLLRDNORM)
				    {
				      std::vector<char> lbuf;
				      lbuf.resize(1500);
				      int n = 0;
				      n = recv(fd[0].fd, &lbuf[0], lbuf.size(),
				      MSG_PEEK);
				      if(n > 0)
					{
					  lbuf.clear();
					  lbuf.resize(n);
					  recv(fd[0].fd, &lbuf[0], lbuf.size(),
					       0);
					  std::copy(lbuf.begin(), lbuf.end(),
						    std::back_inserter(buf));
					}
				      else
					{
					  break;
					}
				    }
				  else
				    {
				      break;
				    }
				}
			    }
			}
		      std::vector<std::vector<char>> msgbuf;
		      receiveMsgs(buf, &msgbuf);
		      for(size_t i = 0; i < msgbuf.size(); i++)
			{
			  buf = msgbuf[i];
			  receiveRP(sock, ttup, buf, seed);
			}
		    }
		}
	      else
		{
		  std::cerr << "relayCheck guard connection not established"
		      << std::endl;
		}
	    }
	  closeSockOp(sock, "relayCheck close socket error: ");
	  mtx->unlock();
	}
    }
  return result;
}

void
RelayOperations::receiveRP(
    int sock, std::tuple<int, std::array<char, 32>, std::array<char, 32>> ttup,
    std::vector<char> &buf, std::array<char, 32> &seed)
{
  std::string chstr;
  std::copy(buf.begin(), buf.begin() + 2, std::back_inserter(chstr));
  if(chstr == "RE")
    {
      std::cout << "No more messages on relay server" << std::endl;
    }
  else
    {
      std::array<char, 32> lseed;
      lseed = std::get<1>(ttup);
      std::array<char, 32> othcrkeyarr;
      othcrkeyarr = std::get<2>(ttup);
      std::string othcrkey = lt::aux::to_hex(othcrkeyarr);
      OutAuxFunc oaf;
      std::string uname = oaf.getKeyFmSeed(lseed);
      std::string passwd = oaf.genPasswd(othcrkey, lseed);
      AuxFuncNet afn;
      buf = afn.decryptStrm(uname, passwd, buf);
      std::string msgtype;
      std::copy(buf.begin(), buf.begin() + 2, std::back_inserter(msgtype));
      if(msgtype == "RP")
	{
	  std::array<char, 32> othkeyarr;
	  std::copy(buf.begin() + 2, buf.begin() + 34, othkeyarr.data());
	  std::array<char, 64> sigarr;
	  std::copy(buf.begin() + 34, buf.begin() + 98, sigarr.data());
	  std::vector<char> rmsg;
	  std::copy(buf.begin() + 98, buf.end(), std::back_inserter(rmsg));
	  std::vector<char> msgtoch;
	  std::copy(othkeyarr.begin(), othkeyarr.end(),
		    std::back_inserter(msgtoch));
	  std::copy(rmsg.begin(), rmsg.end(), std::back_inserter(msgtoch));
	  lt::dht::signature sig;
	  sig.bytes = sigarr;
	  lt::dht::public_key pk;
	  pk.bytes = othkeyarr;
	  if(lt::dht::ed25519_verify(sig, msgtoch, pk))
	    {
	      std::string othkstr = lt::aux::to_hex(othkeyarr);
	      sockaddr_in from;
	      if(relaymsgrcvd_signal)
		{
		  relaymsgrcvd_signal(sock, &from, othkstr, &rmsg);
		}
	      else
		{
		  std::cerr << "relaymsgrcvd_signal slot not connected"
		      << std::endl;
		}
	    }
	  else
	    {
	      std::cerr << "Recieved RP msg did not pass verification"
		  << std::endl;
	    }
	}
    }
}

void
RelayOperations::closeSockOp(int sock, std::string msg)
{
#ifdef __linux
  close(sock);
#endif
#ifdef __WIN32
  int check = closesocket (sock);
  if (check != 0)
    {
      check = WSAGetLastError ();
      std::cerr << msg << check << std::endl;
    }
#endif
}

std::vector<char>
RelayOperations::addMsgSize(std::vector<char> &msg)
{
  std::vector<char> result;
  size_t vsz = msg.size();
  uint16_t sz = static_cast<uint16_t>(vsz);
  sz = sz + sizeof(sz);
  result.resize(sizeof(sz));
  std::memcpy(&result[0], &sz, sizeof(sz));
  std::copy(msg.begin(), msg.end(), std::back_inserter(result));

  return result;
}

int
RelayOperations::receiveMsgs(std::vector<char> &buf,
			     std::vector<std::vector<char>> *msgbuf)
{
  int result = 0;
  std::vector<char> lbuf = buf;
  if(lbuf.size() >= 2)
    {
      uint16_t sz = 0;
      while(lbuf.size() > 0)
	{
	  std::vector<char> msg;
	  std::memcpy(&sz, &lbuf[0], sizeof(sz));
	  if(sz <= lbuf.size())
	    {
	      std::copy(lbuf.begin() + sizeof(sz), lbuf.begin() + sz,
			std::back_inserter(msg));
	      lbuf.erase(lbuf.begin(), lbuf.begin() + sz);
	      msgbuf->push_back(msg);
	      result = result + int(sz);
	    }
	  else
	    {
	      break;
	    }
	}
    }
  return result;
}

int
RelayOperations::sendMsg(int sock, std::vector<char> &msg)
{
  int result = 0;
  std::vector<char> lmsg = msg;
  lmsg = addMsgSize(lmsg);
  while(lmsg.size() > 0)
    {
      ssize_t sz = send(sock, &lmsg[0], lmsg.size(), 0);
      if(sz <= ssize_t(lmsg.size()) && sz > 0)
	{
	  lmsg.erase(lmsg.begin(), lmsg.begin() + sz);
	  result = result + sz;
	}
      if(sz <= 0)
	{
	  if(sz < 0)
	    {
	      result = -1;
	    }
	  break;
	}
    }
  return result;
}
