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

#include "NetworkOperations.h"

NetworkOperations::NetworkOperations (
    std::string username, std::string password,
    std::vector<std::tuple<int, std::string>> &Contacts,
    std::array<char, 32> &Seed, std::vector<std::string> &addfriends,
    std::vector<std::tuple<std::string, std::string>> &Prefvect,
    std::string sharepath, std::string homepath)
{
  Username = username;
  Password = password;
  for (size_t i = 0; i < Contacts.size (); i++)
    {
      std::array<char, 32> keyarr;
      std::string key = std::get<1> (Contacts[i]);
      lt::aux::from_hex (key, keyarr.data ());
      std::tuple<int, std::array<char, 32>> ttup;
      std::get<0> (ttup) = std::get<0> (Contacts[i]);
      std::get<1> (ttup) = keyarr;
      contacts.push_back (ttup);
      contactsfull.push_back (ttup);
    }
  Home_Path = homepath;
  sockipv6 = 0;
  for (size_t i = 0; i < contactsfull.size (); i++)
    {
      std::tuple<std::array<char, 32>, int, std::mutex*, time_t, std::mutex*> ttup;
      std::mutex *mtx = new std::mutex;
      std::mutex *mtxgip = new std::mutex;
      std::get<0> (ttup) = std::get<1> (contactsfull[i]);
      std::get<1> (ttup) = 0;
      std::get<2> (ttup) = mtx;
      std::get<3> (ttup) = 0;
      std::get<4> (ttup) = mtxgip;
      sockets4.push_back (ttup);
    }
  contsizech = contacts.size () - 1;
  seed = Seed;
  Addfriends = addfriends;
  prefvect = Prefvect;
  Sharepath = sharepath;
  auto itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Netmode";
    });
  if (itprv != prefvect.end ())
    {
      std::string nm = std::get<1> (*itprv);
      if (nm == "local")
	{
	  Netmode = "local";
	}
      else
	{
	  Netmode = "internet";
	}
    }
  else
    {
      Netmode = "internet";
    }
  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Maxmsgsz";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << ms;
	  strm >> Maxmsgsz;
	}
    }
  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Partsize";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << ms;
	  strm >> Partsize;
	}
    }

  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "ShutTmt";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << ms;
	  strm >> Shuttmt;
	}
    }

  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "TmtTear";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << ms;
	  strm >> Tmttear;
	}
    }
  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Stunport";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue (loc);
	  strm << ms;
	  strm >> stunport;
	}
    }
  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Stun";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  Enablestun = ms;
	}
    }
  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "DirectInet";
    });
  if (itprv != prefvect.end ())
    {
      std::string ms = std::get<1> (*itprv);
      if (ms != "")
	{
	  Directinet = ms;
	}
    }

  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Relayport";
    });
  if (itprv != prefvect.end ())
    {
      std::string rp = std::get<1> (*itprv);
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << rp;
      strm >> relayport;
    }

  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "RelaySrv";
    });
  if (itprv != prefvect.end ())
    {
      relaysrv = std::get<1> (*itprv);
    }

  itprv = std::find_if (prefvect.begin (), prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "RelayListPath";
    });
  if (itprv != prefvect.end ())
    {
      rellistpath = std::get<1> (*itprv);
    }
}

NetworkOperations::~NetworkOperations ()
{
  for (size_t i = 0; i < sockets4.size (); i++)
    {
      if (std::get<1> (sockets4[i]) >= 0)
	{
#ifdef __linux
	  close (std::get<1> (sockets4[i]));
#endif
#ifdef _WIN32
	  int ch = closesocket (std::get<1> (sockets4[i]));
	  if (ch != 0)
	    {
	      ch = WSAGetLastError ();
	      std::cerr << "ipv4 close socket error: " << ch << std::endl;
	    }
#endif
	}
      std::mutex *mtx1 = std::get<2> (sockets4[i]);
      std::mutex *mtx2 = std::get<4> (sockets4[i]);
      delete mtx1;
      delete mtx2;
    }
  sockets4.clear ();

#ifdef __linux
  close (sockipv6);
#endif
#ifdef _WIN32
  int ch = closesocket (sockipv6);
  if (ch != 0)
    {
      ch = WSAGetLastError ();
      std::cerr << "ipv6 close socket error: " << ch << std::endl;
    }
  ch = WSACleanup ();
  if (ch != 0)
    {
      ch = WSAGetLastError ();
      std::cerr << "Windows cleanup error: " << ch << std::endl;
    }
#endif
  if (DOp)
    {
      delete DOp;
    }
  if (LNOp)
    {
      delete LNOp;
    }
  if (ROp)
    {
      delete ROp;
    }
}

void
NetworkOperations::mainFunc ()
{
  std::string filename = Home_Path;
  filename = filename + "/.Communist/Bufer";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  std::filesystem::create_directories (filepath);

  dnsfinished = [this]
  {
    std::mutex *thrmtx = new std::mutex;
    thrmtx->lock ();
    this->threadvectmtx.lock ();
    this->threadvect.push_back (std::make_tuple (thrmtx, "Dns finished"));
    this->threadvectmtx.unlock ();
    std::thread *dnsfinthr = new std::thread (
	std::bind (&NetworkOperations::dnsFinishedThread, this, thrmtx));
    dnsfinthr->detach ();
    delete dnsfinthr;
  };

  if (Netmode == "internet")
    {
      dnsFunc ();
    }
  else
    {
      if (dnsfinished)
	{
	  dnsfinished ();
	}
    }
}

void
NetworkOperations::putOwnIps (std::array<char, 32> otherkey, uint32_t ip,
			      uint16_t port)
{
  putipmtx.lock ();
  std::tuple<std::array<char, 32>, uint32_t, uint16_t> ttup;
  ttup = std::make_tuple (otherkey, ip, port);
  auto it = std::find (putipv.begin (), putipv.end (), ttup);
  if (it == putipv.end ())
    {
      putipv.push_back (ttup);
    }
  else
    {
      *it = ttup;
    }
  putipmtx.unlock ();
}

std::pair<uint32_t, uint16_t>
NetworkOperations::getOwnIps (int udpsock,
			      std::pair<struct in_addr, int> stunsv)
{
  std::pair<uint32_t, uint16_t> result;
  if (Netmode == "internet" && Directinet == "notdirect")
    {
      std::vector<char> msgv;
      msgv.resize (20);
      uint16_t tt = htons (1);
      std::memcpy (&msgv[0], &tt, sizeof(tt));
      tt = htons (0);
      std::memcpy (&msgv[2], &tt, sizeof(tt));
      uint32_t ttt = htonl (554869826);
      std::memcpy (&msgv[4], &ttt, sizeof(ttt));

      sockaddr_in stun =
	{ };
      stun.sin_family = AF_INET;
      stun.sin_port = stunsv.second;
      result.first = 0;
      result.second = 0;
      stun.sin_addr = stunsv.first;
      sendto (udpsock, msgv.data (), msgv.size (), 0, (struct sockaddr*) &stun,
	      sizeof(stun));
      std::vector<char> buf;
      buf.resize (200);
      int count = 0;
      while (count < 3)
	{
	  if (cancel > 0 || cancelgetoips > 0)
	    {
	      result.first = 0;
	      result.second = 0;
	      return result;
	    }
	  sockaddr_in from =
	    { };
	  socklen_t sizefrom = sizeof(from);
	  int n = 0;
	  pollfd fdsl[1];
	  fdsl[0].fd = udpsock;
	  fdsl[0].events = POLLRDNORM;
	  int respol = poll (fdsl, 1, 3000);
	  if (respol > 0)
	    {
	      n = recvfrom (udpsock, buf.data (), buf.size (), MSG_PEEK,
			    (struct sockaddr*) &from, &sizefrom);
	      if (n > 0 && n <= 576)
		{
		  if (from.sin_addr.s_addr == stun.sin_addr.s_addr
		      && from.sin_port == stun.sin_port)
		    {
		      buf.resize (n);
		      recvfrom (udpsock, buf.data (), buf.size (), 0,
				(struct sockaddr*) &from, &sizefrom);
		      break;
		    }
		}
	      else
		{
		  std::cout << "Stun error!" << std::endl;
		  buf.resize (576);
		  recvfrom (udpsock, buf.data (), buf.size (), 0,
			    (struct sockaddr*) &from, &sizefrom);
		  result = std::make_pair (0, 0);
		  return result;
		}
	    }
	  else
	    {
	      std::cout << "Stun polling error!" << std::endl;
	      result = std::make_pair (0, 0);
	      return result;
	    }
	  count++;
	}
      if (count > 2)
	{
	  std::cout << "Stun error!" << std::endl;
	  result = std::make_pair (0, 0);
	  return result;
	}

      std::pair<uint32_t, uint16_t> xored;
      std::pair<uint32_t, uint16_t> notxored;
      int ch = 0;

      for (size_t i = 0; i < buf.size (); i++)
	{
	  uint16_t chk;
	  std::memcpy (&chk, &buf[i], sizeof(chk));
	  if (chk == htons (1))
	    {
	      if (buf[i + 5] == 1)
		{
		  uint32_t ip;
		  uint16_t port;
		  std::memcpy (&ip, &buf[i + 8], sizeof(ip));
		  std::memcpy (&port, &buf[i + 6], sizeof(port));
		  port = ntohs (port);
		  notxored = std::make_pair (ip, htons (port));
		  ch = 1;
		}
	    }

	  if (chk == htons (32))
	    {
	      if (buf[i + 5] == 1)
		{
		  uint16_t port;
		  std::memcpy (&port, &buf[i + 6], sizeof(port));
		  port = ntohs (port);
		  port ^= 8466;

		  uint32_t iptemp;
		  std::memcpy (&iptemp, &buf[i + 8], sizeof(iptemp));
		  iptemp = ntohl (iptemp);
		  iptemp ^= 554869826;
		  xored = std::make_pair (htonl (iptemp), htons (port));
		  ch = 2;
		}
	    }
	}
      if (ch == 1)
	{
	  result = notxored;
	  uint32_t ip = notxored.first;
	  uint16_t port = notxored.second;
	  std::vector<char> dat;
	  dat.resize (INET_ADDRSTRLEN);
	  std::cout << "Own ipv4:port "
	      << inet_ntop (AF_INET, &ip, dat.data (), dat.size ()) << ":"
	      << ntohs (port) << std::endl;
	}
      if (ch == 2)
	{
	  result = xored;
	  uint32_t ip = xored.first;
	  uint16_t port = xored.second;
	  std::vector<char> dat;
	  dat.resize (INET_ADDRSTRLEN);
	  std::cout << "Own x ipv4:port "
	      << inet_ntop (AF_INET, &ip, dat.data (), dat.size ()) << ":"
	      << ntohs (port) << std::endl;
	}
    }

  if (Netmode == "local" || Directinet == "direct")
    {
      uint32_t ip4;
      IPV4mtx.lock ();
      int ch = inet_pton (AF_INET, IPV4.c_str (), &ip4);
      IPV4mtx.unlock ();
      if (ch > 0)
	{
	  result.first = ip4;
	  sockaddr_in sin =
	    { };
	  socklen_t len = sizeof(sin);
	  if (getsockname (udpsock, (struct sockaddr*) &sin, &len) == -1)
	    {
	      result.second = 0;
	    }
	  else
	    {
	      result.second = sin.sin_port;
	    }
	}
      std::vector<char> dat;
      dat.resize (INET_ADDRSTRLEN);
      std::cout << "Own ipv4:port "
	  << inet_ntop (AF_INET, &ip4, dat.data (), dat.size ()) << ":"
	  << ntohs (result.second) << std::endl;
    }

  return result;
}

void
NetworkOperations::holePunch (int sock, uint32_t ip,
			      std::array<char, 32> otherkey)
{
  holepunchstopmtx.lock ();
  int firstport = 1024;
  auto hpsit = std::find_if (holepunchstop.begin (), holepunchstop.end (),
			     [otherkey]
			     (auto &el)
			       {
				 return std::get<0>(el) == otherkey;
			       });
  if (hpsit != holepunchstop.end ())
    {
      firstport = std::get<1> (*hpsit);
      if (firstport >= 65535)
	{
	  firstport = 1024;
	  std::get<1> (*hpsit) = firstport;
	}
    }
  else
    {
      firstport = 1024;
      holepunchstop.push_back (std::make_tuple (otherkey, firstport));
    }
  holepunchstopmtx.unlock ();
  std::vector<char> ipv;
  ipv.resize (INET_ADDRSTRLEN);
  uint32_t lip = ip;
  std::cout << "HP to " << inet_ntop (AF_INET, &lip, ipv.data (), ipv.size ())
      << std::endl;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> keypair;
  keypair = lt::dht::ed25519_create_keypair (seed);
  std::array<char, 32> key = std::get<0> (keypair).bytes;
  std::string msg = "TT";
  std::vector<char> msgv (key.begin (), key.end ());
  std::copy (msg.begin (), msg.end (), std::back_inserter (msgv));
  std::string unm = lt::aux::to_hex (otherkey);
  lt::dht::public_key othpk;
  othpk.bytes = otherkey;
  AuxFuncNet af;
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (keypair));
  othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
  std::string passwd = lt::aux::to_hex (othpk.bytes);
  msgv = af.cryptStrm (unm, passwd, msgv);

  for (int i = firstport; i < 65536; i = i + 1)
    {
      if (cancel > 0)
	{
	  break;
	}
      sockaddr_in op =
	{ };
      op.sin_family = AF_INET;
      op.sin_port = htons (i);
      op.sin_addr.s_addr = ip;
      int count = 0;
      int ch = -1;
      while (ch < 0)
	{
	  ch = sendto (sock, msgv.data (), msgv.size (), 0,
		       (struct sockaddr*) &op, sizeof(op));
	  if (ch < 0)
	    {
#ifdef __linux
	      std::cerr << "Hole punch error: " << strerror (errno)
		  << std::endl;
#endif
#ifdef _WIN32
	      ch = WSAGetLastError ();
	      std::cerr << "Hole punch error: " << ch << std::endl;
#endif
	    }
	  count++;
	  if (count > 10)
	    {
	      holepunchstopmtx.lock ();
	      hpsit = std::find_if (holepunchstop.begin (),
				    holepunchstop.end (), [otherkey]
				    (auto &el)
				      {
					return std::get<0>(el) == otherkey;
				      });
	      if (hpsit != holepunchstop.end ())
		{
		  std::get<1> (*hpsit) = i;
		}
	      else
		{
		  holepunchstop.push_back (std::make_tuple (otherkey, i));
		}
	      holepunchstopmtx.unlock ();
	      return void ();
	    }
	  usleep (100);
	}
    }
  holepunchstopmtx.lock ();
  hpsit = std::find_if (holepunchstop.begin (), holepunchstop.end (), [otherkey]
  (auto &el)
    {
      return std::get<0>(el) == otherkey;
    });
  if (hpsit != holepunchstop.end ())
    {
      std::get<1> (*hpsit) = 1024;
    }
  else
    {
      holepunchstop.push_back (std::make_tuple (otherkey, 1024));
    }
  holepunchstopmtx.unlock ();
}

int
NetworkOperations::receiveMsg (int sockipv4, sockaddr_in *from,
			       std::string relaykey,
			       std::vector<char> *relaymsg)
{
  int result = 0;
  AuxFuncNet af;
  int n;
  std::vector<char> buf;
  std::array<char, 32> chkey;
  int rcvip6 = 0;
  sockaddr_in6 from6 =
    { };
  socklen_t sizeoffrom6 = sizeof(from6);
  std::string msgtype = "";
  auto itsock = std::find_if (sockets4.begin (), sockets4.end (), [sockipv4]
  (auto &el)
    { return std::get<1>(el) == sockipv4;});
  if (itsock != sockets4.end ())
    {
      chkey = std::get<0> (*itsock);
    }
  buf.clear ();
  n = 0;
  buf.resize (507);
  socklen_t sizefrom = sizeof(*from);

  if (sockipv4 == sockipv6)
    {
      sockipv6mtx.lock ();
      n = recvfrom (sockipv6, buf.data (), buf.size (), MSG_PEEK,
		    (struct sockaddr*) &from6, &sizeoffrom6);
      sockipv6mtx.unlock ();
      if (n >= 0 && n <= 576)
	{
	  buf.clear ();
	  buf.resize (n);
	  recvfrom (sockipv6, buf.data (), buf.size (), MSG_PEEK,
		    (struct sockaddr*) &from6, &sizeoffrom6);
	  rcvip6 = 1;
	  std::vector<char> tmpmsg;
	  tmpmsg.resize (INET6_ADDRSTRLEN);
	  std::string chip = inet_ntop (AF_INET6, &from6.sin6_addr,
					tmpmsg.data (), tmpmsg.size ());
	  ipv6contmtx.lock ();
	  auto itip6 = std::find_if (ipv6cont.begin (), ipv6cont.end (), [&chip]
	  (auto &el)
	    {
	      return std::get<1>(el) == chip;
	    });
	  if (itip6 != ipv6cont.end ())
	    {
	      chkey = std::get<0> (*itip6);
	      std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
	      ownkey = lt::dht::ed25519_create_keypair (seed);
	      std::string unm = lt::aux::to_hex (std::get<0> (ownkey).bytes);
	      lt::dht::public_key othpk;
	      othpk.bytes = chkey;
	      std::array<char, 32> scalar;
	      scalar = lt::dht::ed25519_key_exchange (othpk,
						      std::get<1> (ownkey));
	      othpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey),
						   scalar);
	      std::string passwd = lt::aux::to_hex (othpk.bytes);
	      buf = af.decryptStrm (unm, passwd, buf);
	      std::array<char, 32> keyarr;
	      if (buf.size () >= 32)
		{
		  std::copy_n (buf.begin (), 32, keyarr.begin ());
		}
	      if (chkey != keyarr)
		{
		  recvfrom (sockipv6, buf.data (), buf.size (), 0,
			    (struct sockaddr*) &from6, &sizeoffrom6);
		  n = 0;
		}
	    }
	  else
	    {
	      recvfrom (sockipv6, buf.data (), buf.size (), 0,
			(struct sockaddr*) &from6, &sizeoffrom6);
	      n = 0;
	    }
	  ipv6contmtx.unlock ();
	}
    }
  else
    {
      if (relaykey == "")
	{
	  n = recvfrom (sockipv4, buf.data (), buf.size (), MSG_PEEK,
			(struct sockaddr*) from, &sizefrom);
	  if (n > 0)
	    {
	      buf.clear ();
	      buf.resize (n);
	      recvfrom (sockipv4, buf.data (), buf.size (), MSG_PEEK,
			(struct sockaddr*) from, &sizefrom);
	    }
	  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
	  ownkey = lt::dht::ed25519_create_keypair (seed);
	  std::string unm = lt::aux::to_hex (std::get<0> (ownkey).bytes);
	  lt::dht::public_key othpk;
	  othpk.bytes = chkey;
	  std::array<char, 32> scalar;
	  scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (ownkey));
	  othpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
	  std::string passwd = lt::aux::to_hex (othpk.bytes);
	  buf = af.decryptStrm (unm, passwd, buf);
	  std::array<char, 32> keyarr;
	  if (buf.size () >= 32)
	    {
	      std::copy_n (buf.begin (), 32, keyarr.begin ());
	    }
	  std::string key = lt::aux::to_hex (keyarr);
	  if (chkey != keyarr)
	    {
	      sockaddr_in delfrom =
		{ };
	      recvfrom (sockipv4, buf.data (), buf.size (), 0,
			(struct sockaddr*) &delfrom, &sizefrom);

	      n = 0;
	    }
	  else
	    {
	      result = 1;
	    }
	}
      else
	{
	  if (relaymsg)
	    {
	      n = relaymsg->size ();
	    }
	}
    }
  std::vector<char> tmpmsg;

  if (n > 0 && n <= 576)
    {
      if (relaykey == "")
	{
	  buf.clear ();
	  buf.resize (n);
	  if (rcvip6 == 0)
	    {
	      recvfrom (sockipv4, buf.data (), buf.size (), 0,
			(struct sockaddr*) from, &sizefrom);
	      uint32_t iptmp = from->sin_addr.s_addr;
	      uint16_t tmpp = from->sin_port;
	      tmpmsg.resize (INET_ADDRSTRLEN);
	      std::cout << "Rcvd fm "
		  << inet_ntop (AF_INET, &iptmp, tmpmsg.data (), tmpmsg.size ())
		  << ":" << ntohs (tmpp) << " Type ";
	    }
	  else
	    {
	      tmpmsg.resize (INET6_ADDRSTRLEN);
	      sockipv6mtx.lock ();
	      recvfrom (sockipv6, buf.data (), buf.size (), 0,
			(struct sockaddr*) &from6, &sizeoffrom6);
	      sockipv6mtx.unlock ();

	      std::cout << "Rcvd fm "
		  << inet_ntop (AF_INET6, &from6.sin6_addr, tmpmsg.data (),
				tmpmsg.size ()) << " "
		  << ntohs (from6.sin6_port) << " Type ";
	    }
	}
      else
	{
	  if (relaymsg)
	    {
	      std::cout << "Rcvd fm relay. Type ";
	      buf = *relaymsg;
	      lt::aux::from_hex (relaykey, chkey.data ());
	    }
	}

      std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
      ownkey = lt::dht::ed25519_create_keypair (seed);
      std::string unm = lt::aux::to_hex (std::get<0> (ownkey).bytes);
      lt::dht::public_key othpk;
      othpk.bytes = chkey;
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (ownkey));
      othpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
      std::string passwd = lt::aux::to_hex (othpk.bytes);
      buf = af.decryptStrm (unm, passwd, buf);
      std::array<char, 32> keyarr;
      if (buf.size () >= 32)
	{
	  std::copy_n (buf.begin (), 32, keyarr.begin ());
	}

      if (buf.size () >= 34)
	{
	  msgtype = std::string (buf.begin () + 32, buf.begin () + 34);
	}
      if (keyarr == chkey)
	{
	  time_t crtm = time (NULL);
	  maintblockmtx.lock ();
	  auto itmnt = std::find_if (maintblock.begin (), maintblock.end (),
				     [keyarr]
				     (auto &el)
				       {
					 return std::get<0>(el) == keyarr;
				       });
	  if (itmnt != maintblock.end ())
	    {
	      std::get<1> (*itmnt) = crtm;
	    }
	  else
	    {
	      maintblock.push_back (std::make_tuple (keyarr, crtm));
	    }
	  maintblockmtx.unlock ();
	  if (itsock != sockets4.end ())
	    {
	      std::get<3> (*itsock) = crtm;
	    }
	  if (rcvip6 > 0)
	    {
	      ipv6contmtx.lock ();
	      auto ipv6it = std::find_if (ipv6cont.begin (), ipv6cont.end (),
					  [keyarr]
					  (auto &el)
					    {
					      return std::get<0>(el) == keyarr;
					    });
	      if (ipv6it != ipv6cont.end ())
		{
		  std::vector<char> ipv6ad;
		  ipv6ad.resize (INET6_ADDRSTRLEN);
		  std::get<1> (*ipv6it) = inet_ntop (AF_INET6, &from6.sin6_addr,
						     ipv6ad.data (),
						     ipv6ad.size ());
		  std::get<2> (*ipv6it) = from6.sin6_port;
		}
	      else
		{
		  std::tuple<std::array<char, 32>, std::string, uint16_t, int> ttup;
		  std::vector<char> ipv6ad;
		  ipv6ad.resize (INET6_ADDRSTRLEN);
		  std::string ip6 = inet_ntop (AF_INET6, &from6.sin6_addr,
					       ipv6ad.data (), ipv6ad.size ());
		  uint16_t port6 = from6.sin6_port;
		  ttup = std::make_tuple (keyarr, ip6, port6, 1);
		  ipv6cont.push_back (ttup);
		}
	      ipv6contmtx.unlock ();
	      time_t ctm = time (NULL);
	      ipv6lrmtx.lock ();
	      auto itlr = std::find_if (ipv6lr.begin (), ipv6lr.end (), [keyarr]
	      (auto &el)
		{
		  return std::get<0>(el) == keyarr;
		});
	      if (itlr != ipv6lr.end ())
		{
		  std::get<1> (*itlr) = ctm;
		}
	      else
		{
		  ipv6lr.push_back (std::make_tuple (keyarr, ctm));
		}
	      ipv6lrmtx.unlock ();
	    }

	  result = 1;
	  if (msgtype == "TT")
	    {
	      std::cout << msgtype << std::endl;
	      if (smthrcvdsig)
		{
		  std::string key = lt::aux::to_hex (keyarr);
		  smthrcvdsig (key, crtm);
		}
	    }
	  bool relay = false;
	  if (relaykey != "")
	    {
	      relay = true;
	    }
	  if (buf.size () >= 50 && (msgtype == "MB" || msgtype == "PB"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMBPB (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			   relay);
	    }

	  if (buf.size () >= 50 && (msgtype == "Mb" || msgtype == "Pb"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMbPb (msgtype, keyarr, buf);
	    }

	  if (buf.size () >= 50 && (msgtype == "Mp" || msgtype == "Pp"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMpPp (msgtype, keyarr, buf);
	    }

	  if (buf.size () >= 50 && (msgtype == "Me" || msgtype == "Pe"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMePe (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			   relay);
	    }

	  if (buf.size () >= 42 && (msgtype == "ME" || msgtype == "PE"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMEPE (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			   relay);
	    }
	  if (buf.size () >= 42 && (msgtype == "MA" || msgtype == "PA"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMAPA (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 50 && (msgtype == "Mr" || msgtype == "Pr"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMrPr (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 42 && (msgtype == "MR" || msgtype == "PR"))
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMRPR (msgtype, keyarr, buf);
	    }
	  if (msgtype == "MI" || msgtype == "PI")
	    {
	      MsgProfileReceive mpr (this);
	      mpr.msgMIPI (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 50 && msgtype == "FQ")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFQ (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 42 && msgtype == "FJ")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFJ (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 42 && msgtype == "FA")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFA (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 50 && msgtype == "Fr")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFr (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			  relay);
	    }
	  if (buf.size () >= 42 && (msgtype == "FR" || msgtype == "FI"))
	    {
	      FileReceiveOp fop (this);
	      fop.fileFRFI (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 42 && msgtype == "FB")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFB (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			  relay);
	    }
	  if (buf.size () >= 42 && msgtype == "FH")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFH (msgtype, keyarr, buf);
	    }
	  if (buf.size () >= 50 && msgtype == "Fb")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFb (msgtype, keyarr, rcvip6, &from6, from, sockipv4, buf,
			  relay);
	    }
	  if (buf.size () >= 50 && msgtype == "Fp")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFp (msgtype, keyarr, buf);
	      if (rcvip6 > 0)
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv6, from,
				      &from6, relay);
		}
	      else
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv4, from,
				      &from6, relay);
		}
	    }
	  if (buf.size () >= 42 && msgtype == "Fe")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFe (msgtype, keyarr, buf);
	      if (rcvip6 > 0)
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv6, from,
				      &from6, relay);
		}
	      else
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv4, from,
				      &from6, relay);
		}
	    }
	  if (buf.size () >= 42 && msgtype == "FE")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFE (msgtype, keyarr, buf);
	      if (rcvip6 > 0)
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv6, from,
				      &from6, relay);
		}
	      else
		{
		  fop.fileProcessing (msgtype, chkey, rcvip6, sockipv4, from,
				      &from6, relay);
		}
	    }
	  if (buf.size () >= 42 && msgtype == "FF")
	    {
	      FileReceiveOp fop (this);
	      fop.fileFF (msgtype, keyarr, buf);
	    }
	}
    }

  return result;
}

int
NetworkOperations::sendMsg (int sockipv4, uint32_t ip, uint16_t port,
			    std::vector<char> &msg)
{
  sockaddr_in op =
    { };
  op.sin_family = AF_INET;
  op.sin_port = port;
  op.sin_addr.s_addr = ip;
  if (ip != 0 && port != 0)
    {
      int ch = sendto (sockipv4, msg.data (), msg.size (), 0,
		       (struct sockaddr*) &op, sizeof(op));
      if (ch < 0)
	{
#ifdef __linux
	  std::cerr << "ipv4 send error: " << strerror (errno) << std::endl;
#endif
#ifdef _WIN32
	  ch = WSAGetLastError ();
	  std::cerr << "ipv4 send error: " << ch << std::endl;
#endif
	}
      return ch;
    }
  else
    {
      return -1;
    }
}

int
NetworkOperations::sendMsg6 (int sock, std::string ip6, uint16_t port,
			     std::vector<char> &msg)
{
  sockaddr_in6 op =
    { };
  std::string ip6l = ip6;
  op.sin6_family = AF_INET6;
  op.sin6_port = port;
  inet_pton (AF_INET6, ip6l.c_str (), &op.sin6_addr);
  if (ip6 != "" && port != 0)
    {
      int ch = sendto (sock, msg.data (), msg.size (), 0,
		       (struct sockaddr*) &op, sizeof(op));
      if (ch < 0)
	{
#ifdef __linux
	  std::cerr << "ipv6 send error: " << strerror (errno) << std::endl;
#endif
#ifdef _WIN32
	  ch = WSAGetLastError ();
	  std::cerr << "ipv6 send error: " << ch << std::endl;
#endif
	}
      return ch;
    }
  else
    {
      return -1;
    }
}

void
NetworkOperations::getNewFriends (std::string key)
{
  AuxFuncNet af;
  std::array<char, 32> keyarr;
  lt::aux::from_hex (key, keyarr.data ());
  std::string filename = Home_Path;
  filename = filename + "/.Communist/Profile";
  std::filesystem::path source = std::filesystem::u8path (filename);
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  OutAuxFunc oaf;
  filename = filename + "/" + oaf.randomFileName () + "/Profile.zip";
  std::filesystem::path outpath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (outpath.parent_path ()))
    {
      std::filesystem::remove_all (outpath.parent_path ());
    }
  std::filesystem::create_directories (outpath.parent_path ());
  af.decryptFile (Username, Password, source.u8string (), outpath.u8string ());
  af.unpacking (outpath.u8string (), outpath.parent_path ().u8string ());
  std::filesystem::remove_all (outpath);
  filename = outpath.parent_path ().u8string ();
  filename = filename + "/Profile";
  source = std::filesystem::u8path (filename);
  if (std::filesystem::exists (source))
    {
      std::vector<std::filesystem::path> pv;
      for (auto &itdir : std::filesystem::directory_iterator (source))
	{
	  std::filesystem::path p = itdir.path ();
	  if (p.filename ().u8string () != "Avatar.jpeg"
	      && p.filename ().u8string () != "Profile")
	    {
	      pv.push_back (p);
	    }
	}
      for (size_t i = 0; i < pv.size (); i++)
	{
	  std::filesystem::remove_all (pv[i]);
	}
    }
  af.packing (source.u8string (), outpath.u8string ());
  source = outpath;
  filename = Home_Path;
  filename = filename + "/.Communist/SendBufer/";
  contfullmtx.lock ();
  auto itcont = std::find_if (contactsfull.begin (), contactsfull.end (),
			      [keyarr]
			      (auto &el)
				{
				  return std::get<1>(el) == keyarr;
				});
  if (itcont == contactsfull.end ())
    {
      std::tuple<int, std::array<char, 32>> p;
      contsizech = contsizech + 1;
      std::get<0> (p) = contsizech;
      std::get<1> (p) = keyarr;
      contactsfull.push_back (p);
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << std::get<0> (p);
      filename = filename + strm.str () + "/Profile";
      outpath = std::filesystem::u8path (filename);
      sendbufmtx.lock ();
      if (!std::filesystem::exists (outpath.parent_path ()))
	{
	  std::filesystem::create_directories (outpath.parent_path ());
	}
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (seed);
      lt::dht::public_key opk;
      std::string unm = key;
      lt::aux::from_hex (unm, opk.bytes.data ());
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (opk, std::get<1> (okp));
      opk = lt::dht::ed25519_add_scalar (opk, scalar);
      std::string passwd = lt::aux::to_hex (opk.bytes);
      af.cryptFile (unm, passwd, source.u8string (), outpath.u8string ());
      sendbufmtx.unlock ();
      contmtx.lock ();
      auto itcontn = std::find_if (contacts.begin (), contacts.end (), [keyarr]
      (auto &el)
	{
	  return std::get<1>(el) == keyarr;
	});
      if (itcontn == contacts.end ())
	{
	  contacts.push_back (p);
	}
      contmtx.unlock ();
    }
  std::filesystem::remove_all (source.parent_path ());
  contfullmtx.unlock ();

  getfrmtx.lock ();
  auto gfrit = std::find (getfr.begin (), getfr.end (), keyarr);
  if (gfrit == getfr.end ())
    {
      getfr.push_back (keyarr);
    }
  getfrmtx.unlock ();
  sockmtx.lock ();
  int ss = 0;
  auto itsock = std::find_if (sockets4.begin (), sockets4.end (), [keyarr]
  (auto &el)
    {
      return std::get<0>(el) == keyarr;
    });
  if (itsock == sockets4.end ())
    {
#ifdef __linux
      int sock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
      int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      u_long nonblocking_enabled = TRUE;
      ioctlsocket (sock, FIONBIO, &nonblocking_enabled);
#endif

      sockaddr_in addripv4 =
	{ };
      addripv4.sin_family = AF_INET;
      addripv4.sin_addr.s_addr = INADDR_ANY;
      addripv4.sin_port = 0;
      int addrlen1 = sizeof(addripv4);
      bind (sock, (const sockaddr*) &addripv4, addrlen1);
      std::mutex *mtx = new std::mutex;
      std::mutex *mtxgip = new std::mutex;
      time_t tm = time (NULL);
      sockets4.push_back (std::make_tuple (keyarr, sock, mtx, tm, mtxgip));
    }
  if (sockets4.size () == 1)
    {
      ss = 1;
    }
  sockmtx.unlock ();
  if (ss == 1)
    {
      std::mutex *thrmtx = new std::mutex;
      thrmtx->lock ();
      threadvectmtx.lock ();
      threadvect.push_back (std::make_tuple (thrmtx, "Get new friend"));
      threadvectmtx.unlock ();
      std::thread *thr = new std::thread ( [this, thrmtx]
      {
	if (this->copsrun.try_lock ())
	  {
	    this->commOps ();
	    this->copsrun.unlock ();
	  }
	thrmtx->unlock ();
      });
      thr->detach ();
      delete thr;
    }
}

int
NetworkOperations::sendMsgGlob (int sock, std::array<char, 32> keytos,
				uint32_t ip, uint16_t port)
{
  int result = 0;
  AuxFuncNet af;
  std::array<char, 32> keyarr = keytos;
  bool relay = false;
  sendbyrelaymtx.lock ();
  auto itsbr = std::find (sendbyrelay.begin (), sendbyrelay.end (), keyarr);
  if (itsbr != sendbyrelay.end ())
    {
      relay = true;
    }
  sendbyrelaymtx.unlock ();
  contmtx.lock ();
  auto itcont = std::find_if (contacts.begin (), contacts.end (), [keyarr]
  (auto &el)
    {
      return std::get<1>(el) == keyarr;
    });
  if (itcont != contacts.end ())
    {
      std::string index;
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << std::get<0> (*itcont);
      index = strm.str ();
      std::string filename = Home_Path;
      filename = filename + "/.Communist/SendBufer/" + index;
      std::filesystem::path filepath = std::filesystem::u8path (filename);

      if (std::filesystem::exists (filepath)
	  && std::filesystem::is_directory (filepath))
	{
	  filecanceledmtx.lock ();
	  for (size_t i = 0; i < filecanceled.size (); i++)
	    {
	      if (std::get<0> (filecanceled[i]) == keyarr)
		{
		  std::vector<char> msg;
		  std::array<char, 32> okarr;
		  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
		  okp = lt::dht::ed25519_create_keypair (seed);
		  lt::dht::public_key othpk;
		  othpk.bytes = keytos;
		  std::array<char, 32> scalar = lt::dht::ed25519_key_exchange (
		      othpk, std::get<1> (okp));
		  othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
		  std::string unm = lt::aux::to_hex (keytos);
		  std::string passwd = lt::aux::to_hex (othpk.bytes);
		  okarr = std::get<0> (okp).bytes;
		  std::copy (okarr.begin (), okarr.end (),
			     std::back_inserter (msg));
		  std::string msgtype;
		  msgtype = "FE";
		  std::copy (msgtype.begin (), msgtype.end (),
			     std::back_inserter (msg));
		  uint64_t tmfb = std::get<1> (filecanceled[i]);
		  msg.resize (msg.size () + sizeof(tmfb));
		  std::memcpy (&msg[34], &tmfb, sizeof(tmfb));
		  msg = af.cryptStrm (unm, passwd, msg);
		  time_t curtime = time (NULL);
		  int sent = 0;
		  ipv6lrmtx.lock ();
		  auto itlr6 = std::find_if (
		      ipv6lr.begin (), ipv6lr.end (), [keytos]
		      (auto &el)
			{
			  return std::get<0>(el) == keytos;
			});
		  if (itlr6 != ipv6lr.end ())
		    {
		      if (curtime - std::get<1> (*itlr6) <= Tmttear)
			{
			  ipv6contmtx.lock ();
			  auto itip6 = std::find_if (
			      ipv6cont.begin (), ipv6cont.end (), [keytos]
			      (auto &el)
				{
				  return std::get<0>(el) == keytos;
				});
			  if (itip6 != ipv6cont.end ())
			    {
			      std::string ipv6 = std::get<1> (*itip6);
			      uint16_t port = std::get<2> (*itip6);
			      sockipv6mtx.lock ();
			      sent = sendMsg6 (sockipv6, ipv6, port, msg);
			      sockipv6mtx.unlock ();
			      result = 1;
			    }
			  ipv6contmtx.unlock ();
			}
		    }
		  ipv6lrmtx.unlock ();
		  if (sent <= 0)
		    {
		      if (relay)
			{
			  std::vector<std::vector<char>> mrsb;
			  mrsb.push_back (msg);
			  ROp->relaySend (keytos, seed, mrsb);
			}
		      else
			{
			  sent = sendMsg (sock, ip, port, msg);
			}
		      result = 1;
		    }
		}
	    }
	  filecanceledmtx.unlock ();
	  std::vector<std::filesystem::path> pvect;
	  sendbufmtx.lock ();
	  for (auto &dirit : std::filesystem::directory_iterator (filepath))
	    {
	      std::filesystem::path p = dirit.path ();
	      pvect.push_back (p);
	    }
	  int totalsent = 0;
	  auto itpv = std::find_if (pvect.begin (), pvect.end (), []
	  (auto &el)
	    {
	      return el.filename ().u8string () == "Profile";
	    });
	  if (itpv != pvect.end ())
	    {
	      std::filesystem::path p = *itpv;
	      pvect.erase (itpv);
	      pvect.insert (pvect.begin (), p);
	      std::sort (pvect.begin () + 1, pvect.end (), []
	      (auto &el1, auto &el2)
		{
		  std::string corr = el1.filename ().u8string ();
		  corr = corr.substr (0, corr.find ("f"));
		  std::stringstream strm;
		  std::locale loc("C");
		  strm.imbue(loc);
		  strm << corr;
		  int one;
		  strm >> one;
		  corr = el2.filename ().u8string ();
		  corr = corr.substr (0, corr.find ("f"));
		  strm.str ("");
		  strm.clear ();
		  strm.imbue (loc);
		  strm << corr;
		  int two;
		  strm >> two;
		  return one < two;
		});
	    }
	  else
	    {
	      std::sort (pvect.begin (), pvect.end (), []
	      (auto &el1, auto &el2)
		{
		  std::string corr = el1.filename ().u8string ();
		  corr = corr.substr (0, corr.find ("f"));
		  std::stringstream strm;
		  std::locale loc("C");
		  strm.imbue(loc);
		  strm << corr;
		  int one;
		  strm >> one;
		  corr = el2.filename ().u8string ();
		  corr = corr.substr (0, corr.find ("f"));
		  strm.str ("");
		  strm.clear ();
		  strm.imbue (loc);
		  strm << corr;
		  int two;
		  strm >> two;
		  return one < two;
		});
	    }

	  for (size_t i = 0; i < pvect.size (); i++)
	    {
	      int variant = 0;
	      if (pvect[i].filename ().u8string () == "Profile")
		{
		  variant = 1; //Profile
		}
	      else
		{
		  std::string pathstr = pvect[i].filename ().u8string ();
		  std::string::size_type n;
		  n = pathstr.find ("f");
		  if (n == std::string::npos)
		    {
		      variant = 2; //msg
		    }
		  else
		    {
		      variant = 3; //file
		    }
		}
	      if (variant == 1 || variant == 2)
		{
		  MsgSending ms (this);
		  result = ms.sendMsg (pvect[i], keyarr, variant, sock, ip,
				       port, relay);
		}
	      if (variant == 3)
		{
		  FileSending fs (this);
		  result = fs.fileSending (pvect[i], keyarr, variant, sock, ip,
					   port, &totalsent, relay);
		}
	      if (totalsent > 1521)
		{
		  break;
		}
	    }
	  sendbufmtx.unlock ();
	}
    }
  contmtx.unlock ();
  return result;
}

void
NetworkOperations::removeFriend (std::string key)
{
  std::array<char, 32> keyloc;
  lt::aux::from_hex (key, keyloc.data ());
  cancelgetoips = 1;
  if (sockmtx.try_lock ())
    {
      auto itsock = std::find_if (sockets4.begin (), sockets4.end (), [keyloc]
      (auto &el)
	{
	  if (std::get<0>(el) == keyloc)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
      if (itsock != sockets4.end ())
	{
	  int sock = std::get<1> (*itsock);
	  std::mutex *mtx = std::get<2> (*itsock);
	  std::mutex *mtx2 = std::get<4> (*itsock);
	  if (mtx->try_lock ())
	    {
	      if (sock >= 0)
		{
#ifdef __linux
		  close (sock);
#endif
#ifdef _WIN32
		  closesocket (sock);
#endif
		}
	      mtx->unlock ();
	      delete mtx;
	      delete mtx2;
	      sockets4.erase (itsock);
	    }
	  else
	    {
	      std::mutex *thrmtx = new std::mutex;
	      thrmtx->lock ();
	      threadvectmtx.lock ();
	      threadvect.push_back (std::make_tuple (thrmtx, "deleteFriend"));
	      threadvectmtx.unlock ();
	      std::thread *thr = new std::thread ( [keyloc, this, thrmtx]
	      {
		usleep (100000);
		this->removeFriend (lt::aux::to_hex (keyloc));
		thrmtx->unlock ();
	      });
	      thr->detach ();
	      delete thr;
	      sockmtx.unlock ();
	      return void ();
	    }
	}
      sockmtx.unlock ();
    }
  else
    {
      if (friendDelPulse)
	{
	  friendDelPulse ();
	}
      std::mutex *thrmtx = new std::mutex;
      thrmtx->lock ();
      threadvectmtx.lock ();
      threadvect.push_back (std::make_tuple (thrmtx, "deleteFriend"));
      threadvectmtx.unlock ();
      std::thread *thr = new std::thread ( [keyloc, this, thrmtx]
      {
	usleep (100000);
	this->removeFriend (lt::aux::to_hex (keyloc));
	thrmtx->unlock ();
      });
      thr->detach ();
      delete thr;
      return void ();
    }

  addfrmtx.lock ();
  Addfriends.erase (std::remove (Addfriends.begin (), Addfriends.end (), key),
		    Addfriends.end ());
  addfrmtx.unlock ();

  contfullmtx.lock ();
  auto contit = std::find_if (contactsfull.begin (), contactsfull.end (),
			      [keyloc]
			      (auto &el)
				{
				  return std::get<1>(el) == keyloc;
				});
  if (contit != contactsfull.end ())
    {
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      std::string index;
      strm << std::get<0> (*contit);
      index = strm.str ();
      std::string filename = Home_Path;
      filename = filename + "/.Communist/SendBufer/" + index;
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (filepath))
	{
	  sendbufmtx.lock ();
	  std::filesystem::remove_all (filepath);
	  sendbufmtx.unlock ();
	}

      std::string line;
      int indep = std::get<0> (*contit);
      filename = Home_Path;
      filename = filename + "/.Communist/SendBufer";
      std::filesystem::path folderpath = std::filesystem::u8path (filename);
      std::vector<std::filesystem::path> pathvect;
      if (std::filesystem::exists (folderpath))
	{
	  for (auto &dir : std::filesystem::directory_iterator (folderpath))
	    {
	      std::filesystem::path old = dir.path ();
	      pathvect.push_back (old);
	    }
	  std::sort (pathvect.begin (), pathvect.end (), []
	  (auto &el1, auto el2)
	    {
	      std::string line1 = el1.filename().u8string();
	      std::string line2 = el2.filename().u8string();
	      return std::stoi(line1) < std::stoi(line2);
	    });
	  for (size_t i = 0; i < pathvect.size (); i++)
	    {
	      line = pathvect[i].filename ().u8string ();
	      strm.str ("");
	      strm.clear ();
	      strm.imbue (loc);
	      strm << line;
	      int tint;
	      strm >> tint;
	      if (tint > indep)
		{
		  tint = tint - 1;
		  strm.str ("");
		  strm.clear ();
		  strm.imbue (loc);
		  strm << tint;
		  line = pathvect[i].parent_path ().u8string ();
		  line = line + "/" + strm.str ();
		  std::filesystem::path newpath (
		      std::filesystem::u8path (line));
		  std::filesystem::rename (pathvect[i], newpath);
		}
	    }
	}

      filename = Home_Path;
      filename = filename + "/.Communist/Bufer/" + index;
      filepath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (filepath))
	{
	  std::filesystem::remove_all (filepath);
	}

      filename = Home_Path;
      filename = filename + "/.Communist/Bufer";
      folderpath = std::filesystem::u8path (filename);
      pathvect.clear ();
      if (std::filesystem::exists (folderpath))
	{
	  for (auto &dir : std::filesystem::directory_iterator (folderpath))
	    {
	      std::filesystem::path old = dir.path ();
	      pathvect.push_back (old);
	    }
	  std::sort (pathvect.begin (), pathvect.end (), []
	  (auto &el1, auto el2)
	    {
	      std::string line1 = el1.filename().u8string();
	      std::string line2 = el2.filename().u8string();
	      return std::stoi(line1) < std::stoi(line2);
	    });
	  for (size_t i = 0; i < pathvect.size (); i++)
	    {
	      line = pathvect[i].filename ().u8string ();
	      strm.str ("");
	      strm.clear ();
	      strm.imbue (loc);
	      strm << line;
	      int tint;
	      strm >> tint;
	      if (tint > indep)
		{
		  tint = tint - 1;
		  strm.str ("");
		  strm.clear ();
		  strm.imbue (loc);
		  strm << tint;
		  line = pathvect[i].parent_path ().u8string ();
		  line = line + "/" + strm.str ();
		  std::filesystem::path newpath (
		      std::filesystem::u8path (line));
		  std::filesystem::rename (pathvect[i], newpath);
		}
	    }
	}

      filename = Home_Path;
      filename = filename + "/.Communist/" + index;
      filepath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (filepath))
	{
	  std::filesystem::remove_all (filepath);
	}

      contactsfull.erase (contit);
      filename = Home_Path;
      filename = filename + "/.Communist";
      folderpath = std::filesystem::u8path (filename);
      pathvect.clear ();
      for (auto &dir : std::filesystem::directory_iterator (folderpath))
	{
	  std::filesystem::path old = dir.path ();
	  if (std::filesystem::is_directory (old)
	      && old.filename ().u8string () != "Bufer"
	      && old.filename ().u8string () != "SendBufer")
	    {
	      pathvect.push_back (old);
	    }
	}
      std::sort (pathvect.begin (), pathvect.end (), []
      (auto &el1, auto el2)
	{
	  std::string line1 = el1.filename().u8string();
	  std::string line2 = el2.filename().u8string();
	  return std::stoi(line1) < std::stoi(line2);
	});
      for (size_t i = 0; i < pathvect.size (); i++)
	{
	  line = pathvect[i].filename ().u8string ();
	  strm.str ("");
	  strm.clear ();
	  strm.imbue (loc);
	  strm << line;
	  int tint;
	  strm >> tint;
	  if (tint > indep)
	    {
	      tint = tint - 1;
	      strm.str ("");
	      strm.clear ();
	      strm.imbue (loc);
	      strm << tint;
	      line = pathvect[i].parent_path ().u8string ();
	      line = line + "/" + strm.str ();
	      std::filesystem::path newpath (std::filesystem::u8path (line));
	      std::filesystem::rename (pathvect[i], newpath);
	    }
	}
      for (size_t i = 0; i < contactsfull.size (); i++)
	{
	  if (std::get<0> (contactsfull[i]) > indep)
	    {
	      std::get<0> (contactsfull[i]) = std::get<0> (contactsfull[i]) - 1;
	    }
	}
      OutAuxFunc oaf;
      std::vector<std::tuple<std::string, std::vector<char>>> profvect;
      profvect = oaf.readProfile (Home_Path, Username, Password);
      std::vector<std::string> relaylist;
      relaylist = oaf.readRelayContacts (Home_Path, Username, Password);
      std::vector<std::tuple<int, std::string>> edprofvect;
      for (size_t i = 0; i < contactsfull.size (); i++)
	{
	  std::array<char, 32> keys = std::get<1> (contactsfull[i]);
	  std::string keyl = lt::aux::to_hex (keys);
	  edprofvect.push_back (
	      std::make_tuple (std::get<0> (contactsfull[i]), keyl));
	}
      oaf.editProfile (Username, Password, Home_Path, profvect, seed,
		       edprofvect, Addfriends, relaylist);
      contsizech = contsizech - 1;
      contmtx.lock ();
      contacts.erase (
	  std::remove_if (contacts.begin (), contacts.end (), [keyloc]
	  (auto &el)
	    {
	      return std::get<1>(el) == keyloc;
	    }),
	  contacts.end ());
      for (size_t i = 0; i < contacts.size (); i++)
	{
	  if (std::get<0> (contacts[i]) > indep)
	    {
	      std::get<0> (contacts[i]) = std::get<0> (contacts[i]) - 1;
	    }
	}
      contmtx.unlock ();
    }
  contfullmtx.unlock ();

  cancelgetoips = 0;

  msgpartbufmtx.lock ();
  msgpartbuf.erase (
      std::remove_if (msgpartbuf.begin (), msgpartbuf.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgpartbuf.end ());
  msgpartbufmtx.unlock ();

  msghashmtx.lock ();
  msghash.erase (std::remove_if (msghash.begin (), msghash.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 msghash.end ());
  msghashmtx.unlock ();

  msgparthashmtx.lock ();
  msgparthash.erase (
      std::remove_if (msgparthash.begin (), msgparthash.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgparthash.end ());
  msgparthashmtx.unlock ();

  msgpartrcvmtx.lock ();
  msgpartrcv.erase (
      std::remove_if (msgpartrcv.begin (), msgpartrcv.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgpartrcv.end ());
  msgpartrcvmtx.unlock ();

  msgpartbufmtx.lock ();
  msgpartbuf.erase (
      std::remove_if (msgpartbuf.begin (), msgpartbuf.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgpartbuf.end ());
  msgpartbufmtx.unlock ();

  msgrcvdpnummtx.lock ();
  msgrcvdpnum.erase (
      std::remove_if (msgrcvdpnum.begin (), msgrcvdpnum.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgrcvdpnum.end ());
  msgrcvdpnummtx.unlock ();

  getfrmtx.lock ();
  getfr.erase (std::remove_if (getfr.begin (), getfr.end (), [keyloc]
  (auto &el)
    {
      return el == keyloc;
    }),
	       getfr.end ());
  getfrmtx.unlock ();

  getfrresmtx.lock ();
  getfrres.erase (std::remove_if (getfrres.begin (), getfrres.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		  getfrres.end ());
  getfrresmtx.unlock ();

  putipmtx.lock ();
  putipv.erase (std::remove_if (putipv.begin (), putipv.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		putipv.end ());
  putipmtx.unlock ();

  ipv6contmtx.lock ();
  ipv6cont.erase (std::remove_if (ipv6cont.begin (), ipv6cont.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		  ipv6cont.end ());
  ipv6contmtx.unlock ();

  ipv6lrmtx.lock ();
  ipv6lr.erase (std::remove_if (ipv6lr.begin (), ipv6lr.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		ipv6lr.end ());
  ipv6lrmtx.unlock ();

  filesendreqmtx.lock ();
  filesendreq.erase (
      std::remove_if (filesendreq.begin (), filesendreq.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filesendreq.end ());
  filesendreqmtx.unlock ();

  fqrcvdmtx.lock ();
  fqrcvd.erase (std::remove_if (fqrcvd.begin (), fqrcvd.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		fqrcvd.end ());
  fqrcvdmtx.unlock ();

  filepartbufmtx.lock ();
  filepartbuf.erase (
      std::remove_if (filepartbuf.begin (), filepartbuf.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartbuf.end ());
  filepartbufmtx.unlock ();

  filehashvectmtx.lock ();
  filehashvect.erase (
      std::remove_if (filehashvect.begin (), filehashvect.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filehashvect.end ());
  filehashvectmtx.unlock ();

  fileparthashmtx.lock ();
  fileparthash.erase (
      std::remove_if (fileparthash.begin (), fileparthash.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      fileparthash.end ());
  fileparthashmtx.unlock ();

  filepartrcvmtx.lock ();
  filepartrcv.erase (
      std::remove_if (filepartrcv.begin (), filepartrcv.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartrcv.end ());
  filepartrcvmtx.unlock ();

  filepartrlogmtx.lock ();
  filepartrlog.erase (
      std::remove_if (filepartrlog.begin (), filepartrlog.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartrlog.end ());
  filepartrlogmtx.unlock ();

  currentpartmtx.lock ();
  currentpart.erase (
      std::remove_if (currentpart.begin (), currentpart.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      currentpart.end ());
  currentpartmtx.unlock ();

  fbrvectmtx.lock ();
  fbrvect.erase (std::remove_if (fbrvect.begin (), fbrvect.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 fbrvect.end ());
  fbrvectmtx.unlock ();

  filepartendmtx.lock ();
  filepartend.erase (
      std::remove_if (filepartend.begin (), filepartend.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartend.end ());
  filepartendmtx.unlock ();

  fileendmtx.lock ();
  fileend.erase (std::remove_if (fileend.begin (), fileend.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 fileend.end ());
  fileendmtx.unlock ();

  maintblockmtx.lock ();
  maintblock.erase (
      std::remove_if (maintblock.begin (), maintblock.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      maintblock.end ());
  maintblockmtx.unlock ();

  holepunchstopmtx.lock ();
  holepunchstop.erase (
      std::remove_if (holepunchstop.begin (), holepunchstop.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      holepunchstop.end ());
  holepunchstopmtx.unlock ();

  if (friendDeleted)
    {
      friendDeleted (lt::aux::to_hex (keyloc));
    }
}

bool
NetworkOperations::checkIfMsgSent (std::filesystem::path p)
{
  bool chk = true;
  std::string fnm = p.filename ().u8string ();
  std::string dirnm = p.parent_path ().filename ().u8string ();
  std::string filename = Home_Path + "/.Communist/SendBufer/" + dirnm + "/"
      + fnm;
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  sendbufmtx.lock ();
  if (std::filesystem::exists (filepath))
    {
      chk = false;
    }
  sendbufmtx.unlock ();
  return chk;
}

std::filesystem::path
NetworkOperations::formMsg (std::string key, std::string nick,
			    std::string replstr, std::filesystem::path msgpath,
			    int type)
{
  OutAuxFunc oaf;
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  filename = filename + "/" + oaf.randomFileName () + "commmsg";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  std::string ownkey = oaf.getKeyFmSeed (seed);
  std::fstream f;
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  std::string line;
  if (nick != "")
    {
      line = nick + " " + ownkey + "\n";
    }
  else
    {
      line = ownkey + "\n";
    }
  f.write (line.c_str (), line.size ());
  line = key + "\n";
  f.write (line.c_str (), line.size ());

  time_t curtm = time (NULL);
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << curtm;
  line = strm.str () + "\n";
  f.write (line.c_str (), line.size ());
  strm.clear ();
  strm.str ("");
  strm.imbue (loc);
  strm << type;
  line = strm.str () + "\n";
  f.write (line.c_str (), line.size ());
  line = "r";
  if (replstr != "")
    {
      std::filesystem::path chp = std::filesystem::u8path (replstr);
      if (chp.has_root_path ())
	{
	  replstr = "..." + chp.filename ().u8string ();
	}
      while (replstr.size () > 40)
	{
	  replstr.pop_back ();
	}
      line = line + " " + replstr + "\n";
    }
  else
    {
      line = line + "\n";
    }
  f.write (line.c_str (), line.size ());
  std::fstream fs;
  fs.open (msgpath, std::ios_base::in | std::ios_base::binary);
  int filesize = std::filesystem::file_size (msgpath);
  if (fs.is_open ())
    {
      if (filesize > 0)
	{
	  std::vector<char> readv;
	  int readbytes = 0;
	  for (;;)
	    {
	      readv.clear ();
	      if (filesize - readbytes > 16)
		{
		  readv.resize (16);
		}
	      else
		{
		  if (filesize - readbytes > 0)
		    {
		      readv.resize (filesize - readbytes);
		    }
		}
	      if (readv.size () > 0)
		{
		  fs.read (&readv[0], readv.size ());
		  f.write (&readv[0], readv.size ());
		  readbytes = readbytes + readv.size ();
		}
	      else
		{
		  break;
		}
	    }
	}
      fs.close ();
    }
  else
    {
      std::cerr << "Source file to form msg was not opened!" << std::endl;
    }
  f.close ();
  return createMsg (key, filepath, type);
}

std::filesystem::path
NetworkOperations::formMsg (std::string key, std::string nick,
			    std::string replstr, std::string msgstring,
			    int type)
{
  std::string filename;
#ifdef __linux
  filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
  OutAuxFunc oaf;
  filename = filename + "/" + oaf.randomFileName () + "commmsg";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
      std::filesystem::remove_all (filepath);
    }
  std::string ownkey = oaf.getKeyFmSeed (seed);
  std::fstream f;
  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  std::string line;
  if (nick != "")
    {
      line = nick + " " + ownkey + "\n";
    }
  else
    {
      line = ownkey + "\n";
    }
  f.write (line.c_str (), line.size ());
  line = key + "\n";
  f.write (line.c_str (), line.size ());

  time_t curtm = time (NULL);
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << curtm;
  line = strm.str () + "\n";
  f.write (line.c_str (), line.size ());
  strm.clear ();
  strm.str ("");
  strm.imbue (loc);
  strm << type;
  line = strm.str () + "\n";
  f.write (line.c_str (), line.size ());
  line = "r";
  if (replstr != "")
    {
      std::filesystem::path chp = std::filesystem::u8path (replstr);
      if (chp.has_root_path ())
	{
	  replstr = "..." + chp.filename ().u8string ();
	}
      while (replstr.size () > 40)
	{
	  replstr.pop_back ();
	}
      line = line + " " + replstr + "\n";
    }
  else
    {
      line = line + "\n";
    }
  f.write (line.c_str (), line.size ());
  line = msgstring;
  f.write (line.c_str (), line.size ());
  f.close ();
  return createMsg (key, filepath, type);
}

std::filesystem::path
NetworkOperations::createMsg (std::string key, std::filesystem::path p,
			      int type)
{
  AuxFuncNet af;
  lt::dht::public_key othkey;
  std::string usname = key;
  std::string passwd;

  std::filesystem::path result;
  lt::aux::from_hex (usname, othkey.bytes.data ());
  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
  okp = lt::dht::ed25519_create_keypair (seed);

  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (othkey, std::get<1> (okp));
  othkey = lt::dht::ed25519_add_scalar (othkey, scalar);
  passwd = lt::aux::to_hex (othkey.bytes);
  contfullmtx.lock ();
  contmtx.lock ();
  auto itcont = std::find_if (contacts.begin (), contacts.end (), [usname]
  (auto &el)
    {
      std::array<char, 32> keyarr;
      lt::aux::from_hex(usname, keyarr.data());
      return std::get<1>(el) == keyarr;
    });
  if (itcont != contacts.end ())
    {
      int ind = std::get<0> (*itcont);
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << ind;
      std::string index = strm.str ();
      std::string filename = Home_Path;
      filename = filename + "/.Communist/" + index;
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      std::vector<std::filesystem::path> pv;
      if (std::filesystem::exists (filepath))
	{
	  for (auto &dit : std::filesystem::directory_iterator (filepath))
	    {
	      std::filesystem::path d = dit.path ();
	      if (d.filename ().u8string () != "Profile"
		  && d.filename ().u8string () != "Yes")
		{
		  pv.push_back (d);
		}
	    }
	  std::string filenm;
	  if (pv.size () == 0)
	    {
	      filenm = "0";
	    }
	  else
	    {
	      std::sort (pv.begin (), pv.end (), []
	      (auto &el1, auto &el2)
		{
		  int first;
		  int second;
		  std::stringstream strm;
		  std::locale loc ("C");
		  strm.imbue(loc);
		  strm << el1.filename().u8string ();
		  strm >> first;
		  strm.str("");
		  strm.clear();
		  strm.imbue(loc);
		  strm << el2.filename().u8string();
		  strm >> second;
		  return first < second;
		});
	      strm.str ("");
	      strm.clear ();
	      strm.imbue (loc);
	      strm << pv[pv.size () - 1].filename ().u8string ();
	      int msgind;
	      strm >> msgind;
	      msgind = msgind + 1;
	      strm.str ("");
	      strm.clear ();
	      strm.imbue (loc);
	      strm << msgind;
	      filenm = strm.str ();
	    }
	  if (type == 1)
	    {
	      filenm = filenm + "f";
	    }
	  filename = filename + "/" + filenm;
	  filepath = std::filesystem::u8path (filename);
	  af.cryptFile (usname, passwd, p.u8string (), filepath.u8string ());
	  filename = Home_Path;
	  filename = filename + "/.Communist/SendBufer/" + index + "/" + filenm;
	  filepath = std::filesystem::u8path (filename);
	  sendbufmtx.lock ();
	  if (!std::filesystem::exists (filepath.parent_path ()))
	    {
	      std::filesystem::create_directories (filepath.parent_path ());
	    }
	  af.cryptFile (usname, passwd, p.u8string (), filepath.u8string ());

	  std::array<char, 32> keyarr;
	  lt::aux::from_hex (key, keyarr.data ());
	  af.updateMsgLog (Home_Path, Username, Password, keyarr,
			   filepath.filename ().u8string (), contactsfull);
	  sendbufmtx.unlock ();
	  filename = Home_Path + "/.Communist/"
	      + filepath.parent_path ().filename ().u8string () + "/"
	      + filepath.filename ().u8string ();
	  result = std::filesystem::u8path (filename);
	  std::filesystem::remove_all (p);
	}
    }
  contmtx.unlock ();
  contfullmtx.unlock ();

  return result;
}

void
NetworkOperations::renewProfile (std::string key)
{
  std::array<char, 32> lockey;
  lt::aux::from_hex (key, lockey.data ());
  contmtx.lock ();
  auto it = std::find_if (contacts.begin (), contacts.end (), [lockey]
  (auto &el)
    {
      return std::get<1>(el) == lockey;
    });
  if (it != contacts.end ())
    {
      AuxFuncNet af;
      int ind = std::get<0> (*it);
      std::locale loc ("C");
      std::stringstream strm;
      strm.imbue (loc);
      strm << ind;
      std::string index = strm.str ();
      std::string filename = Home_Path;
      filename = filename + "/.Communist/Profile";
      std::filesystem::path source = std::filesystem::u8path (filename);
#ifdef __linux
      filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
      filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
      OutAuxFunc oaf;
      filename = filename + "/" + oaf.randomFileName ();
      std::filesystem::path outpath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (outpath))
	{
	  std::filesystem::remove_all (outpath);
	}
      std::filesystem::create_directories (outpath);
      oaf.openProfile (Home_Path, Username, Password, outpath.u8string ());
      filename = outpath.u8string () + "/Profile";
      source = std::filesystem::u8path (filename);
      std::vector<std::filesystem::path> pv;
      for (auto &dit : std::filesystem::directory_iterator (source))
	{
	  std::filesystem::path p = dit.path ();
	  if (p.filename ().u8string () != "Profile"
	      && p.filename ().u8string () != "Avatar.jpeg")
	    {
	      pv.push_back (p);
	    }
	}
      for (size_t i = 0; i < pv.size (); i++)
	{
	  std::filesystem::remove_all (pv[i]);
	}
      filename = filename + ".zip";
      outpath = std::filesystem::u8path (filename);
      af.packing (source.u8string (), outpath.u8string ());
      source = outpath;
      filename = Home_Path;
      filename = filename + "/.Communist/SendBufer/" + index + "/Profile";
      outpath = std::filesystem::u8path (filename);
      sendbufmtx.lock ();
      if (!std::filesystem::exists (outpath.parent_path ()))
	{
	  std::filesystem::create_directories (outpath.parent_path ());
	}
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (seed);
      lt::dht::public_key opk;
      std::string unm = key;
      lt::aux::from_hex (unm, opk.bytes.data ());
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (opk, std::get<1> (okp));
      opk = lt::dht::ed25519_add_scalar (opk, scalar);
      std::string passwd = lt::aux::to_hex (opk.bytes);
      af.cryptFile (unm, passwd, source.u8string (), outpath.u8string ());
      sendbufmtx.unlock ();
      std::filesystem::remove_all (source.parent_path ());
    }
  contmtx.unlock ();
}

void
NetworkOperations::commOps ()
{
  if (Netmode == "local")
    {
      LNOp = new LocalNetworkOp (this);
    }
  sockmtx.lock ();
  getfrmtx.lock ();
  for (size_t i = 0; i < sockets4.size (); i++)
    {
      getfr.push_back (std::get<0> (sockets4[i]));
    }
  getfrmtx.unlock ();
  size_t sizesock = sockets4.size () + 1;
  sockmtx.unlock ();
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, time_t>> ownips;
  std::mutex *ownipsmtx = new std::mutex;
  std::vector<std::tuple<std::array<char, 32>, time_t>> blockip;
  std::mutex *blockipmtx = new std::mutex;
  std::vector<std::tuple<std::array<char, 32>, time_t>> lastsent;
  std::mutex *lastsentmtx = new std::mutex;
  std::vector<std::array<char, 32>> sendingthr;
  std::mutex *sendingthrmtx = new std::mutex;
  std::vector<std::tuple<std::array<char, 32>, time_t>> blockchsock;
  std::mutex *relthrmtx = new std::mutex;
  for (;;)
    {
      sockmtx.lock ();
      if (cancel > 0 || sockets4.size () == 0)
	{
	  sockmtx.unlock ();
	  break;
	}
      if (threadvectmtx.try_lock ())
	{
	  for (;;)
	    {
	      auto itthrv = std::find_if (
		  threadvect.begin (), threadvect.end (), []
		  (auto &el)
		    {
		      std::mutex *thrmtx = std::get<0>(el);
		      if (thrmtx->try_lock())
			{
			  thrmtx->unlock();
			  return true;
			}
		      else
			{
			  return false;
			}
		    });
	      if (itthrv != threadvect.end ())
		{
		  std::mutex *thrmtx = std::get<0> (*itthrv);
		  threadvect.erase (itthrv);
		  delete thrmtx;
		}
	      else
		{
		  break;
		}
	    }

	  threadvectmtx.unlock ();
	}

      std::vector<std::array<char, 32>> fordel;

      //Clean blockchsock vector
      for (size_t i = 0; i < blockchsock.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (blockchsock[i]);
	  auto it = std::find_if (sockets4.begin (), sockets4.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it == sockets4.end ())
	    {
	      fordel.push_back (key);
	    }
	}
      for (size_t i = 0; i < fordel.size (); i++)
	{
	  std::array<char, 32> key = fordel[i];
	  blockchsock.erase (
	      std::remove_if (blockchsock.begin (), blockchsock.end (), [key]
	      (auto &el)
		{
		  return std::get<0>(el) == key;
		}),
	      blockchsock.end ());
	}
      fordel.clear ();

      //Clean ownips vector
      ownipsmtx->lock ();
      for (size_t i = 0; i < ownips.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (ownips[i]);
	  auto it = std::find_if (sockets4.begin (), sockets4.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it == sockets4.end ())
	    {
	      fordel.push_back (key);
	    }
	}
      for (size_t i = 0; i < fordel.size (); i++)
	{
	  std::array<char, 32> key = fordel[i];
	  ownips.erase (std::remove_if (ownips.begin (), ownips.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    }),
			ownips.end ());
	}
      ownipsmtx->unlock ();
      fordel.clear ();

      //Clean blockip vector
      blockipmtx->lock ();
      for (size_t i = 0; i < blockip.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (blockip[i]);
	  auto it = std::find_if (sockets4.begin (), sockets4.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it == sockets4.end ())
	    {
	      fordel.push_back (key);
	    }
	}
      for (size_t i = 0; i < fordel.size (); i++)
	{
	  std::array<char, 32> key = fordel[i];
	  blockip.erase (std::remove_if (blockip.begin (), blockip.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    }),
			 blockip.end ());
	}
      blockipmtx->unlock ();
      fordel.clear ();

      lastsentmtx->lock ();
      for (size_t i = 0; i < lastsent.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (lastsent[i]);
	  auto it = std::find_if (sockets4.begin (), sockets4.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it == sockets4.end ())
	    {
	      fordel.push_back (key);
	    }
	}
      for (size_t i = 0; i < fordel.size (); i++)
	{
	  std::array<char, 32> key = fordel[i];
	  lastsent.erase (
	      std::remove_if (lastsent.begin (), lastsent.end (), [key]
	      (auto &el)
		{
		  return std::get<0>(el) == key;
		}),
	      lastsent.end ());
	}
      fordel.clear ();
      lastsentmtx->unlock ();
      sockmtx.unlock ();

      //Clean file request block vector
      time_t copscurtm = time (NULL);
      fqblockvmtx.lock ();
      fqblockv.erase (
	  std::remove_if (fqblockv.begin (), fqblockv.end (), [&copscurtm]
	  (auto &el)
	    {
	      if (copscurtm - std::get<3>(el) > 10)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    }),
	  fqblockv.end ());
      fqblockvmtx.unlock ();

      contmtx.lock ();
      for (size_t i = 0; i < contacts.size (); i++)
	{
	  if (smthrcvdsig)
	    {
	      std::array<char, 32> keyloc = std::get<1> (contacts[i]);
	      smthrcvdsig (lt::aux::to_hex (keyloc), 0);
	    }
	}
      contmtx.unlock ();

      //Change socket
      sockmtx.lock ();
      for (size_t i = 0; i < sockets4.size (); i++)
	{
	  time_t curtime = time (NULL);
	  time_t lr = std::get<3> (sockets4[i]);
	  std::array<char, 32> key = std::get<0> (sockets4[i]);
	  int addtime = 1;
	  holepunchstopmtx.lock ();
	  auto hpsit = std::find_if (holepunchstop.begin (),
				     holepunchstop.end (), [key]
				     (auto &el)
				       {
					 return std::get<0>(el) == key;
				       });
	  if (hpsit != holepunchstop.end ())
	    {
	      addtime = 2;
	    }

	  std::mutex *smtx = std::get<2> (sockets4[i]);
	  int sock = std::get<1> (sockets4[i]);
	  auto it = std::find_if (blockchsock.begin (), blockchsock.end (),
				  [key]
				  (auto &el)
				    {
				      return std::get<0>(el) == key;
				    });
	  if (it == blockchsock.end ())
	    {
	      blockchsock.push_back (std::make_tuple (key, curtime));
	    }
	  else
	    {
	      time_t lch = std::get<1> (*it);
	      if (curtime - lr > Tmttear
		  && curtime - lch > Tmttear * 5 * addtime)
		{
		  std::get<1> (*it) = curtime;
		  if (smtx)
		    {
		      smtx->lock ();
		      if (sock >= 0)
			{
#ifdef __linux
			  close (sock);
#endif
#ifdef _WIN32
                          closesocket (sock);
#endif
			}
#ifdef __linux
		      sock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK,
		      IPPROTO_UDP);
#endif
#ifdef _WIN32
		      sock = socket (AF_INET, SOCK_DGRAM,
		      IPPROTO_UDP);
		      u_long nonblocking_enabled = TRUE;
		      ioctlsocket (sock, FIONBIO, &nonblocking_enabled);
#endif
		      sockaddr_in addripv4 =
			{ };
		      addripv4.sin_family = AF_INET;
		      IPV4mtx.lock ();
		      inet_pton (AF_INET, IPV4.c_str (),
				 &addripv4.sin_addr.s_addr);
		      IPV4mtx.unlock ();
		      addripv4.sin_port = 0;
		      int addrlen1 = sizeof(addripv4);
		      bind (sock, (const sockaddr*) &addripv4, addrlen1);
		      std::get<1> (this->sockets4[i]) = sock;
		      std::get<3> (sockets4[i]) = curtime;
		      std::cerr << "Socket changed on " << lt::aux::to_hex (key)
			  << std::endl;
		      smtx->unlock ();
		      if (hpsit != holepunchstop.end ())
			{
			  holepunchstop.erase (hpsit);
			}
		    }

		  ownipsmtx->lock ();
		  auto itoip = std::find_if (ownips.begin (), ownips.end (),
					     [key]
					     (auto &el)
					       {
						 return std::get<0>(el) == key;
					       });
		  if (itoip != ownips.end ())
		    {
		      if (Netmode == "internet")
			{
			  ownips.erase (itoip);
			}
		      if (Netmode == "local")
			{
			  uint32_t ip;
			  IPV4mtx.lock ();
			  inet_pton (AF_INET, IPV4.c_str (), &ip);
			  IPV4mtx.unlock ();
			  sockaddr_in addressp =
			    { };
			  uint16_t port;
#ifdef __linux
			  uint len = sizeof(addressp);
#endif
#ifdef _WIN32
			  int len = sizeof(addressp);
#endif
			  getsockname (std::get<1> (sockets4[i]),
				       (sockaddr*) &addressp, &len);
			  port = addressp.sin_port;
			  std::get<1> (*itoip) = ip;
			  std::get<2> (*itoip) = port;
			  std::get<3> (*itoip) = curtime;
			}
		    }
		  ownipsmtx->unlock ();
		}
	    }
	  holepunchstopmtx.unlock ();
	}
      sockmtx.unlock ();

      //Receive own ips
      if (Netmode == "internet")
	{
	  std::mutex *thrmtx = nullptr;
	  if (threadvectmtx.try_lock ())
	    {
	      thrmtx = new std::mutex;
	      thrmtx->lock ();
	      threadvect.push_back (std::make_tuple (thrmtx, "Own ips"));
	      threadvectmtx.unlock ();
	    }
	  if (thrmtx != nullptr)
	    {
	      std::thread *throip = new std::thread (
		  std::bind (&NetworkOperations::getOwnIpsThread, this, thrmtx,
			     &ownips, ownipsmtx));
	      throip->detach ();
	      delete throip;
	    }
	}
      if (Netmode == "local" && ownips.size () == 0)
	{

	  time_t curtime = time (NULL);
	  uint32_t ip;
	  IPV4mtx.lock ();
	  inet_pton (AF_INET, IPV4.c_str (), &ip);
	  IPV4mtx.unlock ();
	  sockmtx.lock ();
	  for (size_t i = 0; i < sockets4.size (); i++)
	    {
	      sockaddr_in addressp =
		{ };
	      uint16_t port;
#ifdef __linux
	      uint len = sizeof(addressp);
#endif
#ifdef _WIN32
	      int len = sizeof(addressp);
#endif
	      getsockname (std::get<1> (sockets4[i]), (sockaddr*) &addressp,
			   &len);
	      port = addressp.sin_port;
	      std::array<char, 32> key = std::get<0> (sockets4[i]);
	      ownipsmtx->lock ();
	      auto itoip = std::find_if (ownips.begin (), ownips.end (), [key]
	      (auto &el)
		{
		  return std::get<0>(el) == key;
		});
	      if (itoip == ownips.end ())
		{
		  ownips.push_back (std::make_tuple (key, ip, port, curtime));
		}
	      ownipsmtx->unlock ();
	    }
	  sockmtx.unlock ();
	}

      //Get friends ips
      if (Netmode == "internet")
	{
	  std::mutex *thrmtx = nullptr;
	  if (threadvectmtx.try_lock ())
	    {
	      thrmtx = new std::mutex;
	      thrmtx->lock ();
	      threadvect.push_back (std::make_tuple (thrmtx, "Friend ips"));
	      threadvectmtx.unlock ();
	    }
	  if (thrmtx != nullptr)
	    {
	      std::thread *throthip = new std::thread (
		  std::bind (&NetworkOperations::getFriendIpsThread, this,
			     &blockip, blockipmtx, thrmtx));
	      throthip->detach ();
	      delete throthip;
	    }
	}

      //Connection maintenance
      sockmtx.lock ();
      for (size_t i = 0; i < sockets4.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (sockets4[i]);
	  time_t lr = std::get<3> (sockets4[i]);
	  time_t curtime = time (NULL);
	  time_t blocktime = 0;
	  time_t blockmaint = 0;
	  maintblockmtx.lock ();
	  auto itmnt = std::find_if (maintblock.begin (), maintblock.end (),
				     [key]
				     (auto &el)
				       {
					 return std::get<0>(el) == key;
				       });
	  if (itmnt != maintblock.end ())
	    {
	      blockmaint = std::get<1> (*itmnt);
	    }
	  else
	    {
	      maintblock.push_back (std::make_tuple (key, curtime));
	      blockmaint = curtime;
	    }
	  maintblockmtx.unlock ();
	  if (curtime - blockmaint <= Shuttmt)
	    {
	      lastsentmtx->lock ();
	      auto lsit = std::find_if (lastsent.begin (), lastsent.end (),
					[key]
					(auto &el)
					  {
					    return std::get<0>(el) == key;
					  });
	      if (lsit != lastsent.end ())
		{
		  blocktime = std::get<1> (*lsit);
		}

	      if (curtime - blocktime > 1)
		{
		  if (lsit != lastsent.end ())
		    {
		      std::get<1> (*lsit) = curtime;
		    }
		  else
		    {
		      lastsent.push_back (std::make_tuple (key, curtime));
		    }
		  int s = 0;
		  ipv6contmtx.lock ();
		  auto it6 = std::find_if (ipv6cont.begin (), ipv6cont.end (),
					   [key]
					   (auto &el)
					     {
					       return std::get<0>(el) == key;
					     });
		  if (it6 != ipv6cont.end () && ownipv6 != ""
		      && ownipv6port != 0)
		    {
		      std::string ip6 = std::get<1> (*it6);
		      uint16_t port = std::get<2> (*it6);
		      if (ip6 != "" && ip6 != "0" && port != 0)
			{
			  std::vector<char> msg;
			  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
			  ownkey = lt::dht::ed25519_create_keypair (this->seed);
			  std::array<char, 32> keyarr;
			  keyarr = std::get<0> (ownkey).bytes;
			  std::copy (keyarr.begin (), keyarr.end (),
				     std::back_inserter (msg));
			  msg.push_back ('T');
			  msg.push_back ('T');
			  std::string unm = lt::aux::to_hex (key);
			  lt::dht::public_key othpk;
			  AuxFuncNet af;
			  lt::aux::from_hex (unm, othpk.bytes.data ());
			  std::array<char, 32> scalar;
			  scalar = lt::dht::ed25519_key_exchange (
			      othpk, std::get<1> (ownkey));
			  othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
			  std::string passwd = lt::aux::to_hex (othpk.bytes);
			  msg = af.cryptStrm (unm, passwd, msg);
			  sockipv6mtx.lock ();
			  s = sendMsg6 (sockipv6, ip6, port, msg);
			  std::cout << "Maintenance message to " << ip6 << " "
			      << ntohs (port) << std::endl;
			  sockipv6mtx.unlock ();
			}
		    }
		  ipv6contmtx.unlock ();
		  int chiplr = 0;
		  ipv6lrmtx.lock ();
		  auto itipv6lr = std::find_if (
		      ipv6lr.begin (), ipv6lr.end (), [key]
		      (auto &el)
			{
			  return std::get<0>(el) == key;
			});
		  if (itipv6lr != ipv6lr.end ())
		    {
		      if (time (NULL) - std::get<1> (*itipv6lr) > Tmttear)
			{
			  chiplr = 1;
			}
		    }
		  else
		    {
		      chiplr = 1;
		    }
		  this->ipv6lrmtx.unlock ();
		  if (s <= 0 || chiplr > 0)
		    {
		      bool relay = false;
		      sendbyrelaymtx.lock ();
		      auto itsbr = std::find (sendbyrelay.begin (),
					      sendbyrelay.end (), key);
		      if (itsbr != sendbyrelay.end ())
			{
			  relay = true;
			}
		      sendbyrelaymtx.unlock ();
		      getfrresmtx.lock ();
		      auto it4 = std::find_if (
			  getfrres.begin (), getfrres.end (), [key]
			  (auto &el)
			    {
			      return std::get<0>(el) == key;
			    });
		      if (it4 != getfrres.end ())
			{
			  int sock = std::get<1> (sockets4[i]);
			  uint32_t ip = std::get<1> (*it4);
			  uint16_t port = std::get<2> (*it4);
			  if (ip != 0)
			    {
			      ownipsmtx->lock ();
			      auto itoip = std::find_if (
				  ownips.begin (), ownips.end (), [key]
				  (auto &el)
				    {
				      return std::get<0>(el) == key;
				    });
			      if (itoip != ownips.end ())
				{
				  if (port != 0 && std::get<2> (*itoip) != 0)
				    {
				      std::vector<char> msg;
				      std::tuple<lt::dht::public_key,
					  lt::dht::secret_key> ownkey;
				      ownkey = lt::dht::ed25519_create_keypair (
					  this->seed);
				      std::array<char, 32> keyarr;
				      keyarr = std::get<0> (ownkey).bytes;
				      std::copy (keyarr.begin (), keyarr.end (),
						 std::back_inserter (msg));
				      msg.push_back ('T');
				      msg.push_back ('T');
				      std::string unm = lt::aux::to_hex (key);
				      lt::dht::public_key othpk;
				      AuxFuncNet af;
				      lt::aux::from_hex (unm,
							 othpk.bytes.data ());
				      std::array<char, 32> scalar;
				      scalar = lt::dht::ed25519_key_exchange (
					  othpk, std::get<1> (ownkey));
				      othpk = lt::dht::ed25519_add_scalar (
					  othpk, scalar);
				      std::string passwd = lt::aux::to_hex (
					  othpk.bytes);
				      msg = af.cryptStrm (unm, passwd, msg);

				      if (relay)
					{
					  std::mutex *rmtx = new std::mutex;
					  rmtx->lock ();
					  threadvectmtx.lock ();
					  threadvect.push_back (
					      std::make_tuple (
						  rmtx, "Maint relay1 send"));
					  threadvectmtx.unlock ();
					  std::thread *relthr =
					      new std::thread (
						  [this, key, msg, rmtx]
						  {
						    std::vector<
							std::vector<char>> mrsb;
						    mrsb.push_back (msg);
						    this->ROp->relaySend (key,
									  seed,
									  mrsb);
						    std::cout
							<< "Maintenance message to "
							<< lt::aux::to_hex (key)
							<< std::endl;
						    rmtx->unlock ();
						  });
					  relthr->detach ();
					  delete relthr;

					}
				      else
					{
					  std::mutex *mtx = std::get<2> (
					      sockets4[i]);
					  mtx->lock ();
					  sendMsg (sock, ip, port, msg);
					  mtx->unlock ();
					  std::vector<char> tmpv;
					  tmpv.resize (INET_ADDRSTRLEN);
					  std::cout << "Maintenance message to "
					      << inet_ntop (AF_INET, &ip,
							    tmpv.data (),
							    tmpv.size ()) << ":"
					      << ntohs (port) << std::endl;
					}
				    }
				  else
				    {
				      if (curtime - lr > Tmttear)
					{
					  std::mutex *thrmtx = nullptr;
					  if (threadvectmtx.try_lock ())
					    {
					      thrmtx = new std::mutex;
					      thrmtx->lock ();
					      threadvect.push_back (
						  std::make_tuple (
						      thrmtx,
						      "Connection maintenance"));
					      threadvectmtx.unlock ();
					    }
					  if (thrmtx != nullptr)
					    {
					      std::thread *hpthr =
						  new std::thread (
						      std::bind (
							  &NetworkOperations::holePunchThr,
							  this, i, curtime,
							  sock, ip, thrmtx));
					      hpthr->detach ();
					      delete hpthr;
					    }
					}
				      else
					{
					  if (port != 0)
					    {
					      std::vector<char> msg;
					      std::tuple<lt::dht::public_key,
						  lt::dht::secret_key> ownkey;
					      ownkey =
						  lt::dht::ed25519_create_keypair (
						      this->seed);
					      std::array<char, 32> keyarr;
					      keyarr =
						  std::get<0> (ownkey).bytes;
					      std::copy (
						  keyarr.begin (),
						  keyarr.end (),
						  std::back_inserter (msg));
					      msg.push_back ('T');
					      msg.push_back ('T');
					      std::string unm =
						  lt::aux::to_hex (key);
					      lt::dht::public_key othpk;
					      AuxFuncNet af;
					      lt::aux::from_hex (
						  unm, othpk.bytes.data ());
					      std::array<char, 32> scalar;
					      scalar =
						  lt::dht::ed25519_key_exchange (
						      othpk,
						      std::get<1> (ownkey));
					      othpk =
						  lt::dht::ed25519_add_scalar (
						      othpk, scalar);
					      std::string passwd =
						  lt::aux::to_hex (othpk.bytes);
					      msg = af.cryptStrm (unm, passwd,
								  msg);
					      if (relay)
						{
						  std::mutex *rmtx =
						      new std::mutex;
						  rmtx->lock ();
						  threadvectmtx.lock ();
						  threadvect.push_back (
						      std::make_tuple (
							  rmtx,
							  "Maint relay2 send"));
						  threadvectmtx.unlock ();
						  std::thread *relthr =
						      new std::thread (
							  [this, key, msg, rmtx]
							  {
							    std::vector<
								std::vector<char>> mrsb;
							    mrsb.push_back (
								msg);
							    this->ROp->relaySend (
								key, seed,
								mrsb);
							    std::cout
								<< "Maintenance message to "
								<< lt::aux::to_hex (
								    key)
								<< std::endl;
							    rmtx->unlock ();
							  });
						  relthr->detach ();
						  delete relthr;
						}
					      else
						{
						  std::mutex *mtx =
						      std::get<2> (sockets4[i]);
						  mtx->lock ();
						  sendMsg (sock, ip, port, msg);
						  mtx->unlock ();
						  std::vector<char> tmpv;
						  tmpv.resize (INET_ADDRSTRLEN);
						  std::cout
						      << "Maintenance message to "
						      << inet_ntop (
							  AF_INET, &ip,
							  tmpv.data (),
							  tmpv.size ()) << ":"
						      << ntohs (port)
						      << std::endl;
						}
					    }
					}
				    }
				}

			      ownipsmtx->unlock ();
			    }
			  else
			    {
			      if (Netmode == "internet")
				{
				  std::string adr = "3.3.3.3";
				  uint32_t ip;
				  uint16_t port = htons (3000);
				  inet_pton (AF_INET, adr.c_str (), &ip);
				  int sock = std::get<1> (sockets4[i]);
				  std::vector<char> msg;
				  std::tuple<lt::dht::public_key,
				      lt::dht::secret_key> ownkey;
				  ownkey = lt::dht::ed25519_create_keypair (
				      this->seed);
				  std::array<char, 32> keyarr;
				  keyarr = std::get<0> (ownkey).bytes;
				  std::copy (keyarr.begin (), keyarr.end (),
					     std::back_inserter (msg));
				  msg.push_back ('T');
				  msg.push_back ('T');
				  std::string unm = lt::aux::to_hex (key);
				  lt::dht::public_key othpk;
				  AuxFuncNet af;
				  lt::aux::from_hex (unm, othpk.bytes.data ());
				  std::array<char, 32> scalar;
				  scalar = lt::dht::ed25519_key_exchange (
				      othpk, std::get<1> (ownkey));
				  othpk = lt::dht::ed25519_add_scalar (othpk,
								       scalar);
				  std::string passwd = lt::aux::to_hex (
				      othpk.bytes);
				  msg = af.cryptStrm (unm, passwd, msg);

				  if (relay)
				    {
				      std::mutex *rmtx = new std::mutex;
				      rmtx->lock ();
				      threadvectmtx.lock ();
				      threadvect.push_back (
					  std::make_tuple (
					      rmtx, "Maint relay3 send"));
				      threadvectmtx.unlock ();
				      std::thread *relthr = new std::thread (
					  [this, key, msg, rmtx]
					  {
					    std::vector<std::vector<char>> mrsb;
					    mrsb.push_back (msg);
					    this->ROp->relaySend (key, seed,
								  mrsb);
					    std::cout
						<< "Maintenance message to "
						<< lt::aux::to_hex (key)
						<< std::endl;
					    rmtx->unlock ();
					  });
				      relthr->detach ();
				      delete relthr;
				    }
				  else
				    {
				      std::mutex *mtx = std::get<2> (
					  sockets4[i]);
				      mtx->lock ();
				      sendMsg (sock, ip, port, msg);
				      mtx->unlock ();
				      std::vector<char> tmpv;
				      tmpv.resize (INET_ADDRSTRLEN);
				      std::cout << "Maintenance message to "
					  << inet_ntop (AF_INET, &ip,
							tmpv.data (),
							tmpv.size ()) << ":"
					  << ntohs (port) << std::endl;
				    }

				}
			    }
			}
		      else
			{
			  if (Netmode == "internet")
			    {
			      std::string adr = "3.3.3.3";
			      uint32_t ip;
			      uint16_t port = htons (3000);
			      inet_pton (AF_INET, adr.c_str (), &ip);
			      int sock = std::get<1> (sockets4[i]);
			      std::vector<char> msg;
			      std::tuple<lt::dht::public_key,
				  lt::dht::secret_key> ownkey;
			      ownkey = lt::dht::ed25519_create_keypair (
				  this->seed);
			      std::array<char, 32> keyarr;
			      keyarr = std::get<0> (ownkey).bytes;
			      std::copy (keyarr.begin (), keyarr.end (),
					 std::back_inserter (msg));
			      msg.push_back ('T');
			      msg.push_back ('T');
			      std::string unm = lt::aux::to_hex (key);
			      lt::dht::public_key othpk;
			      AuxFuncNet af;
			      lt::aux::from_hex (unm, othpk.bytes.data ());
			      std::array<char, 32> scalar;
			      scalar = lt::dht::ed25519_key_exchange (
				  othpk, std::get<1> (ownkey));
			      othpk = lt::dht::ed25519_add_scalar (othpk,
								   scalar);
			      std::string passwd = lt::aux::to_hex (
				  othpk.bytes);
			      msg = af.cryptStrm (unm, passwd, msg);
			      if (relay)
				{
				  std::mutex *rmtx = new std::mutex;
				  rmtx->lock ();
				  threadvectmtx.lock ();
				  threadvect.push_back (
				      std::make_tuple (rmtx,
						       "Maint relay4 send"));
				  threadvectmtx.unlock ();
				  std::thread *relthr = new std::thread (
				      [this, key, msg, rmtx]
				      {
					std::vector<std::vector<char>> mrsb;
					mrsb.push_back (msg);
					this->ROp->relaySend (key, seed, mrsb);
					std::cout << "Maintenance message to "
					    << lt::aux::to_hex (key)
					    << std::endl;
					rmtx->unlock ();
				      });
				  relthr->detach ();
				  delete relthr;
				}
			      else
				{
				  std::mutex *mtx = std::get<2> (sockets4[i]);
				  mtx->lock ();
				  sendMsg (sock, ip, port, msg);
				  mtx->unlock ();
				  std::vector<char> tmpv;
				  tmpv.resize (INET_ADDRSTRLEN);
				  std::cout << "Maintenance message to "
				      << inet_ntop (AF_INET, &ip, tmpv.data (),
						    tmpv.size ()) << ":"
				      << ntohs (port) << std::endl;
				}
			    }
			}
		      getfrresmtx.unlock ();
		    }
		}
	      lastsentmtx->unlock ();
	    }
	}
      sockmtx.unlock ();

      //Relay receive operations
      if (relthrmtx->try_lock ())
	{
	  std::mutex *relthr2mtx = new std::mutex;
	  relthr2mtx->lock ();
	  threadvectmtx.lock ();
	  threadvect.push_back (std::make_tuple (relthr2mtx, "Relay check"));
	  threadvectmtx.unlock ();
	  std::thread *relchthr =
	      new std::thread (
		  [this, relthrmtx, relthr2mtx]
		  {
		    std::tuple<uint32_t, uint16_t, std::shared_ptr<std::mutex>> ttup;
		    std::get<0> (ttup) = 0;
		    std::get<1> (ttup) = 0;
		    std::get<2> (ttup) = std::shared_ptr<std::mutex> (
			new std::mutex);
		    this->ROp->relayCheck (this->seed, &(this->cancel), ttup);
		    relthrmtx->unlock ();
		    relthr2mtx->unlock ();
		  });
	  relchthr->detach ();
	  delete relchthr;
	}

      //Polling
      std::vector<int> sforpoll;
      sockmtx.lock ();
      for (size_t i = 0; i < sockets4.size (); i++)
	{
	  std::mutex *mtxgip = std::get<4> (sockets4[i]);
	  if (mtxgip->try_lock ())
	    {
	      sforpoll.push_back (std::get<1> (sockets4[i]));
	      mtxgip->unlock ();
	    }
	}
      sockmtx.unlock ();
      sockipv6mtx.lock ();
      sforpoll.push_back (sockipv6);
      sizesock = sforpoll.size ();
      pollfd *fds = new pollfd[sforpoll.size ()];
      for (size_t i = 0; i < sforpoll.size (); i++)
	{
	  fds[i].fd = sforpoll[i];
	  fds[i].events = POLLRDNORM;
	}
      sockipv6mtx.unlock ();
      int respol = poll (fds, sizesock, 3000);
      if (respol < 0)
	{
#ifdef __linux
	  std::cerr << "Polling error: " << strerror (errno) << std::endl;
#endif
#ifdef _WIN32
	  respol = WSAGetLastError ();
	  std::cerr << "Polling error: " << respol << std::endl;
#endif
	}
      else
	{
	  if (respol > 0)
	    {
	      sockmtx.lock ();

	      for (size_t i = 0; i < sizesock; i++)
		{
		  if (fds[i].revents == POLLRDNORM)
		    {
		      int sock = fds[i].fd;
		      std::mutex *thrmtx = nullptr;
		      if (threadvectmtx.try_lock ())
			{
			  thrmtx = new std::mutex;
			  thrmtx->lock ();
			  threadvect.push_back (
			      std::make_tuple (thrmtx, "Commops poll"));
			  threadvectmtx.unlock ();
			}
		      if (thrmtx != nullptr)
			{
			  std::thread *rcvthr = new std::thread (
			      std::bind (&NetworkOperations::receiveMsgThread,
					 this, sock, thrmtx));
			  rcvthr->detach ();
			  delete rcvthr;
			}
		    }
		}
	      sockmtx.unlock ();
	    }
	}

      delete[] fds;

      //Send messages
      sockmtx.lock ();
      for (size_t i = 0; i < sockets4.size (); i++)
	{
	  if (cancel > 0)
	    {
	      break;
	    }
	  std::array<char, 32> key = std::get<0> (sockets4[i]);
	  int sock = std::get<1> (sockets4[i]);
	  std::mutex *mtx = std::get<2> (sockets4[i]);
	  time_t lrt4 = std::get<3> (sockets4[i]);
	  time_t curtime = time (NULL);
	  time_t lrt6 = 0;
	  ipv6lrmtx.lock ();
	  auto it6 = std::find_if (ipv6lr.begin (), ipv6lr.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it6 != ipv6lr.end ())
	    {
	      lrt6 = std::get<1> (*it6);
	    }
	  ipv6lrmtx.unlock ();
	  sendingthrmtx->lock ();
	  auto itth = std::find (sendingthr.begin (), sendingthr.end (), key);
	  if (itth == sendingthr.end ()
	      && (curtime - lrt4 <= Tmttear || curtime - lrt6 <= Tmttear))
	    {
	      std::mutex *thrmtxsm = nullptr;
	      if (threadvectmtx.try_lock ())
		{
		  sendingthr.push_back (key);
		  thrmtxsm = new std::mutex;
		  thrmtxsm->lock ();
		  threadvect.push_back (std::make_tuple (thrmtxsm, "Send msg"));
		  threadvectmtx.unlock ();
		}
	      if (thrmtxsm != nullptr)
		{
		  std::thread *sendthr = new std::thread (
		      std::bind (&NetworkOperations::sendMsgThread, this,
				 sendingthrmtx, &sendingthr, key, mtx, sock,
				 thrmtxsm));
		  sendthr->detach ();
		  delete sendthr;
		}
	    }
	  else
	    {
	      sendbyrelaymtx.lock ();
	      auto itsbr = std::find (sendbyrelay.begin (), sendbyrelay.end (),
				      key);
	      if (itsbr != sendbyrelay.end () && itth == sendingthr.end ())
		{
		  std::mutex *thrmtxsm = nullptr;
		  if (threadvectmtx.try_lock ())
		    {
		      sendingthr.push_back (key);
		      thrmtxsm = new std::mutex;
		      thrmtxsm->lock ();
		      threadvect.push_back (
			  std::make_tuple (thrmtxsm, "Send msg"));
		      threadvectmtx.unlock ();
		    }
		  if (thrmtxsm != nullptr)
		    {
		      std::thread *sendthr = new std::thread (
			  std::bind (&NetworkOperations::sendMsgThread, this,
				     sendingthrmtx, &sendingthr, key, mtx, sock,
				     thrmtxsm));
		      sendthr->detach ();
		      delete sendthr;
		    }
		}
	      sendbyrelaymtx.unlock ();
	    }
	  sendingthrmtx->unlock ();

	}
      sockmtx.unlock ();
    }
  delete ownipsmtx;
  delete blockipmtx;
  delete lastsentmtx;
  delete sendingthrmtx;
  delete relthrmtx;
}

void
NetworkOperations::fileReject (std::string key, uint64_t tm)
{
  AuxFuncNet af;
  std::array<char, 32> okarr;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
  okp = lt::dht::ed25519_create_keypair (seed);
  okarr = std::get<0> (okp).bytes;
  std::vector<char> msg;
  std::copy (okarr.begin (), okarr.end (), std::back_inserter (msg));
  std::string type = "FJ";
  std::copy (type.begin (), type.end (), std::back_inserter (msg));
  msg.resize (msg.size () + sizeof(tm));
  std::memcpy (&msg[34], &tm, sizeof(tm));
  uint64_t numb = 0;
  msg.resize (msg.size () + sizeof(numb));
  std::memcpy (&msg[42], &numb, sizeof(numb));
  std::string unm = key;
  lt::dht::public_key passkey;
  lt::aux::from_hex (unm, passkey.bytes.data ());
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (passkey, std::get<1> (okp));
  passkey = lt::dht::ed25519_add_scalar (passkey, scalar);
  std::string passwd = lt::aux::to_hex (passkey.bytes);
  msg = af.cryptStrm (unm, passwd, msg);
  time_t curtime = time (NULL);
  int sent = 0;
  std::array<char, 32> keyarr;
  lt::aux::from_hex (key, keyarr.data ());
  ipv6lrmtx.lock ();
  auto it6 = std::find_if (ipv6lr.begin (), ipv6lr.end (), [keyarr]
  (auto &el)
    {
      return std::get<0>(el) == keyarr;
    });
  if (it6 != ipv6lr.end ())
    {
      if (curtime - std::get<1> (*it6) <= Tmttear)
	{
	  ipv6contmtx.lock ();
	  auto it6c = std::find_if (ipv6cont.begin (), ipv6cont.end (), [keyarr]
	  (auto &el)
	    {
	      return std::get<0>(el) == keyarr;
	    });
	  if (it6c != ipv6cont.end ())
	    {
	      std::string ip = std::get<1> (*it6c);
	      uint16_t port = std::get<2> (*it6c);
	      sockipv6mtx.lock ();
	      int ch = sendMsg6 (sockipv6, ip, port, msg);
	      sockipv6mtx.unlock ();
	      if (ch > 0)
		{
		  sent = 1;
		}
	    }
	  ipv6contmtx.unlock ();
	}
    }
  ipv6lrmtx.unlock ();
  if (sent <= 0)
    {
      sockmtx.lock ();
      auto it4 = std::find_if (sockets4.begin (), sockets4.end (), [keyarr]
      (auto &el)
	{
	  return std::get<0>(el) == keyarr;
	});
      if (it4 != sockets4.end ())
	{
	  if (curtime - std::get<3> (*it4) <= Tmttear)
	    {
	      getfrresmtx.lock ();
	      auto itgfr = std::find_if (getfrres.begin (), getfrres.end (),
					 [keyarr]
					 (auto &el)
					   {
					     return std::get<0>(el) == keyarr;
					   });
	      if (itgfr != getfrres.end ())
		{
		  uint32_t ip = std::get<1> (*itgfr);
		  uint16_t port = std::get<2> (*itgfr);
		  std::mutex *mtx = std::get<2> (*it4);
		  mtx->lock ();
		  sendMsg (std::get<1> (*it4), ip, port, msg);
		  mtx->unlock ();
		}
	      getfrresmtx.unlock ();
	    }
	}
      sockmtx.unlock ();
    }

  fqrcvdmtx.lock ();
  fqrcvd.erase (std::remove_if (fqrcvd.begin (), fqrcvd.end (), [keyarr, tm]
  (auto &el)
    {
      if (std::get<0>(el) == keyarr && std::get<1>(el) == tm)
	{
	  return true;
	}
      else
	{
	  return false;
	}
    }),
		fqrcvd.end ());
  fqrcvdmtx.unlock ();
}

void
NetworkOperations::fileAccept (std::string key, uint64_t tm,
			       std::filesystem::path sp, bool fa)
{
  AuxFuncNet af;
  std::array<char, 32> okarr;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
  okp = lt::dht::ed25519_create_keypair (seed);
  okarr = std::get<0> (okp).bytes;
  std::vector<char> msg;
  std::copy (okarr.begin (), okarr.end (), std::back_inserter (msg));
  std::string type = "FA";
  std::copy (type.begin (), type.end (), std::back_inserter (msg));
  uint64_t lct = tm;
  msg.resize (msg.size () + sizeof(lct));
  std::memcpy (&msg[34], &lct, sizeof(lct));
  uint64_t numb = 0;
  msg.resize (msg.size () + sizeof(numb));
  std::memcpy (&msg[42], &numb, sizeof(numb));
  std::string unm = key;
  lt::dht::public_key passkey;
  lt::aux::from_hex (unm, passkey.bytes.data ());
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (passkey, std::get<1> (okp));
  passkey = lt::dht::ed25519_add_scalar (passkey, scalar);
  std::string passwd = lt::aux::to_hex (passkey.bytes);
  msg = af.cryptStrm (unm, passwd, msg);
  time_t curtime = time (NULL);
  int sent = 0;
  std::array<char, 32> keyarr;
  lt::aux::from_hex (key, keyarr.data ());
  ipv6lrmtx.lock ();
  auto it6 = std::find_if (ipv6lr.begin (), ipv6lr.end (), [keyarr]
  (auto &el)
    {
      return std::get<0>(el) == keyarr;
    });
  if (it6 != ipv6lr.end ())
    {
      if (curtime - std::get<1> (*it6) <= Tmttear)
	{
	  ipv6contmtx.lock ();
	  auto it6c = std::find_if (ipv6cont.begin (), ipv6cont.end (), [keyarr]
	  (auto &el)
	    {
	      return std::get<0>(el) == keyarr;
	    });
	  if (it6c != ipv6cont.end ())
	    {
	      std::string ip = std::get<1> (*it6c);
	      uint16_t port = std::get<2> (*it6c);
	      sockipv6mtx.lock ();
	      int ch = sendMsg6 (sockipv6, ip, port, msg);
	      sockipv6mtx.unlock ();
	      if (ch > 0)
		{
		  sent = 1;
		}
	    }
	  ipv6contmtx.unlock ();
	}
    }
  ipv6lrmtx.unlock ();
  if (sent <= 0)
    {
      bool relay = false;
      sendbyrelaymtx.lock ();
      auto itsbr = std::find (sendbyrelay.begin (), sendbyrelay.end (), keyarr);
      if (itsbr != sendbyrelay.end ())
	{
	  relay = true;
	}
      sendbyrelaymtx.unlock ();
      if (relay)
	{
	  if (ROp)
	    {
	      std::mutex *mtx = new std::mutex;
	      mtx->lock ();
	      threadvectmtx.lock ();
	      threadvect.push_back (
		  std::make_tuple (mtx, "fileAccept relay send"));
	      threadvectmtx.unlock ();
	      std::vector<char> *smsg = new std::vector<char>;
	      *smsg = msg;
	      std::thread *thr = new std::thread ( [this, keyarr, smsg, mtx]
	      {
		std::vector<std::vector<char>> msgsbuf;
		msgsbuf.push_back (*smsg);
		delete smsg;
		this->ROp->relaySend (keyarr, this->seed, msgsbuf);
		mtx->unlock ();
	      });
	      thr->detach ();
	      delete thr;
	    }
	}
      else
	{
	  if (!fa)
	    {
	      sockmtx.lock ();
	    }
	  auto it4 = std::find_if (sockets4.begin (), sockets4.end (), [keyarr]
	  (auto &el)
	    {
	      return std::get<0>(el) == keyarr;
	    });
	  if (it4 != sockets4.end ())
	    {
	      if (curtime - std::get<3> (*it4) <= Tmttear)
		{
		  getfrresmtx.lock ();
		  auto itgfr = std::find_if (
		      getfrres.begin (), getfrres.end (), [keyarr]
		      (auto &el)
			{
			  return std::get<0>(el) == keyarr;
			});
		  if (itgfr != getfrres.end ())
		    {
		      uint32_t ip = std::get<1> (*itgfr);
		      uint16_t port = std::get<2> (*itgfr);
		      std::mutex *mtx = std::get<2> (*it4);
		      if (!fa)
			{
			  mtx->lock ();
			}
		      sendMsg (std::get<1> (*it4), ip, port, msg);
		      if (!fa)
			{
			  mtx->unlock ();
			}
		    }
		  getfrresmtx.unlock ();
		}
	    }
	  if (!fa)
	    {
	      sockmtx.unlock ();
	    }
	}
    }
  filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      filehashvect.begin (), filehashvect.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tm)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv == filehashvect.end ())
    {
      std::vector<char> hv;
      filehashvect.push_back (std::make_tuple (keyarr, tm, hv, sp, -1));
    }
  filehashvectmtx.unlock ();
}

void
NetworkOperations::blockFriend (std::string key)
{
  cancelgetoips = 1;
  std::array<char, 32> keyloc;
  lt::aux::from_hex (key, keyloc.data ());
  if (sockmtx.try_lock ())
    {
      auto itsock = std::find_if (sockets4.begin (), sockets4.end (), [keyloc]
      (auto &el)
	{
	  if (std::get<0>(el) == keyloc)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
      if (itsock != sockets4.end ())
	{
	  int sock = std::get<1> (*itsock);
	  std::mutex *mtx = std::get<2> (*itsock);
	  if (mtx->try_lock ())
	    {
	      if (sock >= 0)
		{
#ifdef __linux
		  close (sock);
#endif
#ifdef _WIN32
		  closesocket (sock);
#endif
		}
	      mtx->unlock ();
	      sockets4.erase (itsock);
	    }
	  else
	    {
	      std::thread *thr = new std::thread ( [keyloc, this]
	      {
		usleep (100000);
		this->blockFriend (lt::aux::to_hex (keyloc));
	      });
	      thr->detach ();
	      delete thr;
	      sockmtx.unlock ();
	      return void ();
	    }
	}
      sockmtx.unlock ();
    }
  else
    {
      if (friendDelPulse)
	{
	  friendDelPulse ();
	}
      std::thread *thr = new std::thread ( [keyloc, this]
      {
	usleep (100000);
	this->blockFriend (lt::aux::to_hex (keyloc));
      });
      thr->detach ();
      delete thr;
      return void ();
    }
  cancelgetoips = 0;
  addfrmtx.lock ();
  Addfriends.erase (std::remove (Addfriends.begin (), Addfriends.end (), key),
		    Addfriends.end ());
  addfrmtx.unlock ();

  contmtx.lock ();
  auto contit = std::find_if (contacts.begin (), contacts.end (), [keyloc]
  (auto &el)
    {
      return std::get<1>(el) == keyloc;
    });
  if (contit != contacts.end ())
    {
      contacts.erase (contit);
    }
  contmtx.unlock ();

  msgpartbufmtx.lock ();
  msgpartbuf.erase (
      std::remove_if (msgpartbuf.begin (), msgpartbuf.end (), [keyloc]
      (auto &el)
	{ return std::get<0>(el) == keyloc;}),
      msgpartbuf.end ());
  msgpartbufmtx.unlock ();

  msghashmtx.lock ();
  msghash.erase (std::remove_if (msghash.begin (), msghash.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 msghash.end ());
  msghashmtx.unlock ();

  msgparthashmtx.lock ();
  msgparthash.erase (
      std::remove_if (msgparthash.begin (), msgparthash.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgparthash.end ());
  msgparthashmtx.unlock ();

  msgpartrcvmtx.lock ();
  msgpartrcv.erase (
      std::remove_if (msgpartrcv.begin (), msgpartrcv.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgpartrcv.end ());
  msgpartrcvmtx.unlock ();

  msgpartbufmtx.lock ();
  msgpartbuf.erase (
      std::remove_if (msgpartbuf.begin (), msgpartbuf.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgpartbuf.end ());
  msgpartbufmtx.unlock ();

  msgrcvdpnummtx.lock ();
  msgrcvdpnum.erase (
      std::remove_if (msgrcvdpnum.begin (), msgrcvdpnum.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      msgrcvdpnum.end ());
  msgrcvdpnummtx.unlock ();

  getfrmtx.lock ();
  getfr.erase (std::remove_if (getfr.begin (), getfr.end (), [keyloc]
  (auto &el)
    {
      return el == keyloc;
    }),
	       getfr.end ());
  getfrmtx.unlock ();

  getfrresmtx.lock ();
  getfrres.erase (std::remove_if (getfrres.begin (), getfrres.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		  getfrres.end ());
  getfrresmtx.unlock ();

  putipmtx.lock ();
  putipv.erase (std::remove_if (putipv.begin (), putipv.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		putipv.end ());
  putipmtx.unlock ();

  ipv6contmtx.lock ();
  ipv6cont.erase (std::remove_if (ipv6cont.begin (), ipv6cont.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		  ipv6cont.end ());
  ipv6contmtx.unlock ();

  ipv6lrmtx.lock ();
  ipv6lr.erase (std::remove_if (ipv6lr.begin (), ipv6lr.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		ipv6lr.end ());
  ipv6lrmtx.unlock ();

  filesendreqmtx.lock ();
  filesendreq.erase (
      std::remove_if (filesendreq.begin (), filesendreq.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filesendreq.end ());
  filesendreqmtx.unlock ();

  fqrcvdmtx.lock ();
  fqrcvd.erase (std::remove_if (fqrcvd.begin (), fqrcvd.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		fqrcvd.end ());
  fqrcvdmtx.unlock ();

  filepartbufmtx.lock ();
  filepartbuf.erase (
      std::remove_if (filepartbuf.begin (), filepartbuf.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartbuf.end ());
  filepartbufmtx.unlock ();

  filehashvectmtx.lock ();
  filehashvect.erase (
      std::remove_if (filehashvect.begin (), filehashvect.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filehashvect.end ());
  filehashvectmtx.unlock ();

  fileparthashmtx.lock ();
  fileparthash.erase (
      std::remove_if (fileparthash.begin (), fileparthash.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      fileparthash.end ());
  fileparthashmtx.unlock ();

  filepartrcvmtx.lock ();
  filepartrcv.erase (
      std::remove_if (filepartrcv.begin (), filepartrcv.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartrcv.end ());
  filepartrcvmtx.unlock ();

  filepartrlogmtx.lock ();
  filepartrlog.erase (
      std::remove_if (filepartrlog.begin (), filepartrlog.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartrlog.end ());
  filepartrlogmtx.unlock ();

  currentpartmtx.lock ();
  currentpart.erase (
      std::remove_if (currentpart.begin (), currentpart.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      currentpart.end ());
  currentpartmtx.unlock ();

  fbrvectmtx.lock ();
  fbrvect.erase (std::remove_if (fbrvect.begin (), fbrvect.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 fbrvect.end ());
  fbrvectmtx.unlock ();

  filepartendmtx.lock ();
  filepartend.erase (
      std::remove_if (filepartend.begin (), filepartend.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      filepartend.end ());
  filepartendmtx.unlock ();

  fileendmtx.lock ();
  fileend.erase (std::remove_if (fileend.begin (), fileend.end (), [keyloc]
  (auto &el)
    {
      return std::get<0>(el) == keyloc;
    }),
		 fileend.end ());
  fileendmtx.unlock ();

  maintblockmtx.lock ();
  maintblock.erase (
      std::remove_if (maintblock.begin (), maintblock.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      maintblock.end ());
  maintblockmtx.unlock ();

  holepunchstopmtx.lock ();
  holepunchstop.erase (
      std::remove_if (holepunchstop.begin (), holepunchstop.end (), [keyloc]
      (auto &el)
	{
	  return std::get<0>(el) == keyloc;
	}),
      holepunchstop.end ());
  holepunchstopmtx.unlock ();

  if (friendBlockedSig)
    {
      friendBlockedSig ();
    }
}

void
NetworkOperations::startFriend (std::string key, int ind)
{
  std::array<char, 32> keyarr;
  lt::aux::from_hex (key, keyarr.data ());
  std::mutex *thrmtxgl = new std::mutex;
  thrmtxgl->lock ();
  threadvectmtx.lock ();
  threadvect.push_back (std::make_tuple (thrmtxgl, "startFriend"));
  threadvectmtx.unlock ();
  std::thread *thr = new std::thread ( [this, thrmtxgl, keyarr, ind]
  {
    this->contmtx.lock ();
    auto itcont = std::find_if (this->contacts.begin (), this->contacts.end (),[ keyarr]
  (auto &el)
    {
      return std::get<1>(el) == keyarr;
    });
    if (itcont == this->contacts.end ())
      {
	std::pair<int, std::array<char, 32>> p;
	std::get<0> (p) = ind;
	std::get<1> (p) = keyarr;
	this->contacts.push_back (p);
      }
    this->contmtx.unlock ();

    this->getfrmtx.lock ();
    auto gfrit = std::find (this->getfr.begin (), this->getfr.end (), keyarr);
    if (gfrit == this->getfr.end ())
      {
	this->getfr.push_back (keyarr);
      }
    this->getfrmtx.unlock ();
    this->sockmtx.lock ();
    int ss = 0;
    auto itsock = std::find_if (this->sockets4.begin (), this->sockets4.end (),
				[keyarr]
				(auto &el)
				  {
				    return std::get<0>(el) == keyarr;
				  });
    if (itsock == this->sockets4.end ())
      {
#ifdef __linux
	int sock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
	int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	u_long nonblocking_enabled = TRUE;
	ioctlsocket (sock, FIONBIO, &nonblocking_enabled);
#endif
	sockaddr_in addripv4 =
	  { };
	addripv4.sin_family = AF_INET;
	addripv4.sin_addr.s_addr = INADDR_ANY;
	addripv4.sin_port = 0;
	int addrlen1 = sizeof(addripv4);
	bind (sock, (const sockaddr*) &addripv4, addrlen1);
	std::mutex *mtx = new std::mutex;
	std::mutex *mtxgip = new std::mutex;
	time_t tm = time (NULL);
	this->sockets4.push_back (
	    std::make_tuple (keyarr, sock, mtx, tm, mtxgip));
      }
    if (this->sockets4.size () == 1)
      {
	ss = 1;
      }
    this->sockmtx.unlock ();
    if (ss == 1)
      {
	std::mutex *thrmtx = new std::mutex;
	thrmtx->lock ();
	this->threadvectmtx.lock ();
	this->threadvect.push_back (std::make_tuple (thrmtx, "Start friend"));
	this->threadvectmtx.unlock ();
	std::thread *thr = new std::thread ( [this, thrmtx]
	{
	  if (this->copsrun.try_lock ())
	    {
	      this->commOps ();
	      this->copsrun.unlock ();
	    }
	  thrmtx->unlock ();
	});
	thr->detach ();
	delete thr;
      }
    thrmtxgl->unlock ();
  });
  thr->detach ();
  delete thr;
}

void
NetworkOperations::setIPv6 (std::string ip)
{
  ownipv6mtx.lock ();
  ownipv6 = ip;
  ownipv6mtx.unlock ();
}

void
NetworkOperations::dnsFunc ()
{
  std::mutex *thrmtx = new std::mutex;
  thrmtx->lock ();
  threadvectmtx.lock ();
  threadvect.push_back (std::make_tuple (thrmtx, "Dns func"));
  threadvectmtx.unlock ();
  std::thread *dnsthr = new std::thread ( [this, thrmtx]
  {
    if (this->Directinet == "notdirect")
      {
	std::vector<std::pair<std::string, std::string>> readstun;
	AuxFuncNet af;
	std::string filename;
	std::filesystem::path filepath;
	filename = Sharepath;
	filepath = std::filesystem::u8path (filename);
	if (!std::filesystem::exists (filepath))
	  {
	    std::cout << "StunList not found!" << std::endl;
	  }
	else
	  {
	    std::fstream f;
	    f.open (filepath, std::ios_base::in);
	    while (!f.eof ())
	      {
		std::string line;
		getline (f, line);
		if (line != "")
		  {
		    std::pair<std::string, std::string> p;
		    p.first = line;
		    p.first = p.first.substr (0, p.first.find (" "));
		    p.second = line;
		    p.second = p.second.erase (0, p.second.find (" ") + std::string ( " ").size ());
		    readstun.push_back (p);
		  }
	      }
	    f.close ();
	  }
	for (size_t i = 0; i < readstun.size (); i++)
	  {
	    if (cancel == 1)
	      {
		thrmtx->unlock ();
		return void ();
	      }
	    std::pair<struct in_addr, uint16_t> p;
	    std::string line = readstun[i].second;
	    uint16_t port;
	    std::stringstream strm;
	    std::locale loc ("C");
	    strm.imbue (loc);
	    strm << line;
	    strm >> port;
	    p.second = htons (port);
	    line = readstun[i].first;
	    int ch = inet_pton (AF_INET, line.c_str (), &p.first);
	    if (ch < 1)
	      {
		hostent *hn;
		hn = gethostbyname (readstun.at (i).first.c_str ());
		if (hn != nullptr)
		  {
		    int count = 0;
		    for (;;)
		      {
			if (cancel == 1)
			  {
			    thrmtx->unlock ();
			    return void ();
			  }
			if ((struct in_addr*) hn->h_addr_list[count] == nullptr)
			  {
			    break;
			  }
			p.first = *(struct in_addr*) hn->h_addr_list[count];
			count++;
			this->stunipsmtx.lock ();
			auto iter = std::find_if (
			    this->stunips.begin (), this->stunips.end (), [&p]
			    (auto &el)
			      {
				if (p.first.s_addr == el.first.s_addr &&
				    p.second == el.second)
				  {
				    return true;
				  }
				else
				  {
				    return false;
				  }
			      });
			if (iter == this->stunips.end ())
			  {
			    this->stunips.push_back (p);
			  }
			this->stunipsmtx.unlock ();
		      }
		  }
	      }
	    else
	      {
		this->stunipsmtx.lock ();
		auto iter = std::find_if (
		    this->stunips.begin (), this->stunips.end (), [&p]
		    (auto &el)
		      {
			if (p.first.s_addr == el.first.s_addr &&
			    p.second == el.second)
			  {
			    return true;
			  }
			else
			  {
			    return false;
			  }
		      });
		if (iter == this->stunips.end ())
		  {
		    this->stunips.push_back (p);
		  }
		this->stunipsmtx.unlock ();
	      }
	  }

	readstun.clear ();
      }
    if (dnsfinished)
      {
	this->dnsfinished ();
      }
    thrmtx->unlock ();
  });
  dnsthr->detach ();
  delete dnsthr;
}

void
NetworkOperations::setIPv4 (std::string ip)
{
  IPV4mtx.lock ();
  IPV4 = ip;
  IPV4mtx.unlock ();
}

std::filesystem::path
NetworkOperations::removeMsg (std::string key, std::filesystem::path msgpath)
{
  AuxFuncNet af;
  std::filesystem::remove_all (msgpath);
  std::string ind = msgpath.filename ().u8string ();
  ind = ind.substr (0, ind.find ("f"));
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << ind;
  int indint;
  strm >> indint;
  for (auto &dirit : std::filesystem::directory_iterator (
      msgpath.parent_path ()))
    {
      std::filesystem::path p = dirit.path ();
      if (p.filename ().u8string () != "Profile"
	  && p.filename ().u8string () != "Yes")
	{
	  int tmpi;
	  ind = p.filename ().u8string ();
	  std::string::size_type n;
	  n = ind.find ("f");
	  ind = ind.substr (0, n);
	  strm.clear ();
	  strm.str ("");
	  strm.imbue (loc);
	  strm << ind;
	  strm >> tmpi;
	  if (tmpi > indint)
	    {
	      tmpi = tmpi - 1;
	      strm.clear ();
	      strm.str ("");
	      strm.imbue (loc);
	      strm << tmpi;
	      ind = p.parent_path ().u8string ();
	      ind = ind + "/" + strm.str ();
	      if (n != std::string::npos)
		{
		  ind = ind + "f";
		}
	      std::filesystem::path np = std::filesystem::u8path (ind);
	      std::filesystem::rename (p, np);
	    }
	}
    }
  std::string filename;
  filename = msgpath.parent_path ().u8string ();
  filename = filename + "/Yes";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  if (std::filesystem::exists (filepath))
    {
#ifdef __linux
      filename = std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
      filename = std::filesystem::temp_directory_path ().parent_path ().u8string ();
#endif
      OutAuxFunc oaf;
      filename = filename + "/" + oaf.randomFileName () + "/YesPr";
      std::filesystem::path outpath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (outpath.parent_path ()))
	{
	  std::filesystem::remove_all (outpath.parent_path ());
	}
      std::filesystem::create_directories (outpath.parent_path ());

      af.decryptFile (Username, Password, filepath.u8string (),
		      outpath.u8string ());
      std::fstream f;
      std::vector<std::string> tv;
      f.open (outpath, std::ios_base::in);
      while (!f.eof ())
	{
	  std::string line;
	  getline (f, line);
	  if (line != "")
	    {
	      tv.push_back (line);
	    }
	}
      f.close ();
      tv.erase (std::remove_if (tv.begin () + 1, tv.end (), [&indint]
      (auto &el)
	{
	  std::string tmp = el;
	  tmp = tmp.substr(0, tmp.find(" "));
	  std::stringstream strm;
	  std::locale loc ("C");
	  strm.imbue(loc);
	  strm << tmp;
	  int tint;
	  strm >> tint;
	  if (tint == indint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
		tv.end ());
      for (size_t i = 1; i < tv.size (); i++)
	{
	  std::string tmp = tv[i];
	  tmp = tmp.substr (0, tmp.find (" "));
	  strm.clear ();
	  strm.str ("");
	  strm.imbue (loc);
	  strm << tmp;
	  int tint;
	  strm >> tint;
	  if (tint > indint)
	    {
	      tint = tint - 1;
	      strm.clear ();
	      strm.str ("");
	      strm.imbue (loc);
	      strm << tint;
	      tmp = tv[i];
	      tmp.erase (0, tmp.find (" ") + std::string (" ").size ());
	      tmp = strm.str () + " " + tmp;
	      tv[i] = tmp;
	    }
	}
      if (tv.size () > 1)
	{
	  f.open (outpath, std::ios_base::out | std::ios_base::binary);
	  for (size_t i = 0; i < tv.size (); i++)
	    {
	      std::string line = tv[i];
	      line = line + "\n";
	      f.write (line.c_str (), line.size ());
	    }
	  f.close ();
	  af.cryptFile (Username, Password, outpath.u8string (),
			filepath.u8string ());
	}
      else
	{
	  std::filesystem::remove_all (filepath);
	}
      std::filesystem::remove_all (outpath.parent_path ());
    }

  filename = Home_Path;
  filename = filename + "/.Communist/SendBufer/"
      + msgpath.parent_path ().filename ().u8string () + "/"
      + msgpath.filename ().u8string ();
  std::filesystem::path npath = std::filesystem::u8path (filename);
  std::filesystem::path retpath;
  sendbufmtx.lock ();
  if (std::filesystem::exists (npath))
    {
      filename = npath.filename ().u8string ();
      std::string::size_type n;
      n = filename.find ("f");
      std::string nmrnm;
      if (n == std::string::npos)
	{
	  msgpartbufmtx.lock ();
	  msgpartbuf.erase (
	      std::remove_if (msgpartbuf.begin (), msgpartbuf.end (), [&npath]
	      (auto &el)
		{
		  return std::get<3>(el) == npath;
		}),
	      msgpartbuf.end ());
	  msgpartbufmtx.unlock ();
	  std::filesystem::remove_all (npath);
	  nmrnm = npath.filename ().u8string ();
	}
      else
	{
	  nmrnm = npath.filename ().u8string ();
	  nmrnm = nmrnm.substr (0, nmrnm.find ("f"));
	  std::string unm = key;
	  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
	  okp = lt::dht::ed25519_create_keypair (seed);
	  lt::dht::public_key pkpass;
	  lt::aux::from_hex (unm, pkpass.bytes.data ());
	  std::array<char, 32> scalar;
	  scalar = lt::dht::ed25519_key_exchange (pkpass, std::get<1> (okp));
	  pkpass = lt::dht::ed25519_add_scalar (pkpass, scalar);
	  std::string passwd = lt::aux::to_hex (pkpass.bytes);
	  filename = npath.parent_path ().u8string ();
	  filename = filename + "/TmpMsg";
	  std::filesystem::path outpath = std::filesystem::u8path (filename);
	  af.decryptFile (unm, passwd, npath.u8string (), outpath.u8string ());
	  std::fstream f;
	  int count = 0;
	  f.open (outpath, std::ios_base::in);
	  while (!f.eof ())
	    {
	      getline (f, filename);
	      if (count == 5)
		{
		  break;
		}
	      count++;
	    }
	  f.close ();
	  std::filesystem::path sp = std::filesystem::u8path (filename);
	  retpath = sp;
	  filepartbufmtx.lock ();
	  auto itfpb = std::find_if (filepartbuf.begin (), filepartbuf.end (),
				     [sp]
				     (auto &el)
				       {
					 return std::get<2> (el) == sp;
				       });
	  if (itfpb != filepartbuf.end ())
	    {
	      std::get<3> (*itfpb) = std::filesystem::file_size (sp);
	      std::get<6> (*itfpb) = 1;
	      std::tuple<std::array<char, 32>, time_t> ttup;
	      std::array<char, 32> keyarr;
	      lt::aux::from_hex (key, keyarr.data ());
	      std::get<0> (ttup) = keyarr;
	      std::get<1> (ttup) = std::get<1> (*itfpb);
	      filecanceledmtx.lock ();
	      filecanceled.push_back (ttup);
	      filecanceledmtx.unlock ();
	    }
	  filepartbufmtx.unlock ();
	  std::filesystem::remove_all (outpath);
	  std::filesystem::remove_all (npath);
	}
      filename = Home_Path;
      filename = filename + "/.Communist/SendBufer/"
	  + msgpath.parent_path ().filename ().u8string ();
      std::filesystem::path dirp = std::filesystem::u8path (filename);
      std::stringstream strm;
      std::locale loc ("C");
      int indint;
      strm.imbue (loc);
      strm << nmrnm;
      strm >> indint;
      for (auto &dirit : std::filesystem::directory_iterator (dirp))
	{
	  std::filesystem::path p = dirit.path ();
	  int tmpi;
	  std::string ind = p.filename ().u8string ();
	  std::string::size_type n;
	  n = ind.find ("f");
	  ind = ind.substr (0, n);
	  strm.clear ();
	  strm.str ("");
	  strm.imbue (loc);
	  strm << ind;
	  strm >> tmpi;
	  if (tmpi > indint)
	    {
	      tmpi = tmpi - 1;
	      strm.clear ();
	      strm.str ("");
	      strm.imbue (loc);
	      strm << tmpi;
	      ind = p.parent_path ().u8string ();
	      ind = ind + "/" + strm.str ();
	      if (n != std::string::npos)
		{
		  ind = ind + "f";
		}
	      std::filesystem::path np = std::filesystem::u8path (ind);
	      std::filesystem::rename (p, np);
	    }
	}

    }
  sendbufmtx.unlock ();
  return retpath;
}

void
NetworkOperations::cancelAll ()
{
  cancel = 1;
  std::thread *thr = new std::thread (
      [this]
      {
	for (;;)
	  {
	    if (this->threadvectmtx.try_lock ())
	      {
		for (;;)
		  {
		    auto itthrv = std::find_if (
			this->threadvect.begin (), this->threadvect.end (), []
			(auto &el)
			  {
			    std::mutex *gmtx = std::get<0>(el);

			    if (gmtx)
			      {
				if (gmtx->try_lock())
				  {
				    gmtx->unlock();
				    return true;
				  }
				else
				  {
				    return false;
				  }
			      }
			    else
			      {
				return true;
			      }

			  });
		    if (itthrv != this->threadvect.end ())
		      {
			std::mutex *gmtx = std::get<0> (*itthrv);
			this->threadvect.erase (itthrv);
			delete gmtx;
		      }
		    if (this->threadvect.size () == 0)
		      {
			break;
		      }
		    usleep (100);
		  }
		this->threadvectmtx.unlock ();
		break;
	      }
	    usleep (100);
	  }
	if (this->canceled)
	  {
	    this->canceled ();
	  }
      });
  thr->detach ();
  delete thr;
}

void
NetworkOperations::cancelSendF (std::string key, std::filesystem::path filepath)
{
  filepartbufmtx.lock ();
  auto itfpb = std::find_if (filepartbuf.begin (), filepartbuf.end (),
			     [filepath]
			     (auto &el)
			       {
				 return std::get<2> (el) == filepath;
			       });
  if (itfpb != filepartbuf.end ())
    {
      std::get<3> (*itfpb) = std::filesystem::file_size (filepath);
      std::get<6> (*itfpb) = 1;
      std::tuple<std::array<char, 32>, time_t> ttup;
      std::array<char, 32> keyarr;
      lt::aux::from_hex (key, keyarr.data ());
      std::get<0> (ttup) = keyarr;
      std::get<1> (ttup) = std::get<1> (*itfpb);
      filecanceledmtx.lock ();
      filecanceled.push_back (ttup);
      filecanceledmtx.unlock ();
    }
  filepartbufmtx.unlock ();
}

void
NetworkOperations::cancelReceivF (std::string key,
				  std::filesystem::path filepath)
{
  uint64_t tm = 0;
  std::array<char, 32> keyarr;
  lt::aux::from_hex (key, keyarr.data ());
  filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      filehashvect.begin (), filehashvect.end (), [keyarr, filepath]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<3>(el) == filepath)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != filehashvect.end ())
    {
      tm = std::get<1> (*itfhv);
      filehashvect.erase (itfhv);
    }
  filehashvectmtx.unlock ();

  filesendreqmtx.lock ();
  filesendreq.erase (
      std::remove_if (filesendreq.begin (), filesendreq.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<2>(el) == tm)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      filesendreq.end ());
  filesendreqmtx.unlock ();

  fqrcvdmtx.lock ();
  fqrcvd.erase (std::remove_if (fqrcvd.begin (), fqrcvd.end (), [keyarr, tm]
  (auto &el)
    {
      if (std::get<0>(el) == keyarr && std::get<1>(el) == tm)
	{
	  return true;
	}
      else
	{
	  return false;
	}
    }),
		fqrcvd.end ());
  fqrcvdmtx.unlock ();

  fileparthashmtx.lock ();
  fileparthash.erase (
      std::remove_if (fileparthash.begin (), fileparthash.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tm)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      fileparthash.end ());
  fileparthashmtx.unlock ();

  filepartrcvmtx.lock ();
  filepartrcv.erase (
      std::remove_if (filepartrcv.begin (), filepartrcv.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == uint64_t(tm))
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      filepartrcv.end ());
  filepartrcvmtx.unlock ();

  filepartrlogmtx.lock ();
  filepartrlog.erase (
      std::remove_if (filepartrlog.begin (), filepartrlog.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == uint64_t(tm))
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      filepartrlog.end ());
  filepartrlogmtx.unlock ();

  currentpartmtx.lock ();
  currentpart.erase (
      std::remove_if (currentpart.begin (), currentpart.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == uint64_t(tm))
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      currentpart.end ());
  currentpartmtx.unlock ();

  fbrvectmtx.lock ();
  fbrvect.erase (std::remove_if (fbrvect.begin (), fbrvect.end (), [keyarr, tm]
  (auto &el)
    {
      if (std::get<0>(el) == keyarr && std::get<1>(el) == tm)
	{
	  return true;
	}
      else
	{
	  return false;
	}
    }),
		 fbrvect.end ());
  fbrvectmtx.unlock ();

  filepartendmtx.lock ();
  filepartend.erase (
      std::remove_if (filepartend.begin (), filepartend.end (), [keyarr, tm]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == uint64_t(tm))
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      filepartend.end ());
  filepartendmtx.unlock ();

  fileendmtx.lock ();
  fileend.erase (std::remove_if (fileend.begin (), fileend.end (), [keyarr, tm]
  (auto &el)
    {
      if (std::get<0>(el) == keyarr && std::get<1>(el) == uint64_t(tm))
	{
	  return true;
	}
      else
	{
	  return false;
	}
    }),
		 fileend.end ());
  fileendmtx.unlock ();
}

#ifdef _WIN32
int
NetworkOperations::poll (struct pollfd *pfd, int nfds, int timeout)
{
  return WSAPoll (pfd, nfds, timeout);
}
#endif

void
NetworkOperations::stunSrv ()
{
  int addrlen = 0;
  if (Enablestun == "active")
    {
#ifdef __linux
      int stnsrvsock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
      int stnsrvsock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      u_long nonblocking_enabled = TRUE;
      int ch = 0;
      ioctlsocket (stnsrvsock, FIONBIO, &nonblocking_enabled);
#endif
      sockaddr_in stunsrvaddr =
	{ };
      stunsrvaddr.sin_family = AF_INET;
      stunsrvaddr.sin_addr.s_addr = INADDR_ANY;
      stunsrvaddr.sin_port = htons (stunport);
      addrlen = sizeof(stunsrvaddr);
      if (bind (stnsrvsock, (const sockaddr*) &stunsrvaddr, addrlen) == 0)
	{
	  std::mutex *thrmtx = new std::mutex;
	  thrmtx->lock ();
	  threadvectmtx.lock ();
	  threadvect.push_back (std::make_tuple (thrmtx, "STUN server thread"));
	  threadvectmtx.unlock ();
	  std::thread *stthr = new std::thread (
	      std::bind (&NetworkOperations::stunSrvThread, this, thrmtx,
			 stnsrvsock));
	  stthr->detach ();
	  delete stthr;
	}
      else
	{
#ifdef __linux
	  std::cerr << "STUN socket bind error: " << strerror (errno)
	      << std::endl;
#endif
#ifdef _WIN32
	  ch = WSAGetLastError ();
	  std::cerr << "STUN socket bind error: " << ch << std::endl;
#endif
	}
    }
#ifdef __linux
  int stnsock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
  int stnsock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  u_long nonblocking_enabled = TRUE;
  int ch = 0;
  ioctlsocket (stnsock, FIONBIO, &nonblocking_enabled);
#endif
  sockaddr_in stunaddr =
    { };
  stunaddr.sin_family = AF_INET;
  stunaddr.sin_addr.s_addr = INADDR_ANY;
  stunaddr.sin_port = 0;
  addrlen = sizeof(stunaddr);
  if (bind (stnsock, (const sockaddr*) &stunaddr, addrlen) == 0)
    {
      std::mutex *thrmtx = new std::mutex;
      thrmtx->lock ();
      threadvectmtx.lock ();
      threadvect.push_back (std::make_tuple (thrmtx, "STUN check thread"));
      threadvectmtx.unlock ();
      std::thread *stthr = new std::thread (
	  std::bind (&NetworkOperations::stunCheckThread, this, thrmtx,
		     stnsock));
      stthr->detach ();
      delete stthr;
    }
  else
    {
#ifdef __linux
      std::cerr << "STUN checksocket bind error: " << strerror (errno)
	  << std::endl;
#endif
#ifdef _WIN32
      ch = WSAGetLastError ();
      std::cerr << "STUN checksocket bind error: " << ch << std::endl;
#endif
    }
}

void
NetworkOperations::stunSrvThread (std::mutex *thrmtx, int stnsrvsock)
{
  pollfd fdsl[1];
  fdsl[0].fd = stnsrvsock;
  fdsl[0].events = POLLRDNORM;

  for (;;)
    {
      if (cancel > 0)
	{
	  break;
	}
      int respol = poll (fdsl, 1, 3000);
      if (respol > 0)
	{
	  std::vector<char> msgv;
	  msgv.resize (20);
	  sockaddr_in from =
	    { };
	  socklen_t sizefrom = sizeof(from);
	  recvfrom (stnsrvsock, msgv.data (), msgv.size (), 0,
		    (struct sockaddr*) &from, &sizefrom);
	  uint16_t tt = 1000;
	  std::memcpy (&tt, &msgv[0], sizeof(tt));
	  uint16_t tt2 = 1000;
	  std::memcpy (&tt2, &msgv[2], sizeof(tt2));
	  if (ntohs (tt) == 1 && ntohs (tt2) == 0)
	    {
	      uint32_t ttt = 0;
	      std::memcpy (&ttt, &msgv[4], sizeof(ttt));
	      msgv.clear ();
	      uint16_t type = htons (32);
	      msgv.resize (msgv.size () + sizeof(type));
	      std::memcpy (&msgv[0], &type, sizeof(type));
	      uint16_t length = 64;
	      msgv.resize (msgv.size () + sizeof(length));
	      std::memcpy (&msgv[2], &length, sizeof(length));
	      uint8_t zer = 0;
	      msgv.resize (msgv.size () + sizeof(zer));
	      std::memcpy (&msgv[4], &zer, sizeof(zer));
	      uint8_t family = uint8_t (0x01);
	      msgv.resize (msgv.size () + sizeof(family));
	      std::memcpy (&msgv[5], &family, sizeof(family));
	      uint16_t port = from.sin_port;
	      port = ntohs (port);
	      port ^= 8466;
	      port = htons (port);
	      msgv.resize (msgv.size () + sizeof(port));
	      std::memcpy (&msgv[6], &port, sizeof(port));
	      uint32_t ip = from.sin_addr.s_addr;
	      ip = ntohl (ip);
	      ip ^= 554869826;
	      ip = htonl (ip);
	      msgv.resize (msgv.size () + sizeof(ip));
	      std::memcpy (&msgv[8], &ip, sizeof(ip));
	      std::vector<char> tmpv;
	      tmpv.resize (INET_ADDRSTRLEN);
	      std::cout << "STUN request from "
		  << inet_ntop (AF_INET, &from.sin_addr.s_addr, &tmpv[0],
				tmpv.size ()) << ":" << ntohs (from.sin_port)
		  << std::endl;
	      sockaddr_in stunrp =
		{ };
	      stunrp.sin_family = AF_INET;
	      stunrp.sin_port = from.sin_port;
	      stunrp.sin_addr.s_addr = from.sin_addr.s_addr;
	      sendto (stnsrvsock, msgv.data (), msgv.size (), 0,
		      (struct sockaddr*) &stunrp, sizeof(stunrp));
	    }
	}
    }
#ifdef __linux
  close (stnsrvsock);
#endif
#ifdef _WIN32
  closesocket (stnsrvsock);
#endif
  thrmtx->unlock ();
}

void
NetworkOperations::stunCheckThread (std::mutex *thrmtx, int stnsock)
{
  std::vector<std::tuple<std::array<char, 32>, uint32_t, int, time_t>> chvect;
  for (;;)
    {
      if (cancel > 0)
	{
	  break;
	}
      getfrresmtx.lock ();
      for (size_t i = 0; i < getfrres.size (); i++)
	{
	  std::array<char, 32> key = std::get<0> (getfrres[i]);
	  auto itchv = std::find_if (chvect.begin (), chvect.end (), [key]
	  (auto &el)
	    {
	      return key == std::get<0>(el);
	    });
	  if (itchv == chvect.end ())
	    {
	      time_t sttm = time (NULL);
	      chvect.push_back (
		  std::make_tuple (key, std::get<1> (getfrres[i]), 0, sttm));
	    }
	}
      getfrresmtx.unlock ();

      for (size_t i = 0; i < chvect.size (); i++)
	{
	  int chk = std::get<2> (chvect[i]);
	  time_t ltm = std::get<3> (chvect[i]);
	  time_t curtm = time (NULL);
	  if (chk == 0)
	    {
	      chk = chk + 1;
	      std::get<2> (chvect[i]) = chk;
	      std::pair<struct in_addr, uint16_t> p;
	      p.first.s_addr = std::get<1> (chvect[i]);
	      p.second = htons (stunport);
	      std::pair<uint32_t, uint16_t> result;
	      result = getOwnIps (stnsock, p);
	      if (std::get<0> (result) != 0 && std::get<1> (result) != 0)
		{
		  stunipsmtx.lock ();
		  stunips.insert (stunips.begin (), p);
		  stunipsmtx.unlock ();
		}
	      std::get<2> (chvect[i]) = curtm;
	    }
	  else
	    {
	      if (chk <= 3 && curtm - ltm >= 3)
		{
		  chk = chk + 1;
		  std::get<2> (chvect[i]) = chk;
		  std::pair<struct in_addr, uint16_t> p;
		  p.first.s_addr = std::get<1> (chvect[i]);
		  p.second = htons (stunport);
		  std::pair<uint32_t, uint16_t> result;
		  result = getOwnIps (stnsock, p);
		  if (std::get<0> (result) != 0 && std::get<1> (result) != 0)
		    {
		      stunipsmtx.lock ();
		      stunips.insert (stunips.begin (), p);
		      stunipsmtx.unlock ();
		    }
		  std::get<2> (chvect[i]) = curtm;
		}
	    }
	}
      sleep (3);
    }
#ifdef __linux
  close (stnsock);
#endif
#ifdef _WIN32
  closesocket (stnsock);
#endif
  thrmtx->unlock ();
}

void
NetworkOperations::dnsFinishedThread (std::mutex *thrmtx)
{
  sockipv6mtx.lock ();
#ifdef __linux
  sockipv6 = socket (AF_INET6, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
  sockipv6 = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  u_long nonblocking_enabled = TRUE;
  ioctlsocket (sockipv6, FIONBIO, &nonblocking_enabled);
#endif
  sockaddr_in6 addripv6 =
    { };
  addripv6.sin6_family = AF_INET6;
  addripv6.sin6_addr = in6addr_any;
  addripv6.sin6_port = 0;
  int addrlen2 = sizeof(addripv6);
  bind (sockipv6, (const sockaddr*) &addripv6, addrlen2);
#ifdef __linux
  ifaddrs *ifap, *ifa;

  sockaddr_in *ipv4;
  sockaddr_in6 *ipv6;
  char addr6[INET6_ADDRSTRLEN];

  if (getifaddrs (&ifap) == -1)
#endif
#ifdef _WIN32
  WSADATA WsaData;
  WSAStartup (MAKEWORD (2, 2), &WsaData);
  ULONG outBufLen = 15000;
  PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*) malloc (outBufLen);
  if (GetAdaptersAddresses (AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
			     NULL, pAddresses, &outBufLen) != NO_ERROR)
#endif
    {
      std::cerr << "Error on getting ipv6" << std::endl;
    }
  else
    {
      std::string line;
      std::vector<std::string> ipv6tmp;
      std::vector<std::string> ipv4tmp;
#ifdef __linux
      for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{

	  if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6)
	    {
	      ipv6 = (struct sockaddr_in6*) ifa->ifa_addr;
	      if (!IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr))
		{
		  if (Netmode == "internet")
		    {
		      if (!IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr))
			{
			  line = std::string (ifa->ifa_name) + " ";
			  line = line
			      + inet_ntop (AF_INET6, &ipv6->sin6_addr, addr6,
					   sizeof(addr6));
			  ipv6tmp.push_back (line);
			}
		    }
		  if (Netmode == "local")
		    {
		      line = std::string (ifa->ifa_name) + " ";
		      line = line
			  + +inet_ntop (AF_INET6, &ipv6->sin6_addr, addr6,
					sizeof(addr6));
		      if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr))
			{
			  ipv6tmp.insert (ipv6tmp.begin (), line);
			}
		      else
			{
			  ipv6tmp.push_back (line);
			}
		    }
		}

	    }
	  if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
	    {
	      ipv4 = (struct sockaddr_in*) ifa->ifa_addr;
	      if (ipv4->sin_addr.s_addr != htonl (INADDR_LOOPBACK))
		{
		  std::vector<char> addr4;
		  addr4.resize (INET_ADDRSTRLEN);
		  line = std::string (ifa->ifa_name) + " ";
		  line = line
		      + inet_ntop (AF_INET, &ipv4->sin_addr.s_addr,
				   addr4.data (), addr4.size ());
		  ipv4tmp.push_back (line);
		}
	    }
	}
#endif
#ifdef _WIN32
      while (pAddresses)
	{
	  PIP_ADAPTER_UNICAST_ADDRESS pUnicast =
  	  pAddresses->FirstUnicastAddress;
  	  while (pUnicast != NULL)
  	    {
  	      if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
  		{
  		  sockaddr_in *sa_in =
  		  (sockaddr_in*) pUnicast->Address.lpSockaddr;
  		  std::vector<char> buff;
  		  buff.resize (INET_ADDRSTRLEN);
  		  if (sa_in->sin_addr.s_addr != htonl (INADDR_LOOPBACK))
  		    {
  		      std::string ip = inet_ntop (AF_INET,
  			  &(sa_in->sin_addr),
  			  buff.data (),
  			  buff.size ());
  		      ipv4tmp.push_back (ip);
  		    }
  		}
  	      if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
  		{
  		  sockaddr_in6 *sa_in =
  		  (sockaddr_in6*) pUnicast->Address.lpSockaddr;
  		  std::vector<char> buff;
  		  buff.resize (INET6_ADDRSTRLEN);
  		  if (!IN6_IS_ADDR_LINKLOCAL (&sa_in->sin6_addr)
  		      && !IN6_IS_ADDR_LOOPBACK (&sa_in->sin6_addr))
  		    {
  		      std::string ip = inet_ntop (AF_INET6,
  			  &(sa_in->sin6_addr),
  			  buff.data (),
  			  buff.size ());
  		      ipv6tmp.push_back (ip);
  		    }
  		}
  	      pUnicast = pUnicast->Next;
  	    }

  	  pAddresses = pAddresses->Next;
  	}
#endif
      if (ipv4tmp.size () > 1)
	{
	  for (size_t i = 0; i < ipv4tmp.size (); i++)
	    {
	      line = ipv4tmp[i];
	      if (ipv4signal)
		{
		  ipv4signal (line);
		}
	    }
	  if (ipv4signalfinished)
	    {
	      ipv4signalfinished ();
	    }
	  for (;;)
	    {
	      IPV4mtx.lock ();
	      if (IPV4 != "")
		{
		  std::cout << "Own ipv4 " << IPV4 << std::endl;
		  IPV4mtx.unlock ();
		  break;
		}
	      IPV4mtx.unlock ();

	      usleep (100000);
	    }
	}
      else
	{
	  if (ipv4tmp.size () > 0)
	    {
	      std::string tmp = ipv4tmp[0];
	      tmp.erase (0, tmp.find ((" ")) + std::string (" ").size ());
	      IPV4mtx.lock ();
	      IPV4 = tmp;
	      std::cout << "Own ipv4 " << IPV4 << std::endl;
	      IPV4mtx.unlock ();
	    }
	}
      if (ipv6tmp.size () > 1)
	{
	  for (size_t i = 0; i < ipv6tmp.size (); i++)
	    {
	      line = ipv6tmp[i];
	      if (ipv6signal)
		{
		  ipv6signal (line);
		}
	    }
	  if (ipv6signalfinished)
	    {
	      ipv6signalfinished ();
	    }
	  for (;;)
	    {
	      ownipv6mtx.lock ();
	      if (ownipv6 != "")
		{
		  sockaddr_in6 addressp1 =
		    { };
#ifdef __linux
		  unsigned int len = sizeof(addressp1);
#endif
#ifdef _WIN32
  		  int len = sizeof(addressp1);
#endif
		  getsockname (sockipv6, (sockaddr*) &addressp1, &len);
		  ownipv6port = addressp1.sin6_port;
		  std::cout << "Own ipv6 " << ownipv6 << " ";
		  std::cout << ntohs (addressp1.sin6_port) << std::endl;
		  ownipv6mtx.unlock ();
		  break;
		}
	      ownipv6mtx.unlock ();
	      usleep (100000);
	    }
	}
      else
	{
	  if (ipv6tmp.size () > 0)
	    {
	      sockaddr_in6 addressp1 =
		{ };
#ifdef __linux
	      unsigned int len = sizeof(addressp1);
#endif
#ifdef _WIN32
	      int len = sizeof(addressp1);
#endif
	      getsockname (sockipv6, (sockaddr*) &addressp1, &len);
	      ownipv6mtx.lock ();
	      ownipv6 = ipv6tmp[0];
	      ownipv6.erase (0, ownipv6.find (" ") + std::string (" ").size ());
	      ownipv6port = addressp1.sin6_port;
	      std::cout << "Own ipv6 " << ownipv6 << " ";
	      std::cout << ntohs (addressp1.sin6_port) << std::endl;
	      ownipv6mtx.unlock ();
	    }
	}
#ifdef __linux
      freeifaddrs (ifap);
#endif
    }
  sockipv6mtx.unlock ();
  contmtx.lock ();
  for (size_t i = 0; i < contacts.size (); i++)
    {
#ifdef __linux
      int sock = socket (AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
#endif
#ifdef _WIN32
      int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      u_long nonblocking_enabled = TRUE;
      ioctlsocket (sock, FIONBIO, &nonblocking_enabled);
#endif
      sockaddr_in addripv4 =
	{ };
      addripv4.sin_family = AF_INET;
      IPV4mtx.lock ();
      inet_pton (AF_INET, IPV4.c_str (), &addripv4.sin_addr.s_addr);
      IPV4mtx.unlock ();
      addripv4.sin_port = 0;
      int addrlen1 = sizeof(addripv4);
      bind (sock, (const sockaddr*) &addripv4, addrlen1);

      sockmtx.lock ();
      time_t tm = time (NULL);
      std::array<char, 32> keysearch = std::get<1> (contacts[i]);
      auto itsock = std::find_if (sockets4.begin (), sockets4.end (),
				  [keysearch]
				  (auto &el)
				    {
				      return std::get<0>(el) == keysearch;
				    });
      if (itsock != sockets4.end ())
	{
	  std::get<1> (*itsock) = sock;
	  std::get<3> (*itsock) = tm;
	}
      sockmtx.unlock ();
    }
  contmtx.unlock ();

  IPV4mtx.lock ();
  DOp = new DHTOperations (this);
  ROp = new RelayOperations (IPV4, &getfrres, &getfrresmtx, &relayaddr,
			     &relayaddrmtx, &frrelays, &frrelaysmtx, relayport,
			     relaysrv, &threadvect, &threadvectmtx, &cancel,
			     rellistpath, &sendbyrelay, &sendbyrelaymtx);
  ROp->relaymsgrcvd_signal = std::bind (&NetworkOperations::receiveMsg, this,
					std::placeholders::_1,
					std::placeholders::_2,
					std::placeholders::_3,
					std::placeholders::_4);
  IPV4mtx.unlock ();

  if (Netmode == "internet")
    {
      DOp->processDHT ();
      stunSrv ();
    }

  std::mutex *thrmtxc = new std::mutex;
  thrmtxc->lock ();
  threadvectmtx.lock ();
  threadvect.push_back (std::make_tuple (thrmtxc, "Commops main"));
  threadvectmtx.unlock ();
  std::thread *thr = new std::thread ( [this, thrmtxc]
  {
    if (this->copsrun.try_lock ())
      {
	this->commOps ();
	this->copsrun.unlock ();
      }
    thrmtxc->unlock ();
  });
  thr->detach ();
  delete thr;
  addfrmtx.lock ();
  for (size_t i = 0; i < Addfriends.size (); i++)
    {
      getNewFriends (Addfriends[i]);
    }
  addfrmtx.unlock ();
  thrmtx->unlock ();
}

void
NetworkOperations::holePunchThr (size_t i, time_t curtime, int sock,
				 uint32_t ip, std::mutex *thrmtx)
{
  sockmtx.lock ();
  time_t lrcvd = std::get<3> (sockets4[i]);
  std::array<char, 32> key = std::get<0> (sockets4[i]);
  sockmtx.unlock ();

  bool relay = false;
  sendbyrelaymtx.lock ();
  auto itsbr = std::find (sendbyrelay.begin (), sendbyrelay.end (), key);
  if (itsbr != sendbyrelay.end ())
    {
      relay = true;
    }
  sendbyrelaymtx.unlock ();

  if (curtime - lrcvd > Tmttear && !relay)
    {
      sockmtx.lock ();
      std::mutex *mtx = std::get<2> (sockets4[i]);
      std::array<char, 32> otherkey = std::get<0> (sockets4[i]);
      sockmtx.unlock ();
      mtx->lock ();
      holePunch (sock, ip, otherkey);
      mtx->unlock ();
    }
  thrmtx->unlock ();
}

void
NetworkOperations::editContByRelay (std::vector<std::string> &sendbyrel)
{
  sendbyrelaymtx.lock ();
  sendbyrelay.clear ();
  for (size_t i = 0; i < sendbyrel.size (); i++)
    {
      std::array<char, 32> keyarr;
      std::string key = sendbyrel[i];
      lt::aux::from_hex (key, keyarr.data ());
      sendbyrelay.push_back (keyarr);
    }
  sendbyrelaymtx.unlock ();
}

void
NetworkOperations::getOwnIpsThread (
    std::mutex *thrmtx,
    std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t, time_t>> *ownips,
    std::mutex *ownipsmtx)
{
  std::vector<std::pair<uint32_t, uint16_t>> ips;
  time_t curtime = time (NULL);
  sockmtx.lock ();
  for (size_t i = 0; i < sockets4.size (); i++)
    {
      if (cancelgetoips > 0)
	{
	  sockmtx.unlock ();
	  thrmtx->unlock ();
	  return void ();
	}
      std::array<char, 32> key = std::get<0> (sockets4[i]);
      int chiplr = 0;
      ipv6lrmtx.lock ();
      auto itipv6lr = std::find_if (ipv6lr.begin (), ipv6lr.end (), [key]
      (auto &el)
	{
	  return std::get<0>(el) == key;
	});
      if (itipv6lr != ipv6lr.end ())
	{
	  if (time (NULL) - std::get<1> (*itipv6lr) > Tmttear)
	    {
	      chiplr = 1;
	    }
	}
      else
	{
	  chiplr = 1;
	}
      ipv6lrmtx.unlock ();
      if (chiplr > 0)
	{
	  int sock = std::get<1> (sockets4[i]);
	  std::mutex *smtx = std::get<4> (sockets4[i]);
	  ownipsmtx->lock ();
	  auto it = std::find_if (ownips->begin (), ownips->end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (it == ownips->end ())
	    {
	      std::vector<size_t> rplcstun;
	      stunipsmtx.lock ();
	      for (size_t j = 0; j < stunips.size (); j++)
		{
		  if (cancelgetoips > 0)
		    {
		      sockmtx.unlock ();
		      stunipsmtx.unlock ();
		      thrmtx->unlock ();
		      ownipsmtx->unlock ();
		      return void ();
		    }
		  smtx->lock ();
		  std::pair<uint32_t, uint16_t> p = getOwnIps (sock,
							       stunips[j]);
		  if (p.first != 0)
		    {
		      ips.push_back (p);
		    }
		  else
		    {
		      rplcstun.push_back (j);
		    }
		  smtx->unlock ();
		  if (ips.size () == 3)
		    {
		      break;
		    }
		}
	      for (size_t j = 0; j < rplcstun.size (); j++)
		{
		  if (cancelgetoips > 0)
		    {
		      sockmtx.unlock ();
		      stunipsmtx.unlock ();
		      thrmtx->unlock ();
		      ownipsmtx->unlock ();
		      return void ();
		    }
		  std::pair<struct in_addr, uint16_t> replpair;
		  replpair = stunips[rplcstun[j]];
		  stunips.erase (stunips.begin () + rplcstun[j]);
		  stunips.push_back (replpair);
		}
	      if (stunips.size () == 0 && Directinet == "direct")
		{
		  for (int j = 0; j <= 2; j++)
		    {
		      std::pair<struct in_addr, int> stunsv;
		      std::pair<uint32_t, uint16_t> p = getOwnIps (sock,
								   stunsv);
		      ips.push_back (p);
		    }
		}
	      stunipsmtx.unlock ();
	      for (size_t j = 0; j < ips.size (); j++)
		{
		  if (j > 0)
		    {
		      if (ips[0] != ips[j])
			{
			  ips[0].second = 0;
			  break;
			}
		    }
		}
	      if (ips.size () > 0)
		{
		  std::tuple<std::array<char, 32>, uint32_t, uint16_t, time_t> ttup;
		  ttup = std::make_tuple (key, ips[0].first, ips[0].second,
					  curtime);
		  ownips->push_back (ttup);
		  putOwnIps (key, ips[0].first, ips[0].second);
		}
	      ips.clear ();
	    }
	  else
	    {
	      time_t curtime = time (NULL);
	      time_t lr = std::get<3> (sockets4[i]);
	      if (curtime - lr > Tmttear && curtime - lr <= Shuttmt
		  && curtime - std::get<3> (*it) > Tmttear)
		{
		  std::vector<size_t> rplcstun;
		  stunipsmtx.lock ();
		  for (size_t j = 0; j < stunips.size (); j++)
		    {
		      if (cancelgetoips > 0)
			{
			  sockmtx.unlock ();
			  stunipsmtx.unlock ();
			  thrmtx->unlock ();
			  ownipsmtx->unlock ();
			  return void ();
			}
		      smtx->lock ();
		      std::pair<uint32_t, uint16_t> p = getOwnIps (sock,
								   stunips[j]);
		      if (p.first != 0)
			{
			  ips.push_back (p);
			}
		      else
			{
			  rplcstun.push_back (j);
			}
		      smtx->unlock ();
		      if (ips.size () == 3)
			{
			  break;
			}
		    }
		  for (size_t j = 0; j < rplcstun.size (); j++)
		    {
		      if (cancelgetoips > 0)
			{
			  sockmtx.unlock ();
			  stunipsmtx.unlock ();
			  thrmtx->unlock ();
			  ownipsmtx->unlock ();
			  return void ();
			}
		      std::pair<struct in_addr, uint16_t> replpair;
		      replpair = stunips[rplcstun[j]];
		      stunips.erase (stunips.begin () + rplcstun[j]);
		      stunips.push_back (replpair);
		    }
		  if (stunips.size () == 0 && Directinet == "direct")
		    {
		      for (int j = 0; j <= 2; j++)
			{
			  std::pair<struct in_addr, int> stunsv;
			  std::pair<uint32_t, uint16_t> p = getOwnIps (sock,
								       stunsv);
			  ips.push_back (p);
			}
		    }
		  stunipsmtx.unlock ();
		  for (size_t j = 0; j < ips.size (); j++)
		    {
		      if (j > 0)
			{
			  if (ips[0] != ips[j])
			    {
			      ips[0].second = 0;
			      break;
			    }
			}
		    }
		  if (ips.size () > 0)
		    {
		      std::tuple<std::array<char, 32>, uint32_t, uint16_t,
			  time_t> ttup;
		      ttup = std::make_tuple (key, ips[0].first, ips[0].second,
					      curtime);
		      if (std::get<1> (ttup) != std::get<1> (*it)
			  || std::get<1> (ttup) != std::get<1> (*it))
			{
			  putOwnIps (key, ips[0].first, ips[0].second);
			}
		      *it = ttup;
		    }
		  ips.clear ();

		}
	      if (curtime - lr > Shuttmt && curtime - std::get<3> (*it) >= 300)
		{
		  std::vector<size_t> rplcstun;
		  stunipsmtx.lock ();
		  for (size_t j = 0; j < stunips.size (); j++)
		    {
		      if (cancelgetoips > 0)
			{
			  sockmtx.unlock ();
			  stunipsmtx.unlock ();
			  thrmtx->unlock ();
			  ownipsmtx->unlock ();
			  return void ();
			}
		      smtx->lock ();
		      std::pair<uint32_t, uint16_t> p = getOwnIps (sock,
								   stunips[j]);
		      if (p.first != 0)
			{
			  ips.push_back (p);
			}
		      else
			{
			  rplcstun.push_back (j);
			}
		      smtx->unlock ();
		      if (ips.size () == 3)
			{
			  break;
			}
		    }
		  for (size_t j = 0; j < rplcstun.size (); j++)
		    {
		      if (cancelgetoips > 0)
			{
			  sockmtx.unlock ();
			  stunipsmtx.unlock ();
			  thrmtx->unlock ();
			  ownipsmtx->unlock ();
			  return void ();
			}
		      std::pair<struct in_addr, uint16_t> replpair;
		      replpair = stunips[rplcstun[j]];
		      stunips.erase (stunips.begin () + rplcstun[j]);
		      stunips.push_back (replpair);
		    }
		  stunipsmtx.unlock ();
		  for (size_t j = 0; j < ips.size (); j++)
		    {
		      if (j > 0)
			{
			  if (ips[0] != ips[j])
			    {
			      ips[0].second = 0;
			      break;
			    }
			}
		    }
		  if (ips.size () > 0)
		    {
		      std::tuple<std::array<char, 32>, uint32_t, uint16_t,
			  time_t> ttup;
		      ttup = std::make_tuple (key, ips[0].first, ips[0].second,
					      curtime);
		      if (std::get<1> (ttup) != std::get<1> (*it)
			  || std::get<1> (ttup) != std::get<1> (*it))
			{
			  putOwnIps (key, ips[0].first, ips[0].second);
			}
		      *it = ttup;
		    }
		  ips.clear ();
		}
	    }
	  ownipsmtx->unlock ();
	}
    }
  sockmtx.unlock ();
  thrmtx->unlock ();
}

void
NetworkOperations::getFriendIpsThread (
    std::vector<std::tuple<std::array<char, 32>, time_t>> *blockip,
    std::mutex *blockipmtx, std::mutex *thrmtx)
{
  time_t curtime = time (NULL);

  sockmtx.lock ();
  for (size_t i = 0; i < sockets4.size (); i++)
    {
      time_t lastrcvd = std::get<3> (sockets4[i]);
      std::array<char, 32> key = std::get<0> (sockets4[i]);
      time_t blocktm = 0;
      blockipmtx->lock ();
      auto itbl = std::find_if (blockip->begin (), blockip->end (), [key]
      (auto &el)
	{
	  return std::get<0>(el) == key;
	});
      if (itbl != blockip->end ())
	{
	  blocktm = std::get<1> (*itbl);
	}
      else
	{
	  blockip->push_back (std::make_tuple (key, curtime));
	}

      if (curtime - lastrcvd > Tmttear && curtime - lastrcvd <= Shuttmt
	  && curtime > blocktm)
	{
	  getfrmtx.lock ();
	  auto itgfr = std::find (getfr.begin (), getfr.end (), key);
	  if (itgfr == getfr.end ())
	    {
	      getfr.push_back (key);
	    }
	  itbl = std::find_if (blockip->begin (), blockip->end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (itbl != blockip->end ())
	    {
	      std::get<1> (*itbl) = curtime;
	    }
	  getfrmtx.unlock ();
	}
      if (curtime - lastrcvd > Shuttmt)
	{
	  if (curtime - blocktm >= Tmttear)
	    {
	      getfrmtx.lock ();
	      auto itgfr = std::find (getfr.begin (), getfr.end (), key);
	      if (itgfr == getfr.end ())
		{
		  getfr.push_back (key);
		}
	      if (itbl != blockip->end ())
		{
		  std::get<1> (*itbl) = curtime;
		}
	      getfrmtx.unlock ();
	    }
	}
      blockipmtx->unlock ();
    }
  sockmtx.unlock ();
  thrmtx->unlock ();
}

void
NetworkOperations::receiveMsgThread (int sock, std::mutex *thrmtx)
{
  sockmtx.lock ();
  auto it = std::find_if (sockets4.begin (), sockets4.end (), [sock]
  (auto &el)
    {
      return std::get<1>(el) == sock;
    });
  if (it != sockets4.end ())
    {
      std::mutex *mtx = std::get<2> (*it);
      std::array<char, 32> key = std::get<0> (*it);
      mtx->lock ();
      sockaddr_in from =
	{ };
      int rr = receiveMsg (sock, &from, "", nullptr);
      mtx->unlock ();
      if (rr > 0)
	{
	  getfrresmtx.lock ();
	  auto itgfr = std::find_if (getfrres.begin (), getfrres.end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    });
	  if (itgfr != getfrres.end ())
	    {
	      std::get<1> (*itgfr) = from.sin_addr.s_addr;
	      std::get<2> (*itgfr) = from.sin_port;
	    }
	  else
	    {
	      std::tuple<std::array<char, 32>, uint32_t, uint16_t, int> ttup;
	      std::get<0> (ttup) = key;
	      std::get<1> (ttup) = from.sin_addr.s_addr;
	      std::get<2> (ttup) = from.sin_port;
	      std::get<3> (ttup) = 1;
	      getfrres.push_back (ttup);
	    }
	  getfrresmtx.unlock ();
	}

    }
  else
    {
      if (sock == sockipv6)
	{
	  sockaddr_in from =
	    { };
	  receiveMsg (sock, &from, "", nullptr);
	}
    }
  sockmtx.unlock ();
  thrmtx->unlock ();
}

void
NetworkOperations::sendMsgThread (std::mutex *sendingthrmtx,
				  std::vector<std::array<char, 32>> *sendingthr,
				  std::array<char, 32> key, std::mutex *mtx,
				  int sock, std::mutex *thrmtxsm)
{
  uint32_t ip = 0;
  uint16_t port = 0;
  getfrresmtx.lock ();
  auto gfrit = std::find_if (getfrres.begin (), getfrres.end (), [key]
  (auto &el)
    {
      return std::get<0>(el) == key;
    });
  if (gfrit != getfrres.end ())
    {
      ip = std::get<1> (*gfrit);
      port = std::get<2> (*gfrit);
    }
  getfrresmtx.unlock ();

  mtx->lock ();
  sendMsgGlob (sock, key, ip, port);
  mtx->unlock ();

  sendingthrmtx->lock ();
  sendingthr->erase (
      std::remove (sendingthr->begin (), sendingthr->end (), key),
      sendingthr->end ());
  sendingthrmtx->unlock ();
  thrmtxsm->unlock ();
}
