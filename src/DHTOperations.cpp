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

#include "DHTOperations.h"
#ifdef __linux
#include <arpa/inet.h>
#endif
#ifdef _WIN32
#include <ws2tcpip.h>
#endif

DHTOperations::DHTOperations (NetworkOperations *No)
{
  no = No;
}

DHTOperations::~DHTOperations ()
{
  // TODO Auto-generated destructor stub
}

void
DHTOperations::processDHT ()
{
  std::mutex *thrmtx = new std::mutex;
  thrmtx->lock ();
  no->threadvectmtx.lock ();
  no->threadvect.push_back (std::make_tuple (thrmtx, "Process DHT"));
  no->threadvectmtx.unlock ();
  std::thread *dhtthr = new std::thread (
      std::bind (&DHTOperations::dhtThread, this, thrmtx));
  dhtthr->detach ();
  delete dhtthr;
}

std::vector<std::array<char, 32>>
DHTOperations::getFrVect ()
{
  std::vector<std::array<char, 32>> result;
  no->getfrmtx.lock ();
  result = no->getfr;
  no->getfr.clear ();
  no->getfrmtx.unlock ();
  return result;
}

std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>>
DHTOperations::putVect ()
{
  std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>> result;
  no->putipmtx.lock ();
  result = no->putipv;
  no->putipv.clear ();
  no->putipmtx.unlock ();
  return result;
}

std::array<char, 32>
DHTOperations::getSes (std::array<char, 32> key, lt::session *ses, bool relay)
{
  AuxFuncNet af;
  time_t lt = time (NULL);
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  std::string salt;
  std::string salt6;
  strm << lt / (3600 * 24);
  salt = strm.str ();
  std::string saltrelay = salt;
  saltrelay = saltrelay + "relayaddr";
  salt = salt + "ipv4";
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
  ownkey = lt::dht::ed25519_create_keypair (no->seed);
  lt::dht::public_key otherkey;
  otherkey.bytes = key;
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (otherkey, std::get<1> (ownkey));
  otherkey = lt::dht::ed25519_add_scalar (otherkey, scalar);
  otherkey = lt::dht::ed25519_add_scalar (otherkey, scalar);
  std::tuple<lt::dht::public_key, lt::dht::secret_key> newkp;
  newkp = lt::dht::ed25519_create_keypair (otherkey.bytes);
  otherkey = std::get<0> (newkp);
  if (!relay)
    {
      ses->dht_get_item (otherkey.bytes, salt);
    }
  else
    {
      ses->dht_get_item (otherkey.bytes, saltrelay);
    }
  std::array<char, 32> result = otherkey.bytes;
  return result;
}

std::array<char, 32>
DHTOperations::getSes6 (std::array<char, 32> key, lt::session *ses)
{
  AuxFuncNet af;
  time_t lt = time (NULL);
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  std::string salt;
  std::string salt6;
  strm << lt / (3600 * 24);
  salt = strm.str ();
  salt = salt + "ipv6";
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
  ownkey = lt::dht::ed25519_create_keypair (no->seed);
  lt::dht::public_key otherkey;
  otherkey.bytes = key;
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (otherkey, std::get<1> (ownkey));
  otherkey = lt::dht::ed25519_add_scalar (otherkey, scalar);
  otherkey = lt::dht::ed25519_add_scalar (otherkey, scalar);
  std::tuple<lt::dht::public_key, lt::dht::secret_key> newkp;
  newkp = lt::dht::ed25519_create_keypair (otherkey.bytes);
  otherkey = std::get<0> (newkp);
  ses->dht_get_item (otherkey.bytes, salt);
  std::array<char, 32> result = otherkey.bytes;
  return result;
}

std::array<char, 32>
DHTOperations::putSes (std::array<char, 32> otherkey, uint32_t ip,
		       uint16_t port, lt::session *ses, bool relay)
{
  AuxFuncNet af;
  lt::dht::public_key otherpk;
  otherpk.bytes = otherkey;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
  ownkey = lt::dht::ed25519_create_keypair (no->seed);
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (otherpk, std::get<1> (ownkey));
  otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
  otherpk = lt::dht::ed25519_add_scalar (otherpk, scalar);
  std::tuple<lt::dht::public_key, lt::dht::secret_key> newpk;
  newpk = lt::dht::ed25519_create_keypair (otherpk.bytes);
  time_t curt = time (NULL);
  std::string salt;
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << curt / (3600 * 24);
  salt = strm.str ();
  std::string saltrelay = salt;
  salt = salt + "ipv4";
  std::vector<char> dst;
  dst.resize (INET_ADDRSTRLEN);

  std::string putstring = inet_ntop (AF_INET, &ip, dst.data (), dst.size ());
  strm.str ("");
  strm.clear ();
  strm.imbue (loc);
  strm << ntohs (port);
  std::array<char, 32> putkey = std::get<0> (newpk).bytes;
  if (!relay)
    {
      if (port == 0)
	{
	  putstring = putstring + ":sym1234567890123456";
	  otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
	  std::string passwd = lt::aux::to_hex (otherpk.bytes);
	  std::vector<char> crv (putstring.begin (), putstring.end ());
	  crv = af.cryptStrm (lt::aux::to_hex (otherkey), passwd, crv);
	  putstring = std::string (crv.begin (), crv.end ());
	}
      else
	{
	  putstring = putstring + ":" + strm.str () + "1234567890123456";
	  otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
	  std::string passwd = lt::aux::to_hex (otherpk.bytes);
	  std::vector<char> crv (putstring.begin (), putstring.end ());
	  crv = af.cryptStrm (lt::aux::to_hex (otherkey), passwd, crv);
	  putstring = std::string (crv.begin (), crv.end ());
	}

      ses->dht_put_item (
	  std::get<0> (newpk).bytes,
	  std::bind (&AuxFuncNet::put_string, af, std::placeholders::_1,
		     std::placeholders::_2, std::placeholders::_3,
		     std::placeholders::_4, std::get<0> (newpk).bytes,
		     std::get<1> (newpk).bytes, putstring),
	  salt);
    }
  else
    {
      no->relayaddrmtx.lock ();
      if (no->relayaddr.size () > 0)
	{
	  uint32_t ip = std::get<0> (no->relayaddr[0]);
	  uint16_t port = std::get<1> (no->relayaddr[0]);
	  std::string ipstr;
	  std::vector<char> tmpbuf;
	  tmpbuf.resize (INET_ADDRSTRLEN);
	  ipstr = inet_ntop (AF_INET, &ip, &tmpbuf[0],
			     socklen_t (tmpbuf.size ()));
	  port = ntohs (port);
	  strm.str ("");
	  strm.clear ();
	  strm.imbue (loc);
	  strm << port;
	  ipstr = ipstr + ":" + strm.str ();
	  saltrelay = saltrelay + "relayaddr";
	  otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
	  std::string passwd = lt::aux::to_hex (otherpk.bytes);
	  std::vector<char> crv (ipstr.begin (), ipstr.end ());
	  crv = af.cryptStrm (lt::aux::to_hex (otherkey), passwd, crv);
	  ipstr.clear ();
	  std::copy (crv.begin (), crv.end (), std::back_inserter (ipstr));
	  ses->dht_put_item (
	      std::get<0> (newpk).bytes,
	      std::bind (&AuxFuncNet::put_string, af, std::placeholders::_1,
			 std::placeholders::_2, std::placeholders::_3,
			 std::placeholders::_4, std::get<0> (newpk).bytes,
			 std::get<1> (newpk).bytes, ipstr),
	      saltrelay);
	}
      no->relayaddrmtx.unlock ();
    }
  return putkey;
}

std::array<char, 32>
DHTOperations::putSes6 (std::array<char, 32> otherkey, lt::session *ses)
{
  AuxFuncNet af;
  lt::dht::public_key otherpk;
  otherpk.bytes = otherkey;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
  ownkey = lt::dht::ed25519_create_keypair (no->seed);
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (otherpk, std::get<1> (ownkey));
  otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
  otherpk = lt::dht::ed25519_add_scalar (otherpk, scalar);
  std::tuple<lt::dht::public_key, lt::dht::secret_key> newpk;
  newpk = lt::dht::ed25519_create_keypair (otherpk.bytes);
  time_t curt = time (NULL);
  std::string salt;
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  strm << curt / (3600 * 24);
  salt = strm.str ();
  salt = salt + "ipv6";
  std::string putstring;
  no->ownipv6mtx.lock ();
  if (no->ownipv6 != "" && no->ownipv6port != 0)
    {
      putstring = no->ownipv6;
      strm.str ("");
      strm.clear ();
      strm.imbue (loc);
      strm << ntohs (no->ownipv6port);
      putstring = putstring + "-" + strm.str ();
      otherpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
      std::string passwd = lt::aux::to_hex (otherpk.bytes);
      std::vector<char> crv (putstring.begin (), putstring.end ());
      crv = af.cryptStrm (lt::aux::to_hex (otherkey), passwd, crv);
      putstring = std::string (crv.begin (), crv.end ());
      ses->dht_put_item (
	  std::get<0> (newpk).bytes,
	  std::bind (&AuxFuncNet::put_string, af, std::placeholders::_1,
		     std::placeholders::_2, std::placeholders::_3,
		     std::placeholders::_4, std::get<0> (newpk).bytes,
		     std::get<1> (newpk).bytes, putstring),
	  salt);
    }
  else
    {
      putstring = "0-0";
      ses->dht_put_item (
	  std::get<0> (newpk).bytes,
	  std::bind (&AuxFuncNet::put_string, af, std::placeholders::_1,
		     std::placeholders::_2, std::placeholders::_3,
		     std::placeholders::_4, std::get<0> (newpk).bytes,
		     std::get<1> (newpk).bytes, putstring),
	  salt);
    }
  no->ownipv6mtx.unlock ();
  std::array<char, 32> result = std::get<0> (newpk).bytes;

  return result;
}
void
DHTOperations::getvResult (std::array<char, 32> key, uint32_t ip, uint16_t port,
			   int seq)
{
  if (seq > 0)
    {
      std::tuple<std::array<char, 32>, uint32_t, uint16_t, int> ttup;
      std::array<char, 32> keyloc = key;
      ttup = std::make_tuple (key, ip, port, seq);
      std::vector<char> temp;
      uint32_t iploc = ip;
      temp.resize (INET_ADDRSTRLEN);
      if (inet_ntop (AF_INET, &iploc, temp.data (), temp.size ()))
	{
	  std::cout << "ip4 " << lt::aux::to_hex (key) << " " << temp.data ()
	      << ":" << ntohs (port) << " seq=" << seq << std::endl;
	  no->contmtx.lock ();
	  auto itc = std::find_if (no->contacts.begin (), no->contacts.end (),
				   [keyloc]
				   (auto &el)
				     {
				       return std::get<1>(el) == keyloc;
				     });
	  if (itc != no->contacts.end ())
	    {
	      no->getfrresmtx.lock ();
	      auto it = std::find_if (no->getfrres.begin (),
				      no->getfrres.end (), [keyloc]
				      (auto &el)
					{
					  return std::get<0>(el) == keyloc;
					});
	      if (it == no->getfrres.end ())
		{
		  if (ip != 0)
		    {
		      no->getfrres.push_back (ttup);
		      no->maintblockmtx.lock ();
		      time_t bltm = time (NULL);
		      auto itmnt = std::find_if (
			  no->maintblock.begin (), no->maintblock.end (),
			  [keyloc]
			  (auto &el)
			    {
			      return std::get<0>(el) == keyloc;
			    });
		      if (itmnt != no->maintblock.end ())
			{
			  std::get<1> (*itmnt) = bltm;
			}
		      else
			{
			  no->maintblock.push_back (
			      std::make_tuple (key, bltm));
			}
		      no->maintblockmtx.unlock ();
		    }
		}
	      else
		{
		  if (std::get<3> (*it) < seq && ip != 0)
		    {
		      *it = ttup;
		      no->maintblockmtx.lock ();
		      time_t bltm = time (NULL);
		      auto itmnt = std::find_if (
			  no->maintblock.begin (), no->maintblock.end (),
			  [keyloc]
			  (auto &el)
			    {
			      return std::get<0>(el) == keyloc;
			    });
		      if (itmnt != no->maintblock.end ())
			{
			  std::get<1> (*itmnt) = bltm;
			}
		      else
			{
			  no->maintblock.push_back (
			      std::make_tuple (key, bltm));
			}
		      no->maintblockmtx.unlock ();
		    }
		}
	      no->getfrresmtx.unlock ();
	    }
	  no->contmtx.unlock ();
	}
      else
	{
#ifdef __linux
	  std::cerr << "DHT error on getting ipv4: " << errno << std::endl;
#endif
#ifdef _WIN32
	  int respol = WSAGetLastError ();
	  std::cerr << "DHT error on getting ipv4: " << respol << std::endl;
#endif

	}
    }
}

void
DHTOperations::getvResult6 (std::array<char, 32> key, std::string ip,
			    uint16_t port, int seq)
{
  if (seq > 0)
    {
      std::tuple<std::array<char, 32>, std::string, uint16_t, int> ttup;
      std::array<char, 32> keyloc = key;
      ttup = std::make_tuple (key, ip, port, seq);
      std::cout << "ip6 " << lt::aux::to_hex (key) << " " << ip << " "
	  << ntohs (port) << " seq=" << seq << std::endl;
      no->contmtx.lock ();
      auto itc = std::find_if (no->contacts.begin (), no->contacts.end (),
			       [keyloc]
			       (auto &el)
				 {
				   return std::get<1>(el) == keyloc;
				 });
      if (itc != no->contacts.end ())
	{
	  no->ipv6contmtx.lock ();
	  auto it = std::find_if (no->ipv6cont.begin (), no->ipv6cont.end (),
				  [keyloc]
				  (auto &el)
				    {
				      return std::get<0>(el) == keyloc;
				    });
	  if (it != no->ipv6cont.end ())
	    {
	      if (seq >= std::get<3> (*it))
		{
		  *it = ttup;
		}
	    }
	  else
	    {
	      no->ipv6cont.push_back (ttup);
	    }
	  no->ipv6contmtx.unlock ();
	}
      no->contmtx.unlock ();
    }
}

void
DHTOperations::dhtThread (std::mutex *thrmtx)
{
  AuxFuncNet af;
  std::vector<char> sesbuf;
  lt::session_params sespar;
  std::string filename = no->Home_Path;
  filename = filename + "/.cache/libcommunist/dhtstate";
  std::filesystem::path filepath = std::filesystem::u8path (filename);
  std::fstream f;
  if (std::filesystem::exists (filepath))
    {
      sesbuf.resize (std::filesystem::file_size (filepath));
      f.open (filepath, std::ios_base::in | std::ios_base::binary);
      f.read (&sesbuf[0], sesbuf.size ());
      f.close ();
      sespar = lt::read_session_params (sesbuf,
					lt::session_handle::save_dht_state);
    }
  sesbuf.clear ();
  lt::session ses (sespar);
  lt::settings_pack p;
  p.set_bool (lt::settings_pack::enable_dht, true);
  p.set_int (lt::settings_pack::alert_mask,
	     lt::alert_category::dht | lt::alert_category::dht_operation);
  auto itprv = std::find_if (no->prefvect.begin (), no->prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Listenifcs";
    });
  if (itprv != no->prefvect.end ())
    {
      if (std::get<1> (*itprv) != "")
	{
	  if (std::get<1> (*itprv) == "0.0.0.0:0,[::]:0")
	    {
	      p.set_str (lt::settings_pack::listen_interfaces,
			 "0.0.0.0:0,[::]:0");
	    }
	  else
	    {
	      p.set_str (lt::settings_pack::listen_interfaces,
			 std::get<1> (*itprv));
	    }
	}
      else
	{
	  p.set_str (lt::settings_pack::listen_interfaces, "0.0.0.0:0,[::]:0");
	}
    }
  else
    {
      p.set_str (lt::settings_pack::listen_interfaces, "0.0.0.0:0,[::]:0");
    }

  itprv = std::find_if (no->prefvect.begin (), no->prefvect.end (), []
  (auto &el)
    {
      return std::get<0>(el) == "Bootstrapdht";
    });
  if (itprv != no->prefvect.end ())
    {
      if (std::get<1> (*itprv) != "")
	{
	  p.set_str (lt::setting_by_name ("dht_bootstrap_nodes"),
		     std::get<1> (*itprv));
	}
      else
	{
	  p.set_str (lt::setting_by_name ("dht_bootstrap_nodes"),
		     "router.bittorrent.com:6881");
	}
    }
  else
    {
      p.set_str (lt::setting_by_name ("dht_bootstrap_nodes"),
		 "router.bittorrent.com:6881");
    }
  ses.apply_settings (p);

  int count = 0;
  int errcount = 0;

  for (;;)
    {
      if (ses.is_dht_running () || (no->cancel) != 0)
	{
	  std::cout << "DHT started" << std::endl;
	  break;
	}
      if (count > 2000)
	{
	  std::cerr << "DHT cannot start" << std::endl;
	  break;
	}
      count++;
      usleep (10000);
    }
  if (count <= 2000 && (no->cancel) == 0)
    {
      std::vector<std::array<char, 32>> getv;
      std::vector<std::tuple<std::array<char, 32>, std::array<char, 32>>> getvinner;
      std::vector<std::tuple<std::array<char, 32>, std::array<char, 32>>> getvinner6;
      std::vector<std::array<char, 32>> geterr4;
      std::vector<std::array<char, 32>> rcvdk4;
      std::vector<std::array<char, 32>> rcvdk6;
      std::vector<std::array<char, 32>> geterr6;
      std::vector<std::tuple<std::array<char, 32>, time_t, time_t>> blockgetcall; //0-key, 1-time ipv4 last get call, 2-time ipv6 last get call
      std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>> putv;
      std::vector<std::tuple<std::array<char, 32>, uint32_t, uint16_t>> putfault;
      std::vector<std::array<char, 32>> putfault6;
      std::vector<
	  std::tuple<std::array<char, 32>, std::array<char, 32>, uint32_t,
	      uint16_t>> putvinner;
      std::vector<std::tuple<std::array<char, 32>, std::array<char, 32>>> putvinner6; //other key, put key
      std::vector<lt::alert*> alerts;
      std::vector<std::tuple<std::array<char, 32>, time_t, time_t>> relayputinner; //0-key, 1-time last put, 2-time last get
      for (;;)
	{
	  if ((no->cancel) > 0)
	    {
	      break;
	    }
	  std::vector<std::array<char, 32>> erasev;
	  std::vector<std::tuple<int, std::array<char, 32>>> loccont;
	  no->contmtx.lock ();
	  loccont = no->contacts;
	  no->contmtx.unlock ();
	  for (size_t i = 0; i < blockgetcall.size (); i++)
	    {
	      std::array<char, 32> kk = std::get<0> (blockgetcall[i]);
	      auto itcont = std::find_if (loccont.begin (), loccont.end (), [kk]
	      (auto &el)
		{
		  return std::get<1>(el) == kk;
		});
	      if (itcont == loccont.end ())
		{
		  erasev.push_back (kk);
		}
	    }

	  for (size_t i = 0; i < erasev.size (); i++)
	    {
	      std::array<char, 32> kk = erasev[i];
	      blockgetcall.erase (
		  std::remove_if (blockgetcall.begin (), blockgetcall.end (),
				  [kk]
				  (auto &el)
				    {
				      return std::get<0>(el) == kk;
				    }),
		  blockgetcall.end ());

	      geterr4.erase (std::remove (geterr4.begin (), geterr4.end (), kk),
			     geterr4.end ());
	      geterr6.erase (std::remove (geterr6.begin (), geterr6.end (), kk),
			     geterr6.end ());
	      rcvdk4.erase (std::remove (rcvdk4.begin (), rcvdk4.end (), kk),
			    rcvdk4.end ());
	      rcvdk6.erase (std::remove (rcvdk6.begin (), rcvdk6.end (), kk),
			    rcvdk6.end ());
	    }
	  loccont.clear ();
	  erasev.clear ();

	  getv = getFrVect ();
	  for (size_t i = 0; i < getv.size (); i++)
	    {
	      std::array<char, 32> erk = getv[i];
	      rcvdk4.erase (std::remove (rcvdk4.begin (), rcvdk4.end (), erk),
			    rcvdk4.end ());
	      rcvdk6.erase (std::remove (rcvdk6.begin (), rcvdk6.end (), erk),
			    rcvdk6.end ());
	    }
	  for (size_t i = 0; i < geterr4.size (); i++)
	    {
	      std::array<char, 32> kk = geterr4[i];
	      getv.erase (std::remove (getv.begin (), getv.end (), kk),
			  getv.end ());
	    }
	  for (size_t i = 0; i < geterr6.size (); i++)
	    {
	      std::array<char, 32> kk = geterr6[i];
	      getv.erase (std::remove (getv.begin (), getv.end (), kk),
			  getv.end ());
	    }
	  putv = putVect ();
	  formRelayPut (&relayputinner);
	  time_t curtm = time (NULL);
	  for (size_t i = 0; i < relayputinner.size (); i++)
	    {
	      if (curtm - std::get<1> (relayputinner[i]) > 60)
		{
		  putSes (std::get<0> (relayputinner[i]), 0, 0, &ses, true);
		  std::get<1> (relayputinner[i]) = curtm;
		}
	      if (curtm - std::get<2> (relayputinner[i]) > 60)
		{
		  getSes (std::get<0> (relayputinner[i]), &ses, true);
		}
	    }

	  for (size_t i = 0; i < getv.size (); i++)
	    {
	      std::array<char, 32> getkey = getv[i];

	      auto it = std::find_if (getvinner.begin (), getvinner.end (),
				      [getkey]
				      (auto &el)
					{
					  return std::get<0>(el) == getkey;
					});
	      if (it == getvinner.end ())
		{
		  getkey = getSes (getv[i], &ses, false);
		  std::tuple<std::array<char, 32>, std::array<char, 32>> ttup;
		  ttup = std::make_tuple (getv[i], getkey);
		  getvinner.push_back (ttup);
		  std::array<char, 32> kk = getv[i];
		  auto itbl = std::find_if (blockgetcall.begin (),
					    blockgetcall.end (), [kk]
					    (auto &el)
					      {
						return std::get<0>(el) == kk;
					      });
		  if (itbl == blockgetcall.end ())
		    {
		      time_t crtm = time (NULL);
		      blockgetcall.push_back (std::make_tuple (kk, crtm, 0));
		    }
		  else
		    {
		      time_t crtm = time (NULL);
		      std::get<1> (*itbl) = crtm;
		    }
		}

	      getkey = getv[i];
	      auto it6 = std::find_if (getvinner6.begin (), getvinner6.end (),
				       [getkey]
				       (auto &el)
					 {
					   return std::get<0>(el) == getkey;
					 });
	      if (it6 == getvinner6.end ())
		{
		  getkey = getSes6 (getv[i], &ses);
		  getvinner6.push_back (std::make_tuple (getv[i], getkey));
		  std::array<char, 32> kk = getv[i];
		  auto itbl = std::find_if (blockgetcall.begin (),
					    blockgetcall.end (), [kk]
					    (auto &el)
					      {
						return std::get<0>(el) == kk;
					      });
		  if (itbl == blockgetcall.end ())
		    {
		      time_t crtm = time (NULL);
		      blockgetcall.push_back (std::make_tuple (kk, 0, crtm));
		    }
		  else
		    {
		      time_t crtm = time (NULL);
		      std::get<2> (*itbl) = crtm;
		    }
		}
	    }
	  getv.clear ();

	  for (size_t i = 0; i < geterr4.size (); i++)
	    {
	      std::array<char, 32> kk = geterr4[i];
	      auto it4 = std::find (rcvdk4.begin (), rcvdk4.end (), kk);
	      if (it4 == rcvdk4.end ())
		{
		  auto itbl = std::find_if (blockgetcall.begin (),
					    blockgetcall.end (), [kk]
					    (auto &el)
					      {
						return std::get<0>(el) == kk;
					      });
		  if (itbl == blockgetcall.end ())
		    {
		      getSes (kk, &ses, false);
		      time_t crtm = time (NULL);
		      blockgetcall.push_back (std::make_tuple (kk, crtm, 0));
		    }
		  else
		    {
		      time_t crtm = time (NULL);
		      if (crtm - std::get<1> (*itbl) > 10)
			{
			  getSes (kk, &ses, false);
			  std::get<1> (*itbl) = crtm;
			}
		    }
		}
	    }
	  geterr4.clear ();

	  for (size_t i = 0; i < geterr6.size (); i++)
	    {
	      std::array<char, 32> kk = geterr6[i];
	      auto it6 = std::find (rcvdk6.begin (), rcvdk6.end (), kk);
	      if (it6 == rcvdk6.end ())
		{
		  auto itbl = std::find_if (blockgetcall.begin (),
					    blockgetcall.end (), [kk]
					    (auto &el)
					      {
						return std::get<0>(el) == kk;
					      });
		  if (itbl == blockgetcall.end ())
		    {
		      getSes6 (kk, &ses);
		      time_t crtm = time (NULL);
		      blockgetcall.push_back (std::make_tuple (kk, 0, crtm));
		    }
		  else
		    {
		      time_t crtm = time (NULL);
		      if (crtm - std::get<2> (*itbl) > 10)
			{
			  getSes6 (kk, &ses);
			  std::get<2> (*itbl) = crtm;
			}
		    }
		}

	    }
	  geterr6.clear ();

	  for (size_t i = 0; i < putv.size (); i++)
	    {
	      std::array<char, 32> otherkey = std::get<0> (putv[i]);
	      putfault.erase (
		  std::remove_if (putfault.begin (), putfault.end (), [otherkey]
		  (auto &el)
		    {
		      return std::get<0>(el) == otherkey;
		    }),
		  putfault.end ());
	      auto it = std::find_if (putvinner.begin (), putvinner.end (),
				      [otherkey]
				      (auto &el)
					{
					  return std::get<0>(el) == otherkey;
					});
	      if (it == putvinner.end ())
		{
		  std::array<char, 32> putkey;
		  putkey = putSes (otherkey, std::get<1> (putv[i]),
				   std::get<2> (putv[i]), &ses, false);
		  std::tuple<std::array<char, 32>, std::array<char, 32>,
		      uint32_t, uint16_t> ttup;
		  ttup = std::make_tuple (otherkey, putkey,
					  std::get<1> (putv[i]),
					  std::get<2> (putv[i]));
		  putvinner.push_back (ttup);

		}
	      auto itp6 = std::find_if (putvinner6.begin (), putvinner6.end (),
					[otherkey]
					(auto &el)
					  {
					    return std::get<0>(el) == otherkey;
					  });
	      if (itp6 == putvinner6.end ())
		{
		  std::array<char, 32> putkey = putSes6 (otherkey, &ses);
		  putvinner6.push_back (std::make_tuple (otherkey, putkey));
		}
	    }
	  putv.clear ();

	  for (size_t i = 0; i < putfault6.size (); i++)
	    {
	      std::array<char, 32> otherkey = putfault6[i];
	      putSes6 (otherkey, &ses);
	    }
	  putfault6.clear ();

	  for (size_t i = 0; i < putfault.size (); i++)
	    {
	      std::array<char, 32> otherkey = std::get<0> (putfault[i]);
	      putSes (otherkey, std::get<1> (putfault[i]),
		      std::get<2> (putfault[i]), &ses, false);
	    }
	  putfault.clear ();
	  alerts.clear ();
	  std::vector<
	      std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t>> rcvd;
	  std::vector<
	      std::tuple<std::array<char, 32>, std::string, uint16_t, int64_t>> rcvd6;
	  lt::time_duration tmdur = lt::seconds (5);
	  ses.wait_for_alert (tmdur);
	  ses.pop_alerts (&alerts);
	  for (size_t i = 0; i < alerts.size (); i++)
	    {
	      if (alerts[i]->type () == lt::dht_bootstrap_alert::alert_type)
		{
		  std::cout << alerts[i]->message () << std::endl;
		  break;
		}
	      if (alerts[i]->type () == lt::dht_mutable_item_alert::alert_type)
		{
		  lt::dht_mutable_item_alert *alrt = lt::alert_cast<
		      lt::dht_mutable_item_alert> (alerts[i]);
		  std::array<char, 32> chkarr = alrt->key;
		  auto itgvin = std::find_if (
		      getvinner.begin (), getvinner.end (), [chkarr]
		      (auto &el)
			{
			  return std::get<1>(el) == chkarr;
			});
		  if (itgvin != getvinner.end ())
		    {
		      std::array<char, 32> errk = std::get<0> (*itgvin);
		      auto itgeterr = std::find (geterr4.begin (),
						 geterr4.end (), errk);
		      if (itgeterr == geterr4.end ())
			{
			  auto itrcv4 = std::find (rcvdk4.begin (),
						   rcvdk4.end (), errk);
			  if (itrcv4 == rcvdk4.end ())
			    {
			      geterr4.push_back (errk);
			    }
			}
		    }
		  auto itgvin6 = std::find_if (
		      getvinner6.begin (), getvinner6.end (), [chkarr]
		      (auto &el)
			{
			  return std::get<1>(el) == chkarr;
			});
		  if (itgvin6 != getvinner6.end ())
		    {
		      std::array<char, 32> errk = std::get<0> (*itgvin6);
		      auto itgeterr6 = std::find (geterr6.begin (),
						  geterr6.end (), errk);
		      if (itgeterr6 == geterr6.end ())
			{
			  auto itrcv6 = std::find (rcvdk6.begin (),
						   rcvdk6.end (), errk);
			  if (itrcv6 == rcvdk6.end ())
			    {
			      geterr6.push_back (errk);
			    }
			}
		    }
		  lt::entry entr = alrt->item;
		  if (entr.type () == lt::entry::data_type::string_t)
		    {
		      std::string msg;
		      std::string::size_type n;
		      std::array<char, 32> keyarr = alrt->key;
		      int64_t seq = alrt->seq;
		      msg = entr.string ();
		      std::string rsalt = alrt->salt;
		      n = rsalt.find ("relayaddr");
		      if (n != std::string::npos)
			{
			  rcvRelay (keyarr, seq, msg, getvinner);
			}
		      else
			{
			  n = rsalt.find ("ipv4");
			  if (n != std::string::npos)
			    {

			      std::array<char, 32> othk;
			      auto it = std::find_if (
				  getvinner.begin (), getvinner.end (), [keyarr]
				  (auto &el)
				    {
				      return std::get<1>(el) == keyarr;
				    });

			      if (it != getvinner.end () && seq > 0)
				{
				  othk = std::get<0> (*it);
				  auto itrcv4 = std::find (rcvdk4.begin (),
							   rcvdk4.end (), othk);
				  if (itrcv4 == rcvdk4.end ())
				    {
				      rcvdk4.push_back (othk);
				    }
				  geterr4.erase (
				      std::remove (geterr4.begin (),
						   geterr4.end (), othk),
				      geterr4.end ());
				  std::string ipst = msg;
				  std::vector<char> crv (ipst.begin (),
							 ipst.end ());
				  lt::dht::public_key othpk;
				  othpk.bytes = std::get<0> (*it);
				  std::array<char, 32> scalar;
				  std::tuple<lt::dht::public_key,
				      lt::dht::secret_key> okp;
				  okp = lt::dht::ed25519_create_keypair (
				      no->seed);
				  scalar = lt::dht::ed25519_key_exchange (
				      othpk, std::get<1> (okp));
				  othpk = lt::dht::ed25519_add_scalar (othpk,
								       scalar);

				  std::string unm = lt::aux::to_hex (
				      std::get<0> (okp).bytes);
				  std::string passwd = lt::aux::to_hex (
				      othpk.bytes);
				  crv = af.decryptStrm (unm, passwd, crv);
				  ipst = std::string (crv.begin (), crv.end ());
				  ipst = ipst.substr (0, ipst.find (":"));
				  uint32_t ip;

				  int chip = inet_pton (AF_INET, ipst.c_str (),
							&ip);
				  std::stringstream strm;
				  std::locale loc ("C");
				  strm.imbue (loc);
				  std::string portst = std::string (
				      crv.begin (), crv.end ());
				  portst.erase (
				      0,
				      portst.find (":")
					  + std::string (":").size ());
				  std::string::size_type n;
				  n = portst.find ("1234567890123456");
				  if (n != std::string::npos)
				    {
				      portst.erase (
					  n,
					  n
					      + std::string ("1234567890123456").size ());
				    }

				  uint16_t port;
				  if (portst == "sym")
				    {
				      port = 0;
				    }
				  else
				    {
				      strm << portst;
				      strm >> port;
				      port = htons (port);
				    }
				  auto itr = std::find_if (
				      rcvd.begin (), rcvd.end (), [&othk]
				      (auto &el)
					{ return std::get<0>(el) == othk;});
				  if (itr != rcvd.end ())
				    {
				      if (chip > 0 && seq >= 0)
					{
					  *itr = make_tuple (othk, ip, port,
							     seq);
					}

				    }
				  else
				    {
				      if (chip > 0 && seq >= 0)
					{
					  rcvd.push_back (
					      std::make_tuple (othk, ip, port,
							       seq));
					}
				    }
				}
			    }
			  n = rsalt.find ("ipv6");
			  if (n != std::string::npos)
			    {
			      std::array<char, 32> othk;
			      auto it = std::find_if (
				  getvinner6.begin (), getvinner6.end (),
				  [keyarr]
				  (auto &el)
				    {
				      return std::get<1>(el) == keyarr;
				    });
				{
				  if (it != getvinner6.end () && seq > 0)
				    {
				      othk = std::get<0> (*it);
				      auto itrcv6 = std::find (rcvdk6.begin (),
							       rcvdk6.end (),
							       othk);
				      if (itrcv6 == rcvdk6.end ())
					{
					  rcvdk6.push_back (othk);
					}
				      geterr6.erase (
					  std::remove (geterr6.begin (),
						       geterr6.end (), othk),
					  geterr6.end ());
				      std::string ipst = msg;
				      std::vector<char> crv;
				      if (ipst.size () > 3)
					{
					  std::copy (ipst.begin (), ipst.end (),
						     std::back_inserter (crv));
					  lt::dht::public_key othpk;
					  othpk.bytes = std::get<0> (*it);
					  std::array<char, 32> scalar;
					  std::tuple<lt::dht::public_key,
					      lt::dht::secret_key> okp;
					  okp =
					      lt::dht::ed25519_create_keypair (
						  no->seed);
					  scalar =
					      lt::dht::ed25519_key_exchange (
						  othpk, std::get<1> (okp));
					  othpk = lt::dht::ed25519_add_scalar (
					      othpk, scalar);
					  std::string unm = lt::aux::to_hex (
					      std::get<0> (okp).bytes);
					  std::string passwd = lt::aux::to_hex (
					      othpk.bytes);
					  crv = af.decryptStrm (unm, passwd,
								crv);
					  ipst = std::string (crv.begin (),
							      crv.end ());
					  ipst = ipst.substr (0,
							      ipst.find ("-"));
					  std::stringstream strm;
					  std::locale loc ("C");
					  strm.imbue (loc);
					  std::string portst = std::string (
					      crv.begin (), crv.end ());
					  portst.erase (
					      0,
					      portst.find ("-")
						  + std::string ("-").size ());
					  uint16_t port;
					  strm << portst;
					  strm >> port;
					  port = htons (port);
					  auto itr =
					      std::find_if (
						  rcvd6.begin (),
						  rcvd6.end (),
						  [&othk]
						  (auto &el)
						    { return std::get<0>(el) == othk;});
					  if (itr != rcvd6.end ())
					    {
					      *itr = make_tuple (othk, ipst,
								 port, seq);
					    }
					  else
					    {
					      rcvd6.push_back (
						  std::make_tuple (othk, ipst,
								   port, seq));
					    }
					}
				    }
				}
			    }
			}
		    }
		}
	      if (alerts[i]->type () == lt::dht_put_alert::alert_type)
		{
		  std::string::size_type n;
		  lt::dht_put_alert *alrt = lt::alert_cast<lt::dht_put_alert> (
		      alerts[i]);
		  std::string msg;
		  if (alrt->num_success == 0)
		    {
		      errcount++;
		      std::array<char, 32> keyarr = alrt->public_key;
		      msg = alrt->salt;
		      n = msg.find ("ipv4");
		      if (n != std::string::npos)
			{
			  auto it = std::find_if (
			      putvinner.begin (), putvinner.end (), [keyarr]
			      (auto &el)
				{
				  return std::get<1>(el) == keyarr;
				});
			  if (it != putvinner.end ())
			    {
			      std::array<char, 32> othk = std::get<0> (*it);
			      uint32_t ip = std::get<2> (*it);
			      uint16_t port = std::get<3> (*it);
			      std::tuple<std::array<char, 32>, uint32_t,
				  uint16_t> ttup;
			      ttup = std::make_tuple (othk, ip, port);
			      putfault.push_back (ttup);
			    }
			}
		      n = msg.find ("ipv6");
		      if (n != std::string::npos)
			{
			  auto it = std::find_if (
			      putvinner6.begin (), putvinner6.end (), [keyarr]
			      (auto &el)
				{
				  return std::get<1>(el) == keyarr;
				});
			  if (it != putvinner6.end ())
			    {
			      std::array<char, 32> othk = std::get<0> (*it);
			      putfault6.push_back (othk);
			    }
			}
		    }
		  else
		    {
		      msg = alerts[i]->message ();
		      std::cout << msg << std::endl;
		      errcount = 0;
		      std::array<char, 32> keyarr = alrt->public_key;
		      std::string::size_type n;
		      msg = alrt->salt;
		      n = msg.find ("ipv4");
		      if (n != std::string::npos)
			{
			  putvinner.erase (
			      std::remove_if (
				  putvinner.begin (), putvinner.end (), [keyarr]
				  (auto &el)
				    {
				      return std::get<1>(el) == keyarr;
				    }),
			      putvinner.end ());
			}
		      n = msg.find ("ipv6");
		      if (n != std::string::npos)
			{
			  putvinner6.erase (
			      std::remove_if (
				  putvinner6.begin (), putvinner6.end (),
				  [keyarr]
				  (auto &el)
				    {
				      return std::get<1>(el) == keyarr;
				    }),
			      putvinner6.end ());
			}
		    }
		}
	    }
	  for (size_t i = 0; i < rcvd.size (); i++)
	    {
	      std::array<char, 32> key = std::get<0> (rcvd[i]);
	      getvResult (key, std::get<1> (rcvd[i]), std::get<2> (rcvd[i]),
			  std::get<3> (rcvd[i]));
	      getvinner.erase (
		  std::remove_if (getvinner.begin (), getvinner.end (), [key]
		  (auto &el)
		    {
		      return std::get<0>(el) == key;
		    }),
		  getvinner.end ());
	    }
	  for (size_t i = 0; i < rcvd6.size (); i++)
	    {
	      std::array<char, 32> key = std::get<0> (rcvd6[i]);
	      getvResult6 (key, std::get<1> (rcvd6[i]), std::get<2> (rcvd6[i]),
			   std::get<3> (rcvd6[i]));
	      getvinner6.erase (
		  std::remove_if (getvinner6.begin (), getvinner6.end (), [key]
		  (auto &el)
		    {
		      return std::get<0>(el) == key;
		    }),
		  getvinner6.end ());
	    }
	  if (errcount > 50)
	    {
	      errcount = 0;
	      std::cerr
		  << "DHT put error! Check connection."
		  << std::endl;
	      sleep (10);
	    }
	}
    }
  else
    {
      std::cerr << "DHT not started, check connection!" << std::endl;
    }

  sespar = ses.session_state (lt::save_state_flags_t::all ());
  sesbuf = lt::write_session_params_buf (sespar, lt::session::save_dht_state);
  if (!std::filesystem::exists (filepath.parent_path ()))
    {
      std::filesystem::create_directories (filepath.parent_path ());
    }

  f.open (filepath, std::ios_base::out | std::ios_base::binary);
  f.write (&sesbuf[0], sesbuf.size ());
  f.close ();
  ses.abort ();
  thrmtx->unlock ();
}

void
DHTOperations::rcvRelay (
    std::array<char, 32> key,
    int64_t seq,
    std::string msg,
    std::vector<std::tuple<std::array<char, 32>, std::array<char, 32>>> &getvinner)
{
  AuxFuncNet af;
  std::array<char, 32> othk;
  auto it = std::find_if (getvinner.begin (), getvinner.end (), [key]
  (auto &el)
    {
      return std::get<1>(el) == key;
    });
    {
      if (it != getvinner.end () && seq > 0)
	{
	  othk = std::get<0> (*it);
	  std::string ipst = msg;
	  std::vector<char> crv (ipst.begin (), ipst.end ());
	  lt::dht::public_key othpk;
	  othpk.bytes = std::get<0> (*it);
	  std::array<char, 32> scalar;
	  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
	  okp = lt::dht::ed25519_create_keypair (no->seed);
	  scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
	  othpk = lt::dht::ed25519_add_scalar (othpk, scalar);

	  std::string unm = lt::aux::to_hex (std::get<0> (okp).bytes);
	  std::string passwd = lt::aux::to_hex (othpk.bytes);
	  crv = af.decryptStrm (unm, passwd, crv);
	  ipst = std::string (crv.begin (), crv.end ());
	  ipst = ipst.substr (0, ipst.find (":"));
	  uint32_t ip;
	  int chip = inet_pton (AF_INET, ipst.c_str (), &ip);
	  no->IPV4mtx.lock ();
	  if (chip > 0 && ipst != no->IPV4)
	    {
	      std::stringstream strm;
	      std::locale loc ("C");
	      strm.imbue (loc);
	      std::string portst = std::string (crv.begin (), crv.end ());
	      portst.erase (0, portst.find (":") + std::string (":").size ());

	      uint16_t port;
	      strm << portst;
	      strm >> port;
	      port = htons (port);
	      no->frrelaysmtx.lock ();
	      auto itfrr = std::find_if (no->frrelays.begin (),
					 no->frrelays.end (), [othk]
					 (auto &el)
					   {
					     return std::get<0>(el) == othk;
					   });
	      if (itfrr == no->frrelays.end ())
		{
		  std::tuple<std::array<char, 32>, uint32_t, uint16_t, int64_t> ttup;
		  std::get<0> (ttup) = othk;
		  std::get<1> (ttup) = ip;
		  std::get<2> (ttup) = port;
		  std::get<3> (ttup) = seq;
		  no->frrelays.push_back (ttup);
		  std::cout << "DHT rcvd relay: " << ipst << ":" << ntohs (port)
		      << std::endl;
		}
	      else
		{
		  int64_t chseq = std::get<3> (*itfrr);
		  if (seq > chseq)
		    {
		      std::get<1> (*itfrr) = ip;
		      std::get<2> (*itfrr) = port;
		      std::get<3> (*itfrr) = seq;
		      std::cout << "DHT rcvd relay: " << ipst << ":"
			  << ntohs (port) << std::endl;
		    }
		}
	      no->frrelaysmtx.unlock ();
	    }
	  no->IPV4mtx.unlock ();
	}
    }
}

void
DHTOperations::formRelayPut (
    std::vector<std::tuple<std::array<char, 32>, time_t, time_t>> *relayputinner)
{
  no->contmtx.lock ();
  for (size_t i = 0; i < no->contacts.size (); i++)
    {
      std::array<char, 32> key = std::get<1> (no->contacts[i]);
      auto itrpi = std::find_if (relayputinner->begin (), relayputinner->end (),
				 [key]
				 (auto &el)
				   {
				     return std::get<0>(el) == key;
				   });
      if (itrpi == relayputinner->end ())
	{
	  relayputinner->push_back (std::make_tuple (key, 0, 0));
	}
    }

  std::vector<std::array<char, 32>> fordel;
  for (size_t i = 0; i < relayputinner->size (); i++)
    {
      std::array<char, 32> key = std::get<0> (relayputinner->at (i));
      auto itcont = std::find_if (no->contacts.begin (), no->contacts.end (),
				  [key]
				  (auto &el)
				    {
				      return std::get<1>(el) == key;
				    });
      if (itcont == no->contacts.end ())
	{
	  fordel.push_back (key);
	}
    }
  no->contmtx.unlock ();
  for (size_t i = 0; i < fordel.size (); i++)
    {
      std::array<char, 32> key = fordel[i];
      relayputinner->erase (
	  std::remove_if (relayputinner->begin (), relayputinner->end (), [key]
	  (auto &el)
	    {
	      return std::get<0>(el) == key;
	    }),
	  relayputinner->end ());
    }
}
