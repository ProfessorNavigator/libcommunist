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

#include "MsgProfileReceive.h"

MsgProfileReceive::MsgProfileReceive (NetworkOperations *No)
{
  no = No;
}

MsgProfileReceive::~MsgProfileReceive ()
{
  // TODO Auto-generated destructor stub
}

void
MsgProfileReceive::msgMBPB (std::string msgtype, std::array<char, 32> keyarr,
			    int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
			    int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  uint64_t msgsz;
  std::memcpy (&msgsz, &buf[42], sizeof(msgsz));
  int chprexists = 0;
  no->contmtx.lock ();
  auto contit = std::find_if (no->contacts.begin (), no->contacts.end (),
			      [keyarr]
			      (auto &el)
				{
				  return std::get<1>(el) == keyarr;
				});
  if (contit != no->contacts.end ())
    {
      std::string indstr;
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << std::get<0> (*contit);
      indstr = strm.str ();
      std::string filename;
      std::filesystem::path filepath;
      filename = no->Home_Path;
      if (msgtype == "PB")
	{
	  filename = filename + "/.Communist/" + indstr + "/Profile";
	}
      else
	{
	  filename = filename + "/.Communist/" + indstr;
	  filepath = std::filesystem::u8path (filename);
	  std::vector<int> indv;
	  if (std::filesystem::exists (filepath))
	    {
	      for (auto &dit : std::filesystem::directory_iterator (filepath))
		{
		  std::filesystem::path tp = dit.path ();
		  if (tp.filename ().u8string () != "Profile"
		      && tp.filename ().u8string () != "Yes")
		    {
		      int vint;
		      strm.clear ();
		      strm.str ("");
		      strm.imbue (loc);
		      std::string fnm = tp.filename ().u8string ();
		      std::string::size_type n;
		      n = fnm.find ("f");
		      if (n != std::string::npos)
			{
			  fnm = fnm.substr (0, n);
			}
		      strm << fnm;
		      strm >> vint;
		      indv.push_back (vint);
		    }
		}
	      std::sort (indv.begin (), indv.end ());
	      if (indv.size () > 0)
		{
		  strm.clear ();
		  strm.str ("");
		  strm.imbue (loc);
		  strm << indv[indv.size () - 1];
		  filename = filename + "/" + strm.str ();
		}
	    }
	}
      filepath = std::filesystem::u8path (filename);
      if (std::filesystem::exists (filepath)
	  && !std::filesystem::is_directory (filepath))
	{
	  std::vector<char> hash;
	  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (hash));
	  std::vector<char> chhash = af.filehash (filepath);
	  if (hash == chhash)
	    {
	      chprexists = 1;
	      std::vector<char> rpmsg;
	      std::array<char, 32> okeyarr;
	      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
	      okp = lt::dht::ed25519_create_keypair (no->seed);
	      okeyarr = std::get<0> (okp).bytes;
	      std::copy (okeyarr.begin (), okeyarr.end (),
			 std::back_inserter (rpmsg));
	      std::string mt;
	      if (msgtype == "MB")
		{
		  mt = "MR";
		}
	      if (msgtype == "PB")
		{
		  mt = "PR";
		}
	      std::copy (mt.begin (), mt.end (), std::back_inserter (rpmsg));
	      rpmsg.resize (rpmsg.size () + sizeof(tm));
	      std::memcpy (&rpmsg[34], &tm, sizeof(tm));
	      lt::dht::public_key othpk;
	      othpk.bytes = keyarr;
	      std::array<char, 32> scalar;
	      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
	      othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
	      std::string passwd = lt::aux::to_hex (othpk.bytes);
	      rpmsg = af.cryptStrm (lt::aux::to_hex (keyarr), passwd, rpmsg);
	      if (rcvip6 == 0)
		{
		  if (relay)
		    {
		      NetworkOperations *nop = no;
		      std::mutex *mtx = new std::mutex;
		      mtx->lock ();
		      no->threadvectmtx.lock ();
		      no->threadvect.push_back (
			  std::make_tuple (mtx, "fileProcessing MBPB"));
		      no->threadvectmtx.unlock ();
		      std::thread *thr = new std::thread ( [nop, keyarr, rpmsg]
		      {
			std::vector<char> lmsg = rpmsg;
			std::vector<std::vector<char>> msgsbuf;
			msgsbuf.push_back (lmsg);
			nop->ROp->relaySend (keyarr, nop->seed, msgsbuf);
		      });
		      thr->detach ();
		      delete thr;
		    }
		  else
		    {
		      no->sendMsg (sockipv4, from->sin_addr.s_addr,
				   from->sin_port, rpmsg);
		    }
		}
	      else
		{
		  std::vector<char> ip6ad;
		  ip6ad.resize (INET6_ADDRSTRLEN);
		  std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr,
					       ip6ad.data (), ip6ad.size ());
		  no->sockipv6mtx.lock ();
		  no->sendMsg6 (sockipv4, ip6, from6->sin6_port, rpmsg);
		  no->sockipv6mtx.unlock ();
		}
	    }
	}
    }
  no->contmtx.unlock ();
  if (chprexists == 0)
    {
      no->msghashmtx.lock ();
      auto itmh = std::find_if (
	  no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
      if (itmh == no->msghash.end () && msgsz <= uint64_t (no->Maxmsgsz))
	{
	  std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>> ttup;
	  std::get<0> (ttup) = keyarr;
	  std::get<1> (ttup) = tm;
	  std::get<2> (ttup) = msgsz;
	  std::vector<char> hash;
	  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (hash));
	  std::get<3> (ttup) = hash;
	  no->msghash.push_back (ttup);
	}
      no->msghashmtx.unlock ();

      no->msgparthashmtx.lock ();
      no->msgparthash.erase (
	  std::remove_if (
	      no->msgparthash.begin (), no->msgparthash.end (), [keyarr, tm]
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
	  no->msgparthash.end ());
      no->msgparthashmtx.unlock ();

      no->msgpartrcvmtx.lock ();
      no->msgpartrcv.erase (
	  std::remove_if (
	      no->msgpartrcv.begin (), no->msgpartrcv.end (), [keyarr, tm]
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
	  no->msgpartrcv.end ());
      no->msgpartrcvmtx.unlock ();

      no->msgrcvdpnummtx.lock ();
      no->msgrcvdpnum.erase (
	  std::remove_if (
	      no->msgrcvdpnum.begin (), no->msgrcvdpnum.end (), [keyarr, tm]
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
	  no->msgrcvdpnum.end ());
      no->msgrcvdpnummtx.unlock ();

      std::vector<char> rpmsg;
      std::array<char, 32> okeyarr;
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (no->seed);
      okeyarr = std::get<0> (okp).bytes;
      std::copy (okeyarr.begin (), okeyarr.end (), std::back_inserter (rpmsg));
      std::string mt;
      if (msgtype == "MB")
	{
	  mt = "MA";
	}
      if (msgtype == "PB")
	{
	  mt = "PA";
	}
      std::copy (mt.begin (), mt.end (), std::back_inserter (rpmsg));
      rpmsg.resize (rpmsg.size () + sizeof(tm));
      std::memcpy (&rpmsg[34], &tm, sizeof(tm));
      lt::dht::public_key othpk;
      othpk.bytes = keyarr;
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
      othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
      std::string passwd = lt::aux::to_hex (othpk.bytes);
      rpmsg = af.cryptStrm (lt::aux::to_hex (keyarr), passwd, rpmsg);
      if (rcvip6 == 0)
	{
	  if (relay)
	    {
	      NetworkOperations *nop = no;
	      std::mutex *mtx = new std::mutex;
	      mtx->lock ();
	      no->threadvectmtx.lock ();
	      no->threadvect.push_back (
		  std::make_tuple (mtx, "fileProcessing MBPB2"));
	      no->threadvectmtx.unlock ();
	      std::thread *thr = new std::thread ( [nop, keyarr, rpmsg]
	      {
		std::vector<char> lmsg = rpmsg;
		std::vector<std::vector<char>> msgsbuf;
		msgsbuf.push_back (lmsg);
		nop->ROp->relaySend (keyarr, nop->seed, msgsbuf);
	      });
	      thr->detach ();
	      delete thr;
	    }
	  else
	    {
	      no->sendMsg (sockipv4, from->sin_addr.s_addr, from->sin_port,
			   rpmsg);
	    }
	}
      else
	{
	  std::vector<char> ip6ad;
	  ip6ad.resize (INET6_ADDRSTRLEN);
	  std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr,
				       ip6ad.data (), ip6ad.size ());
	  no->sockipv6mtx.lock ();
	  no->sendMsg6 (no->sockipv6, ip6, from6->sin6_port, rpmsg);
	  no->sockipv6mtx.unlock ();
	}
    }
}

void
MsgProfileReceive::msgMbPb (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));
  no->msghashmtx.lock ();
  auto itmh = std::find_if (
      no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
  if (itmh != no->msghash.end ())
    {
      no->msgparthashmtx.lock ();
      auto itmph = std::find_if (
	  no->msgparthash.begin (), no->msgparthash.end (), [keyarr, tm]
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
      std::vector<char> hash;
      std::copy (buf.begin () + 50, buf.end (), std::back_inserter (hash));
      if (itmph == no->msgparthash.end ())
	{
	  std::tuple<std::array<char, 32>, uint64_t, std::vector<char>> ttup;
	  std::get<0> (ttup) = keyarr;
	  std::get<1> (ttup) = tm;
	  std::get<2> (ttup) = hash;
	  no->msgparthash.push_back (ttup);
	}
      else
	{
	  std::get<2> (*itmph) = hash;
	}
      no->msgparthashmtx.unlock ();
    }
  no->msghashmtx.unlock ();
}

void
MsgProfileReceive::msgMpPp (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));
  no->msgparthashmtx.lock ();
  auto itmph = std::find_if (
      no->msgparthash.begin (), no->msgparthash.end (), [keyarr, tm]
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
  if (itmph != no->msgparthash.end ())
    {
      no->msgpartrcvmtx.lock ();
      auto itmpr = std::find_if (no->msgpartrcv.begin (), no->msgpartrcv.end (),
				 [keyarr, tm, partnum]
				 (auto &el)
				   {
				     if (std::get<0>(el) == keyarr &&
					 std::get<1>(el) == tm &&
					 std::get<2>(el) == partnum)
				       {
					 return true;
				       }
				     else
				       {
					 return false;
				       }
				   });
      if (itmpr == no->msgpartrcv.end ())
	{
	  std::vector<char> part;
	  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (part));
	  no->msgpartrcv.push_back (
	      std::make_tuple (keyarr, tm, partnum, part));
	}

      no->msgpartrcvmtx.unlock ();
    }
  no->msgparthashmtx.unlock ();
}

void
MsgProfileReceive::msgMePe (std::string msgtype, std::array<char, 32> keyarr,
			    int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
			    int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));

  int check = 0;
  if (msgtype == "Me")
    {
      check = msgMe (keyarr, tm, partnum);
    }
  if (msgtype == "Pe")
    {
      check = msgPe (keyarr, tm, partnum);
    }
  if (check == 1)
    {
      std::vector<char> rpmsg;
      std::array<char, 32> okeyarr;
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (no->seed);
      okeyarr = std::get<0> (okp).bytes;
      std::copy (okeyarr.begin (), okeyarr.end (), std::back_inserter (rpmsg));
      std::string mt;
      if (msgtype == "Me")
	{
	  mt = "Mr";
	}
      if (msgtype == "Pe")
	{
	  mt = "Pr";
	}
      std::copy (mt.begin (), mt.end (), std::back_inserter (rpmsg));
      rpmsg.resize (rpmsg.size () + sizeof(tm));
      std::memcpy (&rpmsg[34], &tm, sizeof(tm));
      rpmsg.resize (rpmsg.size () + sizeof(partnum));
      std::memcpy (&rpmsg[42], &partnum, sizeof(partnum));
      lt::dht::public_key othpk;
      othpk.bytes = keyarr;
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
      othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
      std::string passwd = lt::aux::to_hex (othpk.bytes);
      rpmsg = af.cryptStrm (lt::aux::to_hex (keyarr), passwd, rpmsg);
      if (rcvip6 == 0)
	{
	  if (relay)
	    {
	      NetworkOperations *nop = no;
	      std::mutex *mtx = new std::mutex;
	      mtx->lock ();
	      no->threadvectmtx.lock ();
	      no->threadvect.push_back (
		  std::make_tuple (mtx, "fileProcessing MePe"));
	      no->threadvectmtx.unlock ();
	      std::thread *thr = new std::thread ( [nop, keyarr, rpmsg]
	      {
		std::vector<char> lmsg = rpmsg;
		std::vector<std::vector<char>> msgsbuf;
		msgsbuf.push_back (lmsg);
		nop->ROp->relaySend (keyarr, nop->seed, msgsbuf);
	      });
	      thr->detach ();
	      delete thr;
	    }
	  else
	    {
	      no->sendMsg (sockipv4, from->sin_addr.s_addr, from->sin_port,
			   rpmsg);
	    }
	}
      else
	{
	  std::vector<char> ip6ad;
	  ip6ad.resize (INET6_ADDRSTRLEN);
	  std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr,
				       ip6ad.data (), ip6ad.size ());
	  no->sockipv6mtx.lock ();
	  no->sendMsg6 (no->sockipv6, ip6, from6->sin6_port, rpmsg);
	  no->sockipv6mtx.unlock ();
	}
    }
}

void
MsgProfileReceive::msgMEPE (std::string msgtype, std::array<char, 32> keyarr,
			    int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
			    int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  int checkms = 0;
  if (msgtype == "ME")
    {
      checkms = msgME (keyarr, tm);
    }
  if (msgtype == "PE")
    {
      checkms = msgPE (keyarr, tm);
    }
  if (checkms == 1)
    {
      std::vector<char> rpmsg;
      std::array<char, 32> okeyarr;
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (no->seed);
      okeyarr = std::get<0> (okp).bytes;
      std::copy (okeyarr.begin (), okeyarr.end (), std::back_inserter (rpmsg));
      std::string mt;
      if (msgtype == "ME")
	{
	  mt = "MR";
	}
      if (msgtype == "PE")
	{
	  mt = "PR";
	}
      std::copy (mt.begin (), mt.end (), std::back_inserter (rpmsg));
      rpmsg.resize (rpmsg.size () + sizeof(tm));
      std::memcpy (&rpmsg[34], &tm, sizeof(tm));
      lt::dht::public_key othpk;
      othpk.bytes = keyarr;
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
      othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
      std::string passwd = lt::aux::to_hex (othpk.bytes);
      rpmsg = af.cryptStrm (lt::aux::to_hex (keyarr), passwd, rpmsg);
      if (rcvip6 == 0)
	{
	  if (relay)
	    {
	      NetworkOperations *nop = no;
	      std::mutex *mtx = new std::mutex;
	      mtx->lock ();
	      no->threadvectmtx.lock ();
	      no->threadvect.push_back (
		  std::make_tuple (mtx, "fileProcessing MEPE"));
	      no->threadvectmtx.unlock ();
	      std::thread *thr = new std::thread ( [nop, keyarr, rpmsg]
	      {
		std::vector<char> lmsg = rpmsg;
		std::vector<std::vector<char>> msgsbuf;
		msgsbuf.push_back (lmsg);
		nop->ROp->relaySend (keyarr, nop->seed, msgsbuf);
	      });
	      thr->detach ();
	      delete thr;
	    }
	  else
	    {
	      no->sendMsg (sockipv4, from->sin_addr.s_addr, from->sin_port,
			   rpmsg);
	    }
	}
      else
	{
	  std::vector<char> ip6ad;
	  ip6ad.resize (INET6_ADDRSTRLEN);
	  std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr,
				       ip6ad.data (), ip6ad.size ());
	  no->sockipv6mtx.lock ();
	  no->sendMsg6 (no->sockipv6, ip6, from6->sin6_port, rpmsg);
	  no->sockipv6mtx.unlock ();
	}
    }
  else
    {
      std::vector<char> rpmsg;
      std::array<char, 32> okeyarr;
      std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
      okp = lt::dht::ed25519_create_keypair (no->seed);
      okeyarr = std::get<0> (okp).bytes;
      std::copy (okeyarr.begin (), okeyarr.end (), std::back_inserter (rpmsg));
      std::string mt;
      if (msgtype == "ME")
	{
	  mt = "MI";
	}
      if (msgtype == "PE")
	{
	  mt = "PI";
	}
      std::copy (mt.begin (), mt.end (), std::back_inserter (rpmsg));
      rpmsg.resize (rpmsg.size () + sizeof(tm));
      std::memcpy (&rpmsg[34], &tm, sizeof(tm));
      lt::dht::public_key othpk;
      othpk.bytes = keyarr;
      std::array<char, 32> scalar;
      scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
      othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
      std::string passwd = lt::aux::to_hex (othpk.bytes);
      rpmsg = af.cryptStrm (lt::aux::to_hex (keyarr), passwd, rpmsg);
      if (rcvip6 == 0)
	{
	  if (relay)
	    {
	      NetworkOperations *nop = no;
	      std::mutex *mtx = new std::mutex;
	      mtx->lock ();
	      no->threadvectmtx.lock ();
	      no->threadvect.push_back (
		  std::make_tuple (mtx, "fileProcessing MEPE2"));
	      no->threadvectmtx.unlock ();
	      std::thread *thr = new std::thread ( [nop, keyarr, rpmsg]
	      {
		std::vector<char> lmsg = rpmsg;
		std::vector<std::vector<char>> msgsbuf;
		msgsbuf.push_back (lmsg);
		nop->ROp->relaySend (keyarr, nop->seed, msgsbuf);
	      });
	      thr->detach ();
	      delete thr;
	    }
	  else
	    {
	      no->sendMsg (sockipv4, from->sin_addr.s_addr, from->sin_port,
			   rpmsg);
	    }
	}
      else
	{
	  std::vector<char> ip6ad;
	  ip6ad.resize (INET6_ADDRSTRLEN);
	  std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr,
				       ip6ad.data (), ip6ad.size ());
	  no->sockipv6mtx.lock ();
	  no->sendMsg6 (no->sockipv6, ip6, from6->sin6_port, rpmsg);
	  no->sockipv6mtx.unlock ();
	}
    }
  no->msghashmtx.lock ();
  no->msghash.erase (
      std::remove_if (no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
      no->msghash.end ());
  no->msghashmtx.unlock ();

  no->msgparthashmtx.lock ();
  no->msgparthash.erase (
      std::remove_if (
	  no->msgparthash.begin (), no->msgparthash.end (), [keyarr, tm]
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
      no->msgparthash.end ());
  no->msgparthashmtx.unlock ();

  no->msgpartrcvmtx.lock ();
  no->msgpartrcv.erase (
      std::remove_if (
	  no->msgpartrcv.begin (), no->msgpartrcv.end (), [keyarr, tm]
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
      no->msgpartrcv.end ());
  no->msgpartrcvmtx.unlock ();

  no->msgrcvdpnummtx.lock ();
  no->msgrcvdpnum.erase (
      std::remove_if (
	  no->msgrcvdpnum.begin (), no->msgrcvdpnum.end (), [keyarr, tm]
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
      no->msgrcvdpnum.end ());
  no->msgrcvdpnummtx.unlock ();
}

void
MsgProfileReceive::msgMAPA (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  no->msgpartbufmtx.lock ();
  auto itmpb = std::find_if (
      no->msgpartbuf.begin (), no->msgpartbuf.end (), [keyarr, tm]
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
  if (itmpb != no->msgpartbuf.end ())
    {
      if (std::get<2> (*itmpb) == -1)
	{
	  std::get<2> (*itmpb) = 0;
	}
    }
  no->msgpartbufmtx.unlock ();
}

void
MsgProfileReceive::msgMrPr (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));
  no->msgpartbufmtx.lock ();
  auto itmpb = std::find_if (no->msgpartbuf.begin (), no->msgpartbuf.end (),
			     [keyarr, tm, partnum]
			     (auto &el)
			       {
				 if (std::get<0>(el) == keyarr
				     && std::get<1>(el) == tm
				     && std::get<5>(el) == partnum)
				   {
				     return true;
				   }
				 else
				   {
				     return false;
				   }
			       });
  if (itmpb != no->msgpartbuf.end ())
    {
      std::get<2> (*itmpb) = 2;
    }
  no->msgpartbufmtx.unlock ();
}

void
MsgProfileReceive::msgMRPR (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  no->sendbufmtx.lock ();
  no->msgpartbufmtx.lock ();
  auto itmpb = std::find_if (
      no->msgpartbuf.begin (), no->msgpartbuf.end (), [keyarr, tm]
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
  if (itmpb != no->msgpartbuf.end ())
    {
      std::filesystem::path p = std::get<3> (*itmpb);
      if (std::filesystem::exists (p))
	{
	  std::filesystem::remove_all (p);
	}
      if (msgtype == "MR" && no->msgSent)
	{
	  std::string filename = no->Home_Path + "/.Communist/"
	      + p.parent_path ().filename ().u8string () + "/"
	      + p.filename ().u8string ();
	  p = std::filesystem::u8path (filename);
	  no->msgSent (lt::aux::to_hex (keyarr), p);
	}
      no->msgpartbuf.erase (itmpb);
    }
  no->msgpartbufmtx.unlock ();
  no->sendbufmtx.unlock ();
}

void
MsgProfileReceive::msgMIPI (std::string msgtype, std::array<char, 32> keyarr,
			    std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tm;
  std::memcpy (&tm, &buf[34], sizeof(tm));
  no->msgpartbufmtx.lock ();
  no->msgpartbuf.erase (
      std::remove_if (
	  no->msgpartbuf.begin (), no->msgpartbuf.end (), [keyarr, tm]
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
      no->msgpartbuf.end ());
  no->msgpartbufmtx.unlock ();
}

int
MsgProfileReceive::msgMe (std::array<char, 32> keyarr, uint64_t tm,
			  uint64_t partnum)
{
  int result = 0;
  no->contmtx.lock ();
  auto itc = std::find_if (no->contacts.begin (), no->contacts.end (), [keyarr]
  (auto &el)
    {
      return std::get<1>(el) == keyarr;
    });
  if (itc != no->contacts.end ())
    {
      int index = std::get<0> (*itc);
      std::string indexstr;
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << index;
      indexstr = strm.str ();
      std::string filename;
      AuxFuncNet af;
      filename = no->Home_Path;
      filename = filename + "/.Communist/Bufer/" + indexstr;
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      no->rcvmtx.lock ();
      if (!std::filesystem::exists (filepath))
	{
	  std::filesystem::create_directories (filepath);
	}
      no->msgrcvdpnummtx.lock ();
      auto itmrpnm = std::find_if (no->msgrcvdpnum.begin (),
				   no->msgrcvdpnum.end (), [keyarr, tm]
				   (auto &el)
				     {
				       if (std::get<0>(el) == keyarr
					   && std::get<1>(el) == tm)
					 {
					   return true;
					 }
				       else
					 {
					   return false;
					 }
				     });
      if (itmrpnm != no->msgrcvdpnum.end ())
	{
	  uint64_t lpnm = std::get<2> (*itmrpnm);
	  if (partnum - lpnm == 1)
	    {
	      no->msgparthashmtx.lock ();
	      auto itmph = std::find_if (no->msgparthash.begin (),
					 no->msgparthash.end (), [keyarr, tm]
					 (auto &el)
					   {
					     if (std::get<0>(el) == keyarr &&
						 std::get<1>(el) == tm)
					       {
						 return true;
					       }
					     else
					       {
						 return false;
					       }
					   });
	      if (itmph != no->msgparthash.end ())
		{
		  uint64_t num = 0;
		  std::vector<char> part;
		  no->msgpartrcvmtx.lock ();
		  for (;;)
		    {
		      auto itmpr = std::find_if (
			  no->msgpartrcv.begin (), no->msgpartrcv.end (),
			  [keyarr, tm, &num]
			  (auto &el)
			    {
			      if (std::get<0>(el) == keyarr &&
				  std::get<1>(el) == tm &&
				  std::get<2>(el) == num)
				{
				  return true;
				}
			      else
				{
				  return false;
				}
			    });
		      if (itmpr != no->msgpartrcv.end ())
			{
			  std::vector<char> pt = std::get<3> (*itmpr);
			  std::copy (pt.begin (), pt.end (),
				     std::back_inserter (part));
			  no->msgpartrcv.erase (itmpr);
			}
		      else
			{
			  break;
			}
		      num = num + 1;
		    }
		  no->msgpartrcvmtx.unlock ();
		  std::vector<char> hash = std::get<2> (*itmph);
		  std::vector<char> chhash = af.strhash (part, 2);
		  if (hash == chhash)
		    {
		      strm.clear ();
		      strm.str ("");
		      strm.imbue (loc);
		      strm << tm;
		      filename = filepath.u8string ();
		      filename = filename + "/" + strm.str ();
		      filepath = std::filesystem::u8path (filename);
		      std::fstream f;
		      if (std::filesystem::exists (filepath))
			{
			  f.open (
			      filepath,
			      std::ios_base::out | std::ios_base::app
				  | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      else
			{
			  f.open (filepath,
				  std::ios_base::out | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      std::get<2> (*itmrpnm) = partnum;
		      result = 1;
		    }
		  else
		    {
		      std::cerr << "Part not correct" << std::endl;
		    }
		}
	      else
		{
		  std::cerr << "Msg part hash not found" << std::endl;
		}
	      no->msgparthashmtx.unlock ();
	    }
	  else
	    {
	      if (partnum - lpnm == 0)
		{
		  result = 1;
		}
	      std::cerr << "Msg part number not correct" << std::endl;
	    }
	}
      else
	{
	  if (partnum == 0)
	    {
	      no->msgparthashmtx.lock ();
	      auto itmph = std::find_if (no->msgparthash.begin (),
					 no->msgparthash.end (), [keyarr, tm]
					 (auto &el)
					   {
					     if (std::get<0>(el) == keyarr &&
						 std::get<1>(el) == tm)
					       {
						 return true;
					       }
					     else
					       {
						 return false;
					       }
					   });
	      if (itmph != no->msgparthash.end ())
		{
		  uint64_t num = 0;
		  std::vector<char> part;
		  no->msgpartrcvmtx.lock ();
		  for (;;)
		    {
		      auto itmpr = std::find_if (
			  no->msgpartrcv.begin (), no->msgpartrcv.end (),
			  [keyarr, tm, &num]
			  (auto &el)
			    {
			      if (std::get<0>(el) == keyarr &&
				  std::get<1>(el) == tm &&
				  std::get<2>(el) == num)
				{
				  return true;
				}
			      else
				{
				  return false;
				}
			    });
		      if (itmpr != no->msgpartrcv.end ())
			{
			  std::vector<char> pt = std::get<3> (*itmpr);
			  std::copy (pt.begin (), pt.end (),
				     std::back_inserter (part));
			  no->msgpartrcv.erase (itmpr);
			}
		      else
			{
			  break;
			}
		      num = num + 1;
		    }
		  no->msgpartrcvmtx.unlock ();
		  std::vector<char> hash = std::get<2> (*itmph);
		  std::vector<char> chhash = af.strhash (part, 2);
		  if (hash == chhash)
		    {
		      strm.clear ();
		      strm.str ("");
		      strm.imbue (loc);
		      strm << tm;
		      filename = filepath.u8string ();
		      filename = filename + "/" + strm.str ();
		      filepath = std::filesystem::u8path (filename);
		      std::fstream f;
		      if (std::filesystem::exists (filepath))
			{
			  f.open (
			      filepath,
			      std::ios_base::out | std::ios_base::app
				  | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      else
			{
			  f.open (filepath,
				  std::ios_base::out | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      no->msgrcvdpnum.push_back (
			  std::make_tuple (keyarr, tm, partnum));
		      result = 1;
		    }
		  else
		    {
		      std::cerr << "Part not correct" << std::endl;
		    }
		}
	      else
		{
		  std::cerr << "Msg part hash not found" << std::endl;
		}
	      no->msgparthashmtx.unlock ();
	    }
	}
      no->msgrcvdpnummtx.unlock ();

      no->rcvmtx.unlock ();
    }
  no->contmtx.unlock ();
  return result;
}

int
MsgProfileReceive::msgPe (std::array<char, 32> keyarr, uint64_t tm,
			  uint64_t partnum)
{
  int result = 0;
  no->contmtx.lock ();
  auto itc = std::find_if (no->contacts.begin (), no->contacts.end (), [keyarr]
  (auto &el)
    {
      return std::get<1>(el) == keyarr;
    });
  if (itc != no->contacts.end ())
    {
      int index = std::get<0> (*itc);
      std::string indexstr;
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << index;
      indexstr = strm.str ();
      std::string filename;
      AuxFuncNet af;
      filename = no->Home_Path;
      filename = filename + "/.Communist/Bufer/" + indexstr;
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      no->rcvmtx.lock ();
      if (!std::filesystem::exists (filepath))
	{
	  std::filesystem::create_directories (filepath);
	}
      no->msgrcvdpnummtx.lock ();
      auto itmrpnm = std::find_if (no->msgrcvdpnum.begin (),
				   no->msgrcvdpnum.end (), [keyarr, tm]
				   (auto &el)
				     {
				       if (std::get<0>(el) == keyarr
					   && std::get<1>(el) == tm)
					 {
					   return true;
					 }
				       else
					 {
					   return false;
					 }
				     });
      if (itmrpnm != no->msgrcvdpnum.end ())
	{
	  uint64_t lpnm = std::get<2> (*itmrpnm);
	  if (partnum - lpnm == 1)
	    {
	      no->msgparthashmtx.lock ();
	      auto itmph = std::find_if (no->msgparthash.begin (),
					 no->msgparthash.end (), [keyarr, tm]
					 (auto &el)
					   {
					     if (std::get<0>(el) == keyarr &&
						 std::get<1>(el) == tm)
					       {
						 return true;
					       }
					     else
					       {
						 return false;
					       }
					   });
	      if (itmph != no->msgparthash.end ())
		{
		  uint64_t num = 0;
		  std::vector<char> part;
		  no->msgpartrcvmtx.lock ();
		  for (;;)
		    {
		      auto itmpr = std::find_if (
			  no->msgpartrcv.begin (), no->msgpartrcv.end (),
			  [keyarr, tm, &num]
			  (auto &el)
			    {
			      if (std::get<0>(el) == keyarr &&
				  std::get<1>(el) == tm &&
				  std::get<2>(el) == num)
				{
				  return true;
				}
			      else
				{
				  return false;
				}
			    });
		      if (itmpr != no->msgpartrcv.end ())
			{
			  std::vector<char> pt = std::get<3> (*itmpr);
			  std::copy (pt.begin (), pt.end (),
				     std::back_inserter (part));
			  no->msgpartrcv.erase (itmpr);
			}
		      else
			{
			  break;
			}
		      num = num + 1;
		    }
		  no->msgpartrcvmtx.unlock ();
		  std::vector<char> hash = std::get<2> (*itmph);
		  std::vector<char> chhash = af.strhash (part, 2);
		  if (hash == chhash)
		    {
		      filename = filepath.u8string ();
		      filename = filename + "/Profile";
		      filepath = std::filesystem::u8path (filename);
		      std::fstream f;
		      if (std::filesystem::exists (filepath))
			{
			  f.open (
			      filepath,
			      std::ios_base::out | std::ios_base::app
				  | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      else
			{
			  f.open (filepath,
				  std::ios_base::out | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      std::get<2> (*itmrpnm) = partnum;
		      result = 1;
		    }
		  else
		    {
		      std::cerr << "Profile part not correct" << std::endl;
		    }
		}
	      else
		{
		  std::cerr << "Profile part hash not found" << std::endl;
		}
	      no->msgparthashmtx.unlock ();
	    }
	  else
	    {
	      if (partnum - lpnm == 0)
		{
		  result = 1;
		}
	      std::cerr << "Profile part number incorrect" << std::endl;
	    }
	}
      else
	{
	  if (partnum == 0)
	    {
	      no->msgparthashmtx.lock ();
	      auto itmph = std::find_if (no->msgparthash.begin (),
					 no->msgparthash.end (), [keyarr, tm]
					 (auto &el)
					   {
					     if (std::get<0>(el) == keyarr &&
						 std::get<1>(el) == tm)
					       {
						 return true;
					       }
					     else
					       {
						 return false;
					       }
					   });
	      if (itmph != no->msgparthash.end ())
		{
		  uint64_t num = 0;
		  std::vector<char> part;
		  no->msgpartrcvmtx.lock ();
		  for (;;)
		    {
		      auto itmpr = std::find_if (
			  no->msgpartrcv.begin (), no->msgpartrcv.end (),
			  [keyarr, tm, &num]
			  (auto &el)
			    {
			      if (std::get<0>(el) == keyarr &&
				  std::get<1>(el) == tm &&
				  std::get<2>(el) == num)
				{
				  return true;
				}
			      else
				{
				  return false;
				}
			    });
		      if (itmpr != no->msgpartrcv.end ())
			{
			  std::vector<char> pt = std::get<3> (*itmpr);
			  std::copy (pt.begin (), pt.end (),
				     std::back_inserter (part));
			  no->msgpartrcv.erase (itmpr);
			}
		      else
			{
			  break;
			}
		      num = num + 1;
		    }
		  no->msgpartrcvmtx.unlock ();
		  std::vector<char> hash = std::get<2> (*itmph);
		  std::vector<char> chhash = af.strhash (part, 2);
		  if (hash == chhash)
		    {
		      filename = filepath.u8string ();
		      filename = filename + "/Profile";
		      filepath = std::filesystem::u8path (filename);
		      std::fstream f;
		      if (std::filesystem::exists (filepath))
			{
			  f.open (
			      filepath,
			      std::ios_base::out | std::ios_base::app
				  | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      else
			{
			  f.open (filepath,
				  std::ios_base::out | std::ios_base::binary);
			  f.write (&part[0], part.size ());
			  f.close ();
			}
		      no->msgrcvdpnum.push_back (
			  std::make_tuple (keyarr, tm, partnum));
		      result = 1;
		    }
		  else
		    {
		      std::cerr << "Profile part not correct" << std::endl;
		    }
		}
	      else
		{
		  std::cerr << "Profile part hash not found" << std::endl;
		}
	      no->msgparthashmtx.unlock ();
	    }
	}
      no->msgrcvdpnummtx.unlock ();

      no->rcvmtx.unlock ();
    }
  no->contmtx.unlock ();
  return result;
}

int
MsgProfileReceive::msgME (std::array<char, 32> keyarr, uint64_t tm)
{
  int result = 0;
  no->contmtx.lock ();
  auto itc = std::find_if (no->contacts.begin (), no->contacts.end (), [keyarr]
  (auto &el)
    {
      return std::get<1>(el) == keyarr;
    });
  if (itc != no->contacts.end ())
    {
      int index = std::get<0> (*itc);
      std::locale loc ("C");
      std::stringstream strm;
      strm.imbue (loc);
      strm << index;
      std::string indexstr = strm.str ();
      strm.clear ();
      strm.str ("");
      strm.imbue (loc);
      strm << tm;
      std::string tmstr = strm.str ();
      std::string filename;
      AuxFuncNet af;
      filename = no->Home_Path;
      filename = filename + "/.Communist/Bufer/" + indexstr + "/" + tmstr;
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      no->rcvmtx.lock ();
      if (std::filesystem::exists (filepath))
	{
	  no->msghashmtx.lock ();
	  auto itmh = std::find_if (
	      no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
	  if (itmh != no->msghash.end ())
	    {
	      std::vector<char> hash = std::get<3> (*itmh);
	      std::vector<char> chhash = af.filehash (filepath);
	      uint64_t msgsz = std::get<2> (*itmh);
	      if (hash == chhash
		  && msgsz == uint64_t (std::filesystem::file_size (filepath)))
		{
		  filename = no->Home_Path;
		  filename = filename + "/.Communist/" + indexstr;
		  std::filesystem::path outpath = std::filesystem::u8path (
		      filename);
		  if (std::filesystem::exists (outpath))
		    {
		      std::vector<int> findv;
		      for (auto &ditp : std::filesystem::directory_iterator (
			  outpath))
			{
			  std::filesystem::path p = ditp.path ();
			  if (p.filename ().u8string () != "Profile"
			      && p.filename ().u8string () != "Yes")
			    {
			      filename = p.filename ().u8string ();
			      std::string::size_type n;
			      n = filename.find ("f");
			      if (n != std::string::npos)
				{
				  filename.erase (
				      n, n + std::string ("f").size ());
				}
			      strm.clear ();
			      strm.str ("");
			      strm.imbue (loc);
			      strm << filename;
			      int tint;
			      strm >> tint;
			      findv.push_back (tint);
			    }
			}
		      int msgind = 0;
		      if (findv.size () > 0)
			{
			  std::sort (findv.begin (), findv.end ());
			  msgind = findv[findv.size () - 1] + 1;
			}
		      strm.clear ();
		      strm.str ("");
		      strm.imbue (loc);
		      strm << msgind;
		      filename = outpath.u8string ();
		      filename = filename + "/" + strm.str ();
		      outpath = std::filesystem::u8path (filename);
		      std::filesystem::copy (filepath, outpath);
		      if (no->messageReceived)
			{
			  no->messageReceived (lt::aux::to_hex (keyarr),
					       outpath);
			}
		      af.updateMsgLog (no->Home_Path, no->Username,
				       no->Password, keyarr,
				       outpath.u8string (), no->contacts);
		      result = 1;
		    }
		}
	    }
	  no->msghashmtx.unlock ();
	  std::filesystem::remove_all (filepath);
	}
      no->rcvmtx.unlock ();
    }
  no->contmtx.unlock ();
  return result;
}

int
MsgProfileReceive::msgPE (std::array<char, 32> keyarr, uint64_t tm)
{
  int result = 0;
  no->contfullmtx.lock ();
  auto itc = std::find_if (no->contactsfull.begin (), no->contactsfull.end (),
			   [keyarr]
			   (auto &el)
			     {
			       return std::get<1>(el) == keyarr;
			     });
  if (itc != no->contactsfull.end ())
    {
      int index = std::get<0> (*itc);
      std::locale loc ("C");
      std::stringstream strm;
      strm.imbue (loc);
      strm << index;
      std::string indexstr = strm.str ();
      strm.clear ();
      strm.str ("");
      strm.imbue (loc);
      strm << tm;
      std::string tmstr = strm.str ();
      std::string filename;
      AuxFuncNet af;
      filename = no->Home_Path;
      filename = filename + "/.Communist/Bufer/" + indexstr + "/Profile";
      std::filesystem::path filepath = std::filesystem::u8path (filename);
      no->rcvmtx.lock ();
      if (std::filesystem::exists (filepath))
	{
	  no->msghashmtx.lock ();
	  auto itmh = std::find_if (
	      no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
	  if (itmh != no->msghash.end ())
	    {
	      std::vector<char> hash = std::get<3> (*itmh);
	      std::vector<char> chhash = af.filehash (filepath);
	      uint64_t msgsz = std::get<2> (*itmh);
	      if (hash == chhash
		  && msgsz == uint64_t (std::filesystem::file_size (filepath)))
		{
		  filename = no->Home_Path;
		  filename = filename + "/.Communist/" + indexstr + "/Profile";
		  std::filesystem::path outpath = std::filesystem::u8path (
		      filename);
		  if (!std::filesystem::exists (outpath.parent_path ()))
		    {
		      std::filesystem::create_directories (
			  outpath.parent_path ());
		    }
		  if (std::filesystem::exists (outpath))
		    {
		      std::filesystem::remove_all (outpath);
		    }
		  std::filesystem::copy (filepath, outpath);
		  int indint;
		  strm.clear ();
		  strm.str ("");
		  strm.imbue (loc);
		  strm << indexstr;
		  strm >> indint;
		  if (no->profReceived)
		    {
		      no->profReceived (lt::aux::to_hex (keyarr), indint);
		    }
		  result = 1;
		}
	      else
		{
		  if (hash != chhash)
		    {
		      std::cerr << "Prof hash incorrect" << std::endl;
		    }
		  if (msgsz != uint64_t (std::filesystem::file_size (filepath)))
		    {
		      std::cerr << "Prof size incorrect" << std::endl;
		    }
		}
	    }
	  else
	    {
	      std::cerr << "Profile hash not found" << std::endl;
	    }
	  no->msghashmtx.unlock ();
	  std::filesystem::remove_all (filepath);
	}
      else
	{
	  no->msghashmtx.lock ();
	  auto itmh = std::find_if (
	      no->msghash.begin (), no->msghash.end (), [keyarr, tm]
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
	  if (itmh != no->msghash.end ())
	    {
	      filename = no->Home_Path;
	      filename = filename + "/.Communist/" + indexstr + "/Profile";
	      filepath = std::filesystem::u8path (filename);
	      if (std::filesystem::exists (filepath))
		{
		  std::vector<char> hash = std::get<3> (*itmh);
		  std::vector<char> chhash = af.filehash (filepath);
		  if (hash == chhash)
		    {
		      result = 1;
		    }
		}
	      else
		{
		  std::cerr << "Profile not found" << std::endl;
		}
	    }
	  else
	    {
	      std::cerr << "Profile hash not found" << std::endl;
	    }
	  no->msghashmtx.unlock ();
	}
      no->rcvmtx.unlock ();
    }
  no->contfullmtx.unlock ();
  return result;
}
