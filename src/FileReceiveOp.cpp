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

#include "FileReceiveOp.h"

FileReceiveOp::FileReceiveOp (NetworkOperations *No)
{
  no = No;
}

FileReceiveOp::~FileReceiveOp ()
{
  // TODO Auto-generated destructor stub
}

void
FileReceiveOp::fileProcessing (std::string msgtype, std::array<char, 32> keyarr,
			       int ip6check, int sockipv, sockaddr_in *from,
			       sockaddr_in6 *from6, bool relay)
{
  std::array<char, 32> chkey = keyarr;
  int rcvip6 = ip6check;
  AuxFuncNet af;
  no->contmtx.lock ();
  auto contit = std::find_if (no->contacts.begin (), no->contacts.end (),
			      [chkey]
			      (auto &el)
				{
				  return std::get<1>(el) == chkey;
				});
  if (contit != no->contacts.end ())
    {
      std::array<char, 32> key = std::get<1> (*contit);
      std::string index;
      std::stringstream strm;
      std::locale loc ("C");
      strm.imbue (loc);
      strm << std::get<0> (*contit);
      index = strm.str ();
      if (msgtype == "Fp")
	{
	  filePrFp (key, rcvip6, relay, sockipv, from, from6);
	}

      if (msgtype == "Fe")
	{
	  filePrFe (key, rcvip6, relay, sockipv, from, from6);
	}

      if (msgtype == "FE")
	{
	  filePrFE (key, rcvip6, relay, sockipv, from, from6, index);
	}
    }
  no->contmtx.unlock ();
}

void
FileReceiveOp::fileFQ (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t timet;
  std::memcpy (&timet, &buf[34], sizeof(timet));
  uint64_t fsize;
  std::memcpy (&fsize, &buf[42], sizeof(fsize));
  std::vector<char> fnmv;
  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (fnmv));
  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
  okp = lt::dht::ed25519_create_keypair (no->seed);
  lt::dht::public_key othk;
  othk.bytes = keyarr;
  std::string unm = lt::aux::to_hex (std::get<0> (okp).bytes);
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (othk, std::get<1> (okp));
  othk = lt::dht::ed25519_add_scalar (std::get<0> (okp), scalar);
  std::string passwd = lt::aux::to_hex (othk.bytes);
  fnmv = af.decryptStrm (unm, passwd, fnmv);
  std::string fnm (fnmv.begin (), fnmv.end ());
  std::string::size_type n;
  n = fnm.find ("\\");
  if (n != std::string::npos)
    {
      fnm.erase (n, std::string::npos);
    }
  n = fnm.find (" RS");
  std::string resendmsg = "";
  if (n != std::string::npos)
    {
      resendmsg = fnm;
      resendmsg = resendmsg.erase (0, n);
      resendmsg = resendmsg.substr (0, resendmsg.find (" RP"));
      fnm.erase (fnm.find (resendmsg), resendmsg.size ());
      resendmsg.erase (0, std::string (" RS").size ());
    }
  n = fnm.find (" RP");
  std::string replmsg = "";
  if (n != std::string::npos)
    {
      replmsg = fnm;
      replmsg = replmsg.erase (0, n);
      replmsg = replmsg.substr (0, replmsg.find (" RS"));
      fnm.erase (fnm.find (replmsg), replmsg.size ());
      replmsg.erase (0, std::string (" RP").size ());
    }
  no->fqblockvmtx.lock ();
  auto itfqbl = std::find_if (no->fqblockv.begin (), no->fqblockv.end (),
			      [keyarr, timet, fnm]
			      (auto &el)
				{
				  if (std::get<0>(el) == keyarr && std::get<1>(el) == timet
				      && std::get<2>(el) == fnm)
				    {
				      return true;
				    }
				  else
				    {
				      return false;
				    }
				});
  if (itfqbl == no->fqblockv.end ())
    {
      no->fqrcvdmtx.lock ();
      std::tuple<std::array<char, 32>, uint64_t, std::string, std::string,
	  std::string> fqtup;
      fqtup = std::make_tuple (keyarr, timet, fnm, replmsg, resendmsg);
      auto itfqrcvd = std::find (
	  no->fqrcvd.begin (), no->fqrcvd.end (), fqtup);
      if (itfqrcvd == no->fqrcvd.end ())
	{
	  std::cout << lt::aux::to_hex (keyarr) << " " << timet << " " << fsize
	      << " " << fnm << std::endl;
	  no->fqrcvd.push_back (fqtup);
	  if (no->filerequest)
	    {
	      no->filerequest (lt::aux::to_hex (keyarr), timet, fsize, fnm);
	    }
	  time_t curtm = time (NULL);
	  no->fqblockv.push_back (
	      std::make_tuple (keyarr, timet, fnm,
			       static_cast<uint64_t> (curtm)));
	}
      no->fqrcvdmtx.unlock ();
    }
  no->fqblockvmtx.unlock ();

  std::filesystem::path sp;
  bool found = false;
  no->filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      no->filehashvect.begin (), no->filehashvect.end (), [keyarr, fnm]
      (auto &el)
	{
	  std::string chstr = std::get<3>(el).filename().u8string();
	  if (std::get<0>(el) == keyarr && chstr == fnm)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != no->filehashvect.end ())
    {
      sp = std::get<3> (*itfhv);
      if (std::get<1> (*itfhv) == timet)
	{
	  found = true;
	}
    }
  no->filehashvectmtx.unlock ();
  if (found)
    {
      no->fileAccept (lt::aux::to_hex (keyarr), timet, sp, true);
    }
}

void
FileReceiveOp::fileFJ (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->sendbufmtx.lock ();
  no->filesendreqmtx.lock ();
  auto itfsr = std::find_if (
      no->filesendreq.begin (), no->filesendreq.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<2>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfsr != no->filesendreq.end ())
    {
      std::filesystem::path p = std::get<4> (*itfsr);
      if (std::filesystem::exists (p))
	{
	  std::filesystem::remove_all (p);
	}
      if (no->msgSent)
	{
	  std::string filename = no->Home_Path + "/.Communist/"
	      + p.parent_path ().filename ().u8string () + "/"
	      + p.filename ().u8string ();
	  p = std::filesystem::u8path (filename);
	  no->msgSent (lt::aux::to_hex (keyarr), p);
	}
      if (no->fileRejected)
	{
	  std::filesystem::path sp = std::get<1> (*itfsr);
	  no->fileRejected (lt::aux::to_hex (keyarr), sp);
	}
      no->filesendreq.erase (itfsr);
    }
  no->filesendreqmtx.unlock ();
  no->sendbufmtx.unlock ();
}

void
FileReceiveOp::fileFA (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->filesendreqmtx.lock ();
  auto itfsr = std::find_if (
      no->filesendreq.begin (), no->filesendreq.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<2>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfsr != no->filesendreq.end ())
    {
      std::filesystem::path p = std::get<1> (*itfsr);
      std::vector<char> frbuf;
      no->filepartbufmtx.lock ();
      auto it = std::find_if (
	  no->filepartbuf.begin (), no->filepartbuf.end (), [keyarr, tint]
	  (auto &el)
	    {
	      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    });
      if (it == no->filepartbuf.end ())
	{
	  no->filepartbuf.push_back (
	      std::make_tuple (keyarr, tint, p, 0, 0, frbuf, 1));
	}
      no->filepartbufmtx.unlock ();
      std::get<3> (*itfsr) = 1;
    }
  no->filesendreqmtx.unlock ();
}

void
FileReceiveOp::fileFr (std::string msgtype, std::array<char, 32> keyarr,
		       int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
		       int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> ownkey;
  ownkey = lt::dht::ed25519_create_keypair (no->seed);
  std::string unm = lt::aux::to_hex (std::get<0> (ownkey).bytes);
  lt::dht::public_key othpk;
  othpk.bytes = keyarr;
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (ownkey));
  othpk = lt::dht::ed25519_add_scalar (std::get<0> (ownkey), scalar);
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));
  no->filepartbufmtx.lock ();
  auto itfpb = std::find_if (
      no->filepartbuf.begin (), no->filepartbuf.end (), [keyarr, tint, partnum]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr &&
	      std::get<1>(el) == tint && std::get<4>(el) == partnum)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfpb != no->filepartbuf.end ())
    {
      std::get<6> (*itfpb) = 1;
      std::filesystem::path sentp = std::get<2> (*itfpb);
      if (int (std::filesystem::file_size (sentp)) == std::get<3> (*itfpb))
	{
	  sendMsg (keyarr, "FE", tint, 0, rcvip6, relay, sockipv4, from, from6);
	}
      else
	{
	  if (no->filepartsendsig)
	    {
	      no->filepartsendsig (lt::aux::to_hex (keyarr),
				   std::get<2> (*itfpb),
				   uint64_t (std::get<3> (*itfpb)));
	    }
	}
    }
  no->filepartbufmtx.unlock ();
}
void
FileReceiveOp::fileFRFI (std::string msgtype, std::array<char, 32> keyarr,
			 std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->sendbufmtx.lock ();
  no->filesendreqmtx.lock ();
  auto itfsr = std::find_if (
      no->filesendreq.begin (), no->filesendreq.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<2>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfsr != no->filesendreq.end ())
    {
      std::filesystem::path p = std::get<4> (*itfsr);
      std::filesystem::remove_all (p);
      if (no->msgSent)
	{
	  std::string filename = no->Home_Path + "/.Communist/"
	      + p.parent_path ().filename ().u8string () + "/"
	      + p.filename ().u8string ();
	  p = std::filesystem::u8path (filename);
	  no->msgSent (lt::aux::to_hex (keyarr), p);
	}
      no->filesendreq.erase (itfsr);
    }
  no->filesendreqmtx.unlock ();
  no->sendbufmtx.unlock ();

  no->filepartbufmtx.lock ();
  auto itfpb = std::find_if (
      no->filepartbuf.begin (), no->filepartbuf.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfpb != no->filepartbuf.end ())
    {
      if (msgtype == "FR")
	{
	  no->filecanceledmtx.lock ();
	  no->filecanceled.erase (
	      std::remove_if (
		  no->filecanceled.begin (), no->filecanceled.end (),
		  [keyarr, tint]
		  (auto &el)
		    {
		      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    }),
	      no->filecanceled.end ());
	  no->filecanceledmtx.unlock ();
	  if (no->filesentsig)
	    {
	      no->filesentsig (lt::aux::to_hex (keyarr), std::get<2> (*itfpb));
	    }
	}
      if (msgtype == "FI")
	{
	  no->filecanceledmtx.lock ();
	  no->filecanceled.erase (
	      std::remove_if (
		  no->filecanceled.begin (), no->filecanceled.end (),
		  [keyarr, tint]
		  (auto &el)
		    {
		      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    }),
	      no->filecanceled.end ());
	  no->filecanceledmtx.unlock ();
	  std::filesystem::path toemit = std::get<2> (*itfpb);
	  if (no->filesenterror)
	    {
	      no->filesenterror (lt::aux::to_hex (keyarr), toemit);
	    }
	}
      no->filepartbuf.erase (itfpb);
    }
  no->filepartbufmtx.unlock ();
}

void
FileReceiveOp::fileFB (std::string msgtype, std::array<char, 32> keyarr,
		       int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
		       int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      no->filehashvect.begin (), no->filehashvect.end (), [keyarr, tint]
      (auto &el)
	{
	  if(std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != no->filehashvect.end ())
    {
      std::vector<char> fh;
      std::copy (buf.begin () + 50, buf.end (), std::back_inserter (fh));
      std::get<2> (*itfhv) = fh;
      sendMsg (keyarr, "FH", tint, 0, rcvip6, relay, sockipv4, from, from6);
    }
  no->filehashvectmtx.unlock ();
}

void
FileReceiveOp::fileFH (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->filepartbufmtx.lock ();
  auto itfpb = std::find_if (
      no->filepartbuf.begin (), no->filepartbuf.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfpb != no->filepartbuf.end ())
    {
      no->fbrvectmtx.lock ();
      auto itfbrv = std::find_if (
	  no->fbrvect.begin (), no->fbrvect.end (), [keyarr, tint]
	  (auto &el)
	    {
	      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    });
      if (itfbrv == no->fbrvect.end ())
	{
	  no->fbrvect.push_back (std::make_tuple (keyarr, tint));
	}
      no->fbrvectmtx.unlock ();
    }
  no->filepartbufmtx.unlock ();
}

void
FileReceiveOp::fileFb (std::string msgtype, std::array<char, 32> keyarr,
		       int rcvip6, sockaddr_in6 *from6, sockaddr_in *from,
		       int sockipv4, std::vector<char> &buf, bool relay)
{
  AuxFuncNet af;
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  uint64_t partnum;
  std::memcpy (&partnum, &buf[42], sizeof(partnum));
  std::vector<char> hash;
  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (hash));
  no->filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      no->filehashvect.begin (), no->filehashvect.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != no->filehashvect.end ())
    {
      no->fileparthashmtx.lock ();
      no->fileparthash.erase (
	  std::remove_if (
	      no->fileparthash.begin (), no->fileparthash.end (), [keyarr, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	  no->fileparthash.end ());
      no->fileparthash.push_back (
	  std::make_tuple (keyarr, tint, partnum, hash));
      no->fileparthashmtx.unlock ();

      no->filepartrlogmtx.lock ();
      no->filepartrlog.erase (
	  std::remove_if (
	      no->filepartrlog.begin (), no->filepartrlog.end (), [keyarr, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	  no->filepartrlog.end ());
      no->filepartrlog.push_back (std::make_tuple (keyarr, tint, -1));
      no->filepartrlogmtx.unlock ();

      no->filepartrcvmtx.lock ();
      no->filepartrcv.erase (
	  std::remove_if (
	      no->filepartrcv.begin (), no->filepartrcv.end (), [keyarr, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	  no->filepartrcv.end ());
      no->filepartrcvmtx.unlock ();

      no->currentpartmtx.lock ();
      no->currentpart.erase (
	  std::remove_if (
	      no->currentpart.begin (), no->currentpart.end (), [keyarr, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	  no->currentpart.end ());
      no->currentpartmtx.unlock ();

      no->filepartendmtx.lock ();
      no->filepartend.erase (
	  std::remove_if (
	      no->filepartend.begin (), no->filepartend.end (), [keyarr, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		}),
	  no->filepartend.end ());
      no->filepartendmtx.unlock ();
    }
  else
    {
      std::string type;
      no->fqrcvdmtx.lock ();
      auto itfqrcv = std::find_if (
	  no->fqrcvd.begin (), no->fqrcvd.end (), [keyarr, tint]
	  (auto &el)
	    {
	      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    });
      if (itfqrcv != no->fqrcvd.end ())
	{
	  type = "FF";
	}
      else
	{
	  type = "FI";
	}
      no->fqrcvdmtx.unlock ();
      sendMsg (keyarr, type, tint, 0, rcvip6, relay, sockipv4, from, from6);
    }
  no->filehashvectmtx.unlock ();
}

void
FileReceiveOp::fileFp (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  uint64_t numb;
  std::memcpy (&numb, &buf[42], sizeof(numb));
  std::vector<char> data;
  std::copy (buf.begin () + 50, buf.end (), std::back_inserter (data));
  no->filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      no->filehashvect.begin (), no->filehashvect.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != no->filehashvect.end ())
    {
      std::tuple<std::array<char, 32>, uint64_t, uint64_t, std::vector<char>> tempt;
      tempt = std::make_tuple (keyarr, tint, numb, data);
      no->filepartrcvmtx.lock ();
      auto itfpr = std::find (no->filepartrcv.begin (), no->filepartrcv.end (),
			      tempt);
      if (itfpr == no->filepartrcv.end ())
	{
	  no->filepartrcv.push_back (tempt);
	}
      no->filepartrcvmtx.unlock ();
    }
  no->filehashvectmtx.unlock ();
}

void
FileReceiveOp::fileFe (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->filehashvectmtx.lock ();
  auto itfhv = std::find_if (
      no->filehashvect.begin (), no->filehashvect.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfhv != no->filehashvect.end ())
    {
      std::tuple<std::array<char, 32>, uint64_t> tempt;
      tempt = std::make_tuple (keyarr, tint);
      no->filepartendmtx.lock ();
      auto itfpe = std::find (no->filepartend.begin (), no->filepartend.end (),
			      tempt);
      if (itfpe == no->filepartend.end ())
	{
	  no->filepartend.push_back (tempt);
	}
      no->filepartendmtx.unlock ();
    }
  no->filehashvectmtx.unlock ();
}

void
FileReceiveOp::fileFE (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->fileendmtx.lock ();
  auto itfev = std::find_if (
      no->fileend.begin (), no->fileend.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	});
  if (itfev == no->fileend.end ())
    {
      no->fileend.push_back (std::make_tuple (keyarr, tint));
    }
  no->fileendmtx.unlock ();
}

void
FileReceiveOp::fileFF (std::string msgtype, std::array<char, 32> keyarr,
		       std::vector<char> &buf)
{
  std::cout << msgtype << std::endl;
  uint64_t tint;
  std::memcpy (&tint, &buf[34], sizeof(tint));
  no->filesendreqmtx.lock ();
  no->filesendreq.erase (
      std::remove_if (
	  no->filesendreq.begin (), no->filesendreq.end (), [keyarr, tint]
	  (auto &el)
	    {
	      if (std::get<0>(el) == keyarr && std::get<2>(el) == tint)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    }),
      no->filesendreq.end ());
  no->filesendreqmtx.unlock ();

  no->filepartbufmtx.lock ();
  no->filepartbuf.erase (
      std::remove_if (
	  no->filepartbuf.begin (), no->filepartbuf.end (), [keyarr, tint]
	  (auto &el)
	    {
	      if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
		{
		  return true;
		}
	      else
		{
		  return false;
		}
	    }),
      no->filepartbuf.end ());
  no->filepartbufmtx.unlock ();

  no->fbrvectmtx.lock ();
  no->fbrvect.erase (
      std::remove_if (no->fbrvect.begin (), no->fbrvect.end (), [keyarr, tint]
      (auto &el)
	{
	  if (std::get<0>(el) == keyarr && std::get<1>(el) == tint)
	    {
	      return true;
	    }
	  else
	    {
	      return false;
	    }
	}),
      no->fbrvect.end ());
  no->fbrvectmtx.unlock ();
}

void
FileReceiveOp::filePrFp (std::array<char, 32> key, int rcvip6, bool relay,
			 int sockipv, sockaddr_in *from, sockaddr_in6 *from6)
{
  no->filepartrcvmtx.lock ();
  for (;;)
    {
      auto itfpr = std::find_if (no->filepartrcv.begin (),
				 no->filepartrcv.end (), [key]
				 (auto &el)
				   {
				     return std::get<0>(el) == key;
				   });
      if (itfpr != no->filepartrcv.end ())
	{
	  uint64_t tint = std::get<1> (*itfpr);
	  uint64_t rpnum = std::get<2> (*itfpr);
	  no->filepartrlogmtx.lock ();
	  auto itfprl = std::find_if (
	      no->filepartrlog.begin (), no->filepartrlog.end (),
	      [key, tint, rpnum]
	      (auto &el)
		{
		  if (std::get<0>(el) == key && std::get<1>(el) == tint
		      && int (rpnum) == std::get<2>(el) + 1)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		});
	  if (itfprl != no->filepartrlog.end ())
	    {
	      no->currentpartmtx.lock ();
	      auto itcpv = std::find_if (
		  no->currentpart.begin (), no->currentpart.end (), [key, tint]
		  (auto &el)
		    {
		      if (std::get<0>(el) == key && std::get<1>(el) == tint)
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    });
	      std::vector<char> part = std::get<3> (*itfpr);
	      if (itcpv == no->currentpart.end ())
		{
		  no->currentpart.push_back (std::make_tuple (key, tint, part));
		}
	      else
		{
		  std::vector<char> tv = std::get<2> (*itcpv);
		  std::copy (part.begin (), part.end (),
			     std::back_inserter (tv));
		  std::get<2> (*itcpv) = tv;
		}
	      no->currentpartmtx.unlock ();
	      no->filepartrcv.erase (itfpr);
	      std::get<2> (*itfprl) = std::get<2> (*itfprl) + 1;
	    }
	  else
	    {
	      no->filepartrlogmtx.unlock ();
	      break;
	    }
	  no->filepartrlogmtx.unlock ();
	}
      else
	{
	  break;
	}
    }
  no->filepartrcvmtx.unlock ();
}

void
FileReceiveOp::filePrFe (std::array<char, 32> key, int rcvip6, bool relay,
			 int sockipv, sockaddr_in *from, sockaddr_in6 *from6)
{
  AuxFuncNet af;
  no->filepartendmtx.lock ();
  for (;;)
    {
      auto itfpe = std::find_if (no->filepartend.begin (),
				 no->filepartend.end (), [key]
				 (auto &el)
				   {
				     return std::get<0>(el) == key;
				   });
      if (itfpe == no->filepartend.end ())
	{
	  break;
	}
      else
	{
	  uint64_t tint = std::get<1> (*itfpe);
	  no->fileparthashmtx.lock ();
	  auto itfph = std::find_if (
	      no->fileparthash.begin (), no->fileparthash.end (), [key, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == key && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		});
	  if (itfph == no->fileparthash.end ())
	    {
	      no->filepartend.erase (itfpe);
	      no->fileparthashmtx.unlock ();
	      break;
	    }
	  else
	    {
	      std::vector<char> hash = std::get<3> (*itfph);
	      no->currentpartmtx.lock ();
	      auto itcp = std::find_if (
		  no->currentpart.begin (), no->currentpart.end (), [key, tint]
		  (auto &el)
		    {
		      if(std::get<0>(el) == key && std::get<1>(el) == tint)
			{
			  return true;
			}
		      else
			{
			  return false;
			}
		    });
	      if (itcp == no->currentpart.end ())
		{
		  no->filepartend.erase (itfpe);
		  no->fileparthash.erase (itfph);
		  no->currentpartmtx.unlock ();
		  no->fileparthashmtx.unlock ();
		  break;
		}
	      else
		{
		  std::vector<char> part = std::get<2> (*itcp);
		  std::vector<char> chhash;
		  chhash = af.strhash (part, 2);
		  if (chhash == hash)
		    {
		      no->filehashvectmtx.lock ();
		      auto itfhv =
			  std::find_if (
			      no->filehashvect.begin (),
			      no->filehashvect.end (),
			      [key, tint]
			      (auto &el)
				{
				  if (std::get<0>(el) == key && std::get<1>(el) == tint)
				    {
				      return true;
				    }
				  else
				    {
				      return false;
				    }
				});
		      if (itfhv == no->filehashvect.end ())
			{
			  no->filepartend.erase (itfpe);
			  no->fileparthash.erase (itfph);
			  no->currentpart.erase (itcp);
			  no->currentpartmtx.unlock ();
			  no->fileparthashmtx.unlock ();
			  no->filehashvectmtx.unlock ();
			  break;
			}
		      else
			{
			  if (int (std::get<2> (*itfph)) > std::get<4> (*itfhv))
			    {
			      std::filesystem::path p = std::get<3> (*itfhv);
			      std::fstream f;
			      f.open (
				  p,
				  std::ios_base::out | std::ios_base::app
				      | std::ios_base::binary);
			      f.write (&part[0], part.size ());
			      f.close ();
			      uint64_t fcsz = std::filesystem::file_size (p);
			      if (no->filepartrcvdsig)
				{
				  no->filepartrcvdsig (lt::aux::to_hex (key), p,
						       fcsz);
				}
			      std::get<4> (*itfhv) = std::get<4> (*itfhv) + 1;
			    }
			  this->sendMsg (key, "Fr", tint, std::get<2> (*itfph),
					 rcvip6, relay, sockipv, from, from6);
			  no->filepartend.erase (itfpe);
			  no->fileparthash.erase (itfph);
			  no->currentpart.erase (itcp);
			}
		      no->filehashvectmtx.unlock ();
		    }
		  else
		    {
		      std::cerr << "File part hash error!" << std::endl;
		      no->filepartend.erase (itfpe);
		      no->fileparthash.erase (itfph);
		      no->currentpart.erase (itcp);
		    }
		}
	      no->currentpartmtx.unlock ();
	    }
	  no->fileparthashmtx.unlock ();
	}
    }
  no->filepartendmtx.unlock ();
}

void
FileReceiveOp::filePrFE (std::array<char, 32> key, int rcvip6, bool relay,
			 int sockipv, sockaddr_in *from, sockaddr_in6 *from6,
			 std::string index)
{
  AuxFuncNet af;
  std::stringstream strm;
  std::locale loc ("C");
  strm.imbue (loc);
  no->fileendmtx.lock ();
  for (;;)
    {
      auto itfev = std::find_if (no->fileend.begin (), no->fileend.end (), [key]
      (auto &el)
	{
	  return std::get<0>(el) == key;
	});
      if (itfev == no->fileend.end ())
	{
	  break;
	}
      else
	{
	  uint64_t tint = std::get<1> (*itfev);
	  no->filehashvectmtx.lock ();
	  auto itfhv = std::find_if (
	      no->filehashvect.begin (), no->filehashvect.end (), [key, tint]
	      (auto &el)
		{
		  if (std::get<0>(el) == key && std::get<1>(el) == tint)
		    {
		      return true;
		    }
		  else
		    {
		      return false;
		    }
		});
	  if (itfhv == no->filehashvect.end ())
	    {
	      sendMsg (key, "FR", tint, 0, rcvip6, relay, sockipv, from, from6);
	      no->fileend.erase (itfev);
	      no->filehashvectmtx.unlock ();

	      no->fqrcvdmtx.lock ();
	      no->fqrcvd.erase (
		  std::remove_if (
		      no->fqrcvd.begin (), no->fqrcvd.end (), [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->fqrcvd.end ());
	      no->fqrcvdmtx.unlock ();
	      break;
	    }
	  else
	    {
	      std::vector<char> hash = std::get<2> (*itfhv);
	      std::filesystem::path p = std::get<3> (*itfhv);
	      std::vector<char> chhash = af.filehash (p);
	      if (hash == chhash)
		{
		  this->sendMsg (key, "FR", tint, 0, rcvip6, relay, sockipv,
				 from, from6);
		  std::string replmsg = "";
		  std::string resendmsg = "";
		  no->fqrcvdmtx.lock ();
		  auto itfqrcvd = std::find_if (
		      no->fqrcvd.begin (), no->fqrcvd.end (), [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			});
		  if (itfqrcvd != no->fqrcvd.end ())
		    {
		      replmsg = std::get<3> (*itfqrcvd);
		      resendmsg = std::get<4> (*itfqrcvd);
		      no->fqrcvd.erase (itfqrcvd);
		    }
		  no->fqrcvdmtx.unlock ();
		  std::string filename;
		  time_t curtime = time (NULL);
		  strm.clear ();
		  strm.str ("");
		  strm.imbue (loc);
		  strm << curtime;
#ifdef __linux
		  filename =
		      std::filesystem::temp_directory_path ().u8string ();
#endif
#ifdef _WIN32
  			  filename =
  			      std::filesystem::temp_directory_path ()
  			      .parent_path ().u8string ();
  #endif
		  filename = filename + "/" + strm.str ();
		  std::filesystem::path filepath = std::filesystem::u8path (
		      filename);
		  std::fstream f;
		  std::string line;
		  f.open (filepath, std::ios_base::out | std::ios_base::binary);
		  if (resendmsg != "")
		    {
		      line = resendmsg + " " + lt::aux::to_hex (key) + "\n";
		    }
		  else
		    {
		      line = lt::aux::to_hex (key) + "\n";
		    }
		  f.write (line.c_str (), line.size ());
		  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
		  okp = lt::dht::ed25519_create_keypair (no->seed);
		  line = lt::aux::to_hex (std::get<0> (okp).bytes) + "\n";
		  f.write (line.c_str (), line.size ());
		  time_t ctmutc = curtime;
		  strm.clear ();
		  strm.str ("");
		  strm.imbue (loc);
		  strm << ctmutc;
		  line = strm.str () + "\n";
		  f.write (line.c_str (), line.size ());
		  line = "1\n";
		  f.write (line.c_str (), line.size ());
		  if (replmsg != "")
		    {
		      while (replmsg.size () > 40)
			{
			  replmsg.pop_back ();
			}
		      line = "r " + replmsg + "\n";
		    }
		  else
		    {
		      line = "r\n";
		    }
		  f.write (line.c_str (), line.size ());
		  line = p.u8string ();
		  f.write (line.c_str (), line.size ());
		  f.close ();
		  lt::dht::public_key othpk;
		  std::array<char, 32> scalar;
		  othpk.bytes = key;
		  scalar = lt::dht::ed25519_key_exchange (othpk,
							  std::get<1> (okp));
		  othpk = lt::dht::ed25519_add_scalar (std::get<0> (okp),
						       scalar);
		  std::string unm = lt::aux::to_hex (std::get<0> (okp).bytes);
		  std::string passwd = lt::aux::to_hex (othpk.bytes);
		  filename = no->Home_Path;
		  filename = filename + "/.Communist/" + index;
		  std::filesystem::path outpath;
		  outpath = std::filesystem::u8path (filename);
		  std::vector<int> fnmv;
		  for (auto &dit : std::filesystem::directory_iterator (outpath))
		    {
		      std::filesystem::path tp = dit.path ();
		      if (tp.filename ().u8string () != "Yes"
			  && tp.filename ().u8string () != "Profile")
			{
			  filename = tp.filename ().u8string ();
			  std::string::size_type n;
			  n = filename.find ("f");
			  if (n != std::string::npos)
			    {
			      filename.erase (n, n + std::string ("f").size ());
			    }
			  strm.clear ();
			  strm.str ("");
			  strm.imbue (loc);
			  strm << filename;
			  int fnmi;
			  strm >> fnmi;
			  fnmv.push_back (fnmi);
			}
		    }
		  std::string fnm;
		  if (fnmv.size () > 0)
		    {
		      std::sort (fnmv.begin (), fnmv.end ());
		      int fnmi = fnmv[fnmv.size () - 1];
		      fnmi = fnmi + 1;
		      strm.clear ();
		      strm.str ("");
		      strm.imbue (loc);
		      strm << fnmi;
		      fnm = strm.str () + "f";
		    }
		  else
		    {
		      fnm = "0f";
		    }
		  filename = no->Home_Path;
		  filename = filename + "/.Communist/" + index + "/" + fnm;
		  outpath = std::filesystem::u8path (filename);
		  if (!std::filesystem::exists (outpath.parent_path ()))
		    {
		      std::filesystem::create_directories (
			  outpath.parent_path ());
		    }
		  af.cryptFile (unm, passwd, filepath.u8string (),
				outpath.u8string ());
		  af.updateMsgLog (no->Home_Path, no->Username, no->Password,
				   key, outpath.u8string (), no->contacts);
		  std::filesystem::remove_all (filepath);

		  if (no->filercvd)
		    {
		      no->filercvd (lt::aux::to_hex (key), p);
		    }
		  if (no->messageReceived)
		    {
		      no->messageReceived (lt::aux::to_hex (key), outpath);
		    }
		}
	      else
		{
		  sendMsg (key, "FI", tint, 0, rcvip6, relay, sockipv, from,
			   from6);
		  if (no->filehasherr)
		    {
		      no->filehasherr (lt::aux::to_hex (key), p);
		    }
		}
	      no->filehashvect.erase (itfhv);

	      no->filepartrcvmtx.lock ();
	      no->filepartrcv.erase (
		  std::remove_if (
		      no->filepartrcv.begin (), no->filepartrcv.end (),
		      [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->filepartrcv.end ());
	      no->filepartrcvmtx.unlock ();

	      no->fileparthashmtx.lock ();
	      no->fileparthash.erase (
		  std::remove_if (
		      no->fileparthash.begin (), no->fileparthash.end (),
		      [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->fileparthash.end ());
	      no->fileparthashmtx.unlock ();

	      no->filepartrlogmtx.lock ();
	      no->filepartrlog.erase (
		  std::remove_if (
		      no->filepartrlog.begin (), no->filepartrlog.end (),
		      [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->filepartrlog.end ());
	      no->filepartrlogmtx.unlock ();

	      no->currentpartmtx.lock ();
	      no->currentpart.erase (
		  std::remove_if (
		      no->currentpart.begin (), no->currentpart.end (),
		      [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->currentpart.end ());
	      no->currentpartmtx.unlock ();

	      no->filepartendmtx.lock ();
	      no->filepartend.erase (
		  std::remove_if (
		      no->filepartend.begin (), no->filepartend.end (),
		      [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->filepartend.end ());
	      no->filepartendmtx.unlock ();

	      no->fqrcvdmtx.lock ();
	      no->fqrcvd.erase (
		  std::remove_if (
		      no->fqrcvd.begin (), no->fqrcvd.end (), [key, tint]
		      (auto &el)
			{
			  if (std::get<0>(el) == key && std::get<1>(el) == tint)
			    {
			      return true;
			    }
			  else
			    {
			      return false;
			    }
			}),
		  no->fqrcvd.end ());
	      no->fqrcvdmtx.unlock ();

	      no->fileend.erase (itfev);
	    }
	  no->filehashvectmtx.unlock ();
	}
    }
  no->fileendmtx.unlock ();
}

void
FileReceiveOp::sendMsg (std::array<char, 32> key, std::string mtype,
			uint64_t tint, uint64_t numb, int rcvip6, bool relay,
			int sockipv, sockaddr_in *from, sockaddr_in6 *from6)
{
  AuxFuncNet af;
  std::vector<char> msg;
  std::tuple<lt::dht::public_key, lt::dht::secret_key> okp;
  okp = lt::dht::ed25519_create_keypair (no->seed);
  std::array<char, 32> okarr = std::get<0> (okp).bytes;
  std::copy (okarr.begin (), okarr.end (), std::back_inserter (msg));
  std::copy (mtype.begin (), mtype.end (), std::back_inserter (msg));
  msg.resize (msg.size () + sizeof(tint));
  std::memcpy (&msg[34], &tint, sizeof(tint));
  msg.resize (msg.size () + sizeof(numb));
  std::memcpy (&msg[42], &numb, sizeof(numb));
  std::string uname = lt::aux::to_hex (key);
  lt::dht::public_key othpk;
  othpk.bytes = key;
  std::array<char, 32> scalar;
  scalar = lt::dht::ed25519_key_exchange (othpk, std::get<1> (okp));
  othpk = lt::dht::ed25519_add_scalar (othpk, scalar);
  std::string passwd = lt::aux::to_hex (othpk.bytes);
  msg = af.cryptStrm (uname, passwd, msg);
  if (rcvip6 == 0)
    {
      if (relay)
	{
	  NetworkOperations *nop = no;
	  std::mutex *mtx = new std::mutex;
	  mtx->lock ();
	  no->threadvectmtx.lock ();
	  no->threadvect.push_back (std::make_tuple (mtx, "fileProcessing FR"));
	  no->threadvectmtx.unlock ();
	  std::thread *thr = new std::thread ( [nop, key, msg]
	  {
	    std::vector<char> lmsg = msg;
	    std::vector<std::vector<char>> msgsbuf;
	    msgsbuf.push_back (lmsg);
	    nop->ROp->relaySend (key, nop->seed, msgsbuf);
	  });
	  thr->detach ();
	  delete thr;
	}
      else
	{
	  no->sendMsg (sockipv, from->sin_addr.s_addr, from->sin_port, msg);
	}
    }
  else
    {
      std::vector<char> ip6ad;
      ip6ad.resize (INET6_ADDRSTRLEN);
      std::string ip6 = inet_ntop (AF_INET6, &from6->sin6_addr, ip6ad.data (),
				   ip6ad.size ());
      no->sockipv6mtx.lock ();
      no->sendMsg6 (sockipv, ip6, from6->sin6_port, msg);
      no->sockipv6mtx.unlock ();
    }
}
